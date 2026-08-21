"""Background execution manager for the Flask web layer.

This module bridges a web POST request and the synchronous
``EvaluationService.execute(...)`` API without modifying the core layer.

The core service remains responsible for creating ``<output_root>/<run_id>``.
The web manager owns only:
- run_id generation;
- the single-active-run lock;
- background execution;
- web-visible transient status;
- persistence of final report/status;
- cleanup after success or failure.
"""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from security_eval.contracts import Estimate, RunReport, RunRequest
from security_eval.errors import ConfigurationError
from security_eval.web.storage import RunStorage, WebRunStatus


logger = logging.getLogger(__name__)


class EvaluationExecutor(Protocol):
    """Small public surface required from EvaluationService or a fake."""

    def estimate(
        self,
        request: RunRequest,
    ) -> list[Estimate]: ...

    def execute(
        self,
        request: RunRequest,
        *,
        run_id: str | None = None,
    ) -> RunReport: ...


RunIdFactory = Callable[[], str]


def generate_run_id() -> str:
    """Generate a contract-compatible, human-readable run id."""

    now = datetime.now(timezone.utc)

    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


class RunManager:
    """Run at most one evaluation in the background.

    EvaluationService.execute() is synchronous.

    The manager therefore uses its own one-worker executor so a Flask
    request can return a run_id immediately and the browser can poll
    progress.

    The filesystem lock in RunStorage is the authoritative single-run
    guard. The in-memory state is only used for progress polling before
    status.json can be written.
    """

    def __init__(
        self,
        *,
        service: EvaluationExecutor,
        storage: RunStorage,
        run_id_factory: RunIdFactory = generate_run_id,
    ) -> None:
        self.service = service
        self.storage = storage
        self._run_id_factory = run_id_factory

        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="web-evaluation",
        )

        self._mutex = threading.RLock()

        self._futures: dict[
            str,
            Future[RunReport],
        ] = {}

        self._states: dict[
            str,
            WebRunStatus,
        ] = {}

        # If the Flask process restarted while a run was active,
        # the old worker no longer exists.
        #
        # Recover stale queued/running states and clear the stale
        # filesystem lock before accepting new runs.
        self.recovered_run_ids = self.storage.recover_after_restart()

    # ========================================================
    # Public API
    # ========================================================

    def start(
        self,
        request: RunRequest,
    ) -> str:
        """Start one authorized evaluation.

        Returns the generated run_id immediately.

        The actual evaluation continues in the background.
        """

        validated = RunRequest.model_validate(request)

        # Authorization should fail immediately at the HTTP boundary.
        #
        # Otherwise POST /runs would appear successful and the run
        # would only fail later in the background thread.
        if not validated.authorized_target:
            raise ConfigurationError("Target authorization must be confirmed")

        run_id = self.storage.validate_run_id(self._run_id_factory())

        # IMPORTANT:
        #
        # Do NOT create:
        #
        #     output_root / run_id
        #
        # here.
        #
        # EvaluationService.execute() owns that directory creation
        # and uses exist_ok=False.
        self.storage.acquire_run_lock(run_id)

        try:
            with self._mutex:
                self._states[run_id] = "queued"

                future = self._executor.submit(
                    self._execute_run,
                    run_id,
                    validated,
                )

                self._futures[run_id] = future

        except Exception:
            # If submitting the worker itself fails, there is no
            # background task available to release the lock.
            self.storage.release_run_lock(run_id)

            with self._mutex:
                self._states.pop(
                    run_id,
                    None,
                )

                self._futures.pop(
                    run_id,
                    None,
                )

            raise

        return run_id

    def estimate(
        self,
        request: RunRequest,
    ) -> list[Estimate]:
        """Return public module estimates without starting a run."""

        validated = RunRequest.model_validate(request)

        return list(self.service.estimate(validated))

    def get_status(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        """Return the web-visible status for one run.

        Returns None when the run_id is valid but unknown.

        While EvaluationService is running, the core may already have
        created the run directory but status.json may not exist yet.

        In that case the manager uses its in-memory queued/running
        state and persists it once the directory becomes available.
        """

        run_id = self.storage.validate_run_id(run_id)

        # First prefer persisted data.
        if self.storage.run_exists(run_id):
            # report.json is authoritative once it exists.
            #
            # This also repairs a stale queued/running status if the
            # process managed to save report.json but was interrupted
            # before final status.json was written.
            report = self.storage.load_report(run_id)

            status = self.storage.load_status(run_id)

            if report is not None:
                if (
                    status is None
                    or status.get("status") != report.status
                    or not status.get(
                        "report_available",
                        False,
                    )
                ):
                    return self.storage.save_status(
                        run_id,
                        report.status,
                    )

                return status

            if status is not None:
                return status

        # No durable status yet. Check the active in-memory run.
        with self._mutex:
            transient = self._states.get(run_id)

        if transient is None:
            return None

        # As soon as the core creates the run directory, make the
        # transient state durable.
        if self.storage.run_exists(run_id):
            try:
                return self.storage.save_status(
                    run_id,
                    transient,
                )

            except (
                FileNotFoundError,
                OSError,
                ValueError,
            ):
                # Polling should still work even if this lightweight
                # status write temporarily fails.
                logger.debug(
                    "Could not persist transient status for run %s",
                    run_id,
                    exc_info=True,
                )

        return {
            "run_id": run_id,
            "status": transient,
            "report_available": False,
        }

    def get_report(
        self,
        run_id: str,
    ) -> RunReport | None:
        """Return the persisted report when available."""

        run_id = self.storage.validate_run_id(run_id)

        if not self.storage.run_exists(run_id):
            return None

        return self.storage.load_report(run_id)

    def is_active(
        self,
    ) -> bool:
        """Return whether one evaluation currently owns the run lock."""

        try:
            return self.storage.get_active_run_id() is not None

        except (
            OSError,
            ValueError,
        ):
            return False

    def shutdown(
        self,
        *,
        wait: bool = True,
    ) -> None:
        """Shut down the web manager executor.

        The EvaluationService instance is injected into this class and
        is therefore not owned or shut down here.
        """

        self._executor.shutdown(
            wait=wait,
            cancel_futures=False,
        )

    # ========================================================
    # Background worker
    # ========================================================

    def _execute_run(
        self,
        run_id: str,
        request: RunRequest,
    ) -> RunReport:
        """Execute one evaluation inside the background worker."""

        self._set_state(
            run_id,
            "running",
        )

        try:
            # This call creates:
            #
            #     output_root / run_id
            #
            # and executes Task 1 / Task 2 / Task 4.
            report = RunReport.model_validate(
                self.service.execute(
                    request,
                    run_id=run_id,
                )
            )

            # Never allow a service result belonging to a different run
            # to be persisted under this run.
            if report.run_id != run_id:
                raise ValueError(
                    "EvaluationService returned a report with a different run_id"
                )

            # report.json is the authoritative final result.
            self.storage.save_report(report)

            # status.json is only a lightweight view of that result.
            #
            # If this write fails, do not turn a successful evaluation
            # into a failed evaluation. get_status() can rebuild it from
            # report.json later.
            try:
                self.storage.save_status(
                    run_id,
                    report.status,
                )

            except Exception:
                logger.exception(
                    "Could not persist final status for run %s",
                    run_id,
                )

            self._set_state(
                run_id,
                report.status,
            )

            return report

        except Exception:
            self._set_state(
                run_id,
                "failed",
            )

            self._persist_failure_status(run_id)

            logger.exception(
                "Evaluation run %s failed",
                run_id,
            )

            raise

        finally:
            # Success, partial and failure must all release the single
            # active-run slot.
            try:
                self.storage.release_run_lock(run_id)

            except Exception:
                # Do not replace the real evaluation result/exception
                # merely because lock cleanup failed.
                logger.exception(
                    "Could not release active-run lock for %s",
                    run_id,
                )

    # ========================================================
    # Failure handling
    # ========================================================

    def _persist_failure_status(
        self,
        run_id: str,
    ) -> None:
        """Persist a safe generic failed state.

        EvaluationService normally creates the run directory before
        executing modules.

        However, it can fail during its initial request validation,
        before the directory has been created.

        At that point execute() has already raised, so the web layer may
        safely create the directory solely to retain the failure status.
        """

        try:
            if not self.storage.run_exists(run_id):
                run_dir = self.storage.run_directory(
                    run_id,
                    must_exist=False,
                )

                run_dir.mkdir(
                    parents=False,
                    exist_ok=True,
                )

            # Do not expose raw exception strings here.
            #
            # They may contain internal implementation/configuration
            # details. Detailed normalized errors belong in RunReport
            # when the core is able to produce one.
            self.storage.save_status(
                run_id,
                "failed",
                message=("Evaluation failed before a complete report was produced."),
            )

        except Exception:
            logger.exception(
                "Could not persist failure status for run %s",
                run_id,
            )

    # ========================================================
    # Internal state
    # ========================================================

    def _set_state(
        self,
        run_id: str,
        status: WebRunStatus,
    ) -> None:
        """Update one transient run state safely."""

        with self._mutex:
            self._states[run_id] = status
