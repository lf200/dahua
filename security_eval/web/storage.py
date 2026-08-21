"""Disk storage helpers for the Flask web layer.

The core EvaluationService owns creation of each run directory. This module
therefore never creates ``<output_root>/<run_id>`` ahead of the service; doing
so would conflict with EvaluationService.execute(...), which intentionally
creates the directory with ``exist_ok=False``.

Responsibilities:
- strict run_id validation;
- atomic status.json / report.json writes;
- validated RunReport loading;
- restart recovery for interrupted web runs;
- a filesystem-backed single-active-run lock;
- safe artifact path resolution inside one run directory.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping

from security_eval.contracts import RunReport


# ============================================================
# Public status types
# ============================================================

WebRunStatus = Literal[
    "queued",
    "running",
    "completed",
    "partial",
    "failed",
]


# Keep the same run_id rule as contracts.py.
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$")

WEB_RUN_STATUSES = frozenset(
    {
        "queued",
        "running",
        "completed",
        "partial",
        "failed",
    }
)

FINAL_RUN_STATUSES = frozenset(
    {
        "completed",
        "partial",
        "failed",
    }
)


STATUS_FILENAME = "status.json"
REPORT_FILENAME = "report.json"
ACTIVE_LOCK_FILENAME = ".active_run.lock"


class RunStorage:
    """Filesystem persistence used by the web layer.

    ``output_root`` should be the same directory as
    ``Settings.output_root``.

    Important:
    individual run directories are created by
    ``EvaluationService.execute`` rather than this class.
    """

    def __init__(
        self,
        output_root: str | Path,
    ) -> None:
        self.output_root = Path(output_root).expanduser().resolve()

        # Creating the top-level runs directory is safe.
        # We deliberately do NOT create a specific run directory here.
        self.output_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Protect storage operations inside the current Python process.
        self._mutex = threading.RLock()

    # ========================================================
    # run_id and path handling
    # ========================================================

    @staticmethod
    def validate_run_id(
        run_id: str,
    ) -> str:
        """Validate and return a contract-compatible run id."""

        if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
            raise ValueError(
                "Invalid run_id: expected 8-64 characters using only "
                "letters, digits, '_' or '-', starting with a letter "
                "or digit"
            )

        return run_id

    def run_directory(
        self,
        run_id: str,
        *,
        must_exist: bool = True,
    ) -> Path:
        """Return the safe directory belonging to ``run_id``.

        This function never creates the run directory.
        """

        run_id = self.validate_run_id(run_id)

        candidate = (self.output_root / run_id).resolve()

        self._ensure_within(
            candidate,
            self.output_root,
        )

        if must_exist:
            if not candidate.exists() or not candidate.is_dir():
                raise FileNotFoundError(f"Run not found: {run_id}")

        return candidate

    def run_exists(
        self,
        run_id: str,
    ) -> bool:
        """Return whether a valid run directory currently exists."""

        try:
            run_dir = self.run_directory(
                run_id,
                must_exist=False,
            )
        except ValueError:
            return False

        return run_dir.is_dir()

    def status_path(
        self,
        run_id: str,
        *,
        must_exist: bool = False,
    ) -> Path:
        """Return the status.json path for one run."""

        run_dir = self.run_directory(
            run_id,
            must_exist=True,
        )

        path = run_dir / STATUS_FILENAME

        if must_exist and not path.is_file():
            raise FileNotFoundError(f"Status not found for run: {run_id}")

        return path

    def report_path(
        self,
        run_id: str,
        *,
        must_exist: bool = False,
    ) -> Path:
        """Return the report.json path for one run."""

        run_dir = self.run_directory(
            run_id,
            must_exist=True,
        )

        path = run_dir / REPORT_FILENAME

        if must_exist and not path.is_file():
            raise FileNotFoundError(f"Report not found for run: {run_id}")

        return path

    # ========================================================
    # status.json
    # ========================================================

    def save_status(
        self,
        run_id: str,
        status: WebRunStatus,
        *,
        message: str | None = None,
    ) -> dict[str, Any]:
        """Atomically save web-visible run status.

        The run directory must already exist.

        This is intentional because EvaluationService.execute()
        owns creation of the run directory.
        """

        run_id = self.validate_run_id(run_id)

        if status not in WEB_RUN_STATUSES:
            raise ValueError(f"Unsupported web run status: {status}")

        run_dir = self.run_directory(
            run_id,
            must_exist=True,
        )

        payload: dict[str, Any] = {
            "run_id": run_id,
            "status": status,
            "updated_at": self._utc_now_iso(),
            "report_available": (run_dir / REPORT_FILENAME).is_file(),
        }

        if message:
            # Prevent an exception message from creating a huge status file.
            payload["message"] = str(message)[:1000]

        with self._mutex:
            self._atomic_write_json(
                run_dir / STATUS_FILENAME,
                payload,
            )

        return payload

    def load_status(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        """Load status.json.

        Returns None when the run exists but status.json has not yet
        been written.
        """

        path = self.status_path(
            run_id,
            must_exist=False,
        )

        if not path.is_file():
            return None

        payload = self._read_json_object(path)

        stored_run_id = payload.get("run_id")

        stored_status = payload.get("status")

        if stored_run_id != run_id:
            raise ValueError(f"status.json run_id mismatch for run: {run_id}")

        if stored_status not in WEB_RUN_STATUSES:
            raise ValueError(f"Invalid status.json state for run: {run_id}")

        return payload

    # ========================================================
    # report.json
    # ========================================================

    def save_report(
        self,
        report: RunReport,
    ) -> Path:
        """Validate and atomically save a complete RunReport."""

        # Validate again at the web persistence boundary.
        validated = RunReport.model_validate(report)

        run_id = self.validate_run_id(validated.run_id)

        run_dir = self.run_directory(
            run_id,
            must_exist=True,
        )

        path = run_dir / REPORT_FILENAME

        payload = validated.model_dump(mode="json")

        with self._mutex:
            self._atomic_write_json(
                path,
                payload,
            )

        return path

    def load_report(
        self,
        run_id: str,
    ) -> RunReport | None:
        """Load and validate report.json.

        Returns None when the run exists but no report has been
        written yet.
        """

        path = self.report_path(
            run_id,
            must_exist=False,
        )

        if not path.is_file():
            return None

        payload = self._read_json_object(path)

        report = RunReport.model_validate(payload)

        if report.run_id != run_id:
            raise ValueError(f"report.json run_id mismatch for run: {run_id}")

        return report

    # ========================================================
    # Single active-run lock
    # ========================================================

    @property
    def active_lock_path(
        self,
    ) -> Path:
        """Location of the filesystem-backed active-run lock."""

        return self.output_root / ACTIVE_LOCK_FILENAME

    def acquire_run_lock(
        self,
        run_id: str,
    ) -> None:
        """Claim the single web-run slot atomically.

        The lock is stored directly under output_root instead of
        inside the run directory.

        Therefore acquiring the lock does not interfere with
        EvaluationService creating the run directory later.
        """

        run_id = self.validate_run_id(run_id)

        payload = {
            "run_id": run_id,
            "created_at": self._utc_now_iso(),
            "pid": os.getpid(),
        }

        encoded = self._encode_json(payload)

        with self._mutex:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

            try:
                fd = os.open(
                    self.active_lock_path,
                    flags,
                    0o600,
                )

            except FileExistsError as exc:
                active = self.get_active_run_id()

                suffix = f": {active}" if active else ""

                raise RuntimeError(
                    f"Another evaluation is already active{suffix}"
                ) from exc

            try:
                with os.fdopen(
                    fd,
                    "w",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    handle.write(encoded)

                    handle.flush()

                    os.fsync(handle.fileno())

            except Exception:
                self.active_lock_path.unlink(missing_ok=True)

                raise

    def get_active_run_id(
        self,
    ) -> str | None:
        """Return the run id currently owning the active lock."""

        path = self.active_lock_path

        if not path.is_file():
            return None

        payload = self._read_json_object(path)

        run_id = payload.get("run_id")

        if not isinstance(
            run_id,
            str,
        ):
            raise ValueError("Active-run lock is missing run_id")

        return self.validate_run_id(run_id)

    def release_run_lock(
        self,
        run_id: str,
    ) -> None:
        """Release the active-run lock.

        A run is only allowed to release a lock that it owns.
        """

        run_id = self.validate_run_id(run_id)

        with self._mutex:
            if not self.active_lock_path.exists():
                return

            active = self.get_active_run_id()

            if active != run_id:
                raise RuntimeError(
                    f"Cannot release active-run lock for {run_id}; owned by {active}"
                )

            self.active_lock_path.unlink(missing_ok=True)

    # ========================================================
    # Restart recovery
    # ========================================================

    def recover_after_restart(
        self,
    ) -> list[str]:
        """Repair stale persisted state after the web app restarts.

        Rules:

        1. If report.json exists, the report is authoritative and
           status.json is rebuilt from report.status.

        2. A queued/running run without report.json is treated as
           interrupted and changed to failed.

        3. A stale .active_run.lock is removed after recovery.

        Returns the run ids whose status was repaired.
        """

        recovered: list[str] = []

        with self._mutex:
            stale_active: str | None = None

            if self.active_lock_path.exists():
                try:
                    stale_active = self.get_active_run_id()

                except (
                    ValueError,
                    OSError,
                    json.JSONDecodeError,
                ):
                    stale_active = None

            candidates: set[str] = set()

            if stale_active is not None:
                candidates.add(stale_active)

            # Also recover status files that explicitly say
            # queued/running.
            for child in self.output_root.iterdir():
                if not child.is_dir():
                    continue

                if not RUN_ID_PATTERN.fullmatch(child.name):
                    continue

                status_file = child / STATUS_FILENAME

                if not status_file.is_file():
                    continue

                try:
                    payload = self._read_json_object(status_file)

                except (
                    ValueError,
                    OSError,
                    json.JSONDecodeError,
                ):
                    candidates.add(child.name)

                    continue

                if payload.get("status") in {
                    "queued",
                    "running",
                }:
                    candidates.add(child.name)

            for run_id in sorted(candidates):
                if not self.run_exists(run_id):
                    continue

                try:
                    report = self.load_report(run_id)

                except Exception:
                    # Corrupt / invalid report should not make
                    # application startup fail.
                    report = None

                if report is not None:
                    self.save_status(
                        run_id,
                        report.status,
                        message=(
                            "Status restored from the saved report after restart."
                        ),
                    )

                else:
                    self.save_status(
                        run_id,
                        "failed",
                        message=("Run was interrupted by an application restart."),
                    )

                recovered.append(run_id)

            # For this single-process web application, a lock found
            # during startup belongs to the old process.
            self.active_lock_path.unlink(missing_ok=True)

        return recovered

    # ========================================================
    # Artifact download boundary
    # ========================================================

    def resolve_artifact(
        self,
        run_id: str,
        artifact_path: str,
    ) -> Path:
        """Resolve a downloadable artifact safely.

        Prevents:

        ../../etc/passwd

        absolute paths

        and symlink escape outside the run directory.
        """

        if (
            not isinstance(
                artifact_path,
                str,
            )
            or not artifact_path.strip()
        ):
            raise ValueError("artifact_path must be a non-empty relative path")

        relative = Path(artifact_path)

        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("artifact_path must stay inside the run directory")

        run_dir = self.run_directory(
            run_id,
            must_exist=True,
        ).resolve(strict=True)

        candidate = (run_dir / relative).resolve(strict=True)

        self._ensure_within(
            candidate,
            run_dir,
        )

        if not candidate.is_file():
            raise FileNotFoundError(f"Artifact is not a file: {artifact_path}")

        return candidate

    # ========================================================
    # Internal helpers
    # ========================================================

    @staticmethod
    def _utc_now_iso() -> str:
        """Return current UTC time in ISO-8601 format."""

        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _ensure_within(
        candidate: Path,
        parent: Path,
    ) -> None:
        """Ensure candidate is contained by parent."""

        try:
            candidate.relative_to(parent)

        except ValueError as exc:
            raise ValueError(
                "Resolved path escapes the configured storage root"
            ) from exc

    @staticmethod
    def _encode_json(
        payload: Mapping[str, Any],
    ) -> str:
        """Serialize a JSON object consistently."""

        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=False,
            )
            + "\n"
        )

    @classmethod
    def _atomic_write_json(
        cls,
        path: Path,
        payload: Mapping[str, Any],
    ) -> None:
        """Write JSON using temp-file + os.replace.

        The temporary file is created in the same directory so
        os.replace remains atomic on the same filesystem.
        """

        if not path.parent.is_dir():
            raise FileNotFoundError(f"Parent directory does not exist: {path.parent}")

        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            text=True,
        )

        temp_path = Path(temp_name)

        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                handle.write(cls._encode_json(payload))

                # Push Python's buffer to the OS.
                handle.flush()

                # Push the file contents toward disk before replace.
                os.fsync(handle.fileno())

            # Atomic replacement of the destination.
            os.replace(
                temp_path,
                path,
            )

        except Exception:
            temp_path.unlink(missing_ok=True)

            raise

    @staticmethod
    def _read_json_object(
        path: Path,
    ) -> dict[str, Any]:
        """Read a JSON file and require its top level to be an object."""

        with path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            payload = json.load(handle)

        if not isinstance(
            payload,
            dict,
        ):
            raise ValueError(f"Expected a JSON object in {path.name}")

        return payload
