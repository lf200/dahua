"""Injectable clocks for deterministic tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(slots=True)
class FrozenClock:
    value: datetime

    def now(self) -> datetime:
        return self.value
