from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ScanStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"
    RUNNING = "RUNNING"
    QUEUED = "QUEUED"
    PENDING = "PENDING"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "ScanStatus":
        if not value:
            raise ValueError("scan status missing")
        try:
            return cls(value.strip().upper())
        except ValueError as exc:
            raise ValueError(f"unknown scan status: {value!r}") from exc


@dataclass
class QuotaUsage:
    plan_name: Optional[str] = None
    daily_limit: Optional[int] = None
    monthly_limit: Optional[int] = None
    daily_usage: Optional[int] = None
    monthly_usage: Optional[int] = None
    day_reset_at: Optional[str] = None
    month_reset_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "QuotaUsage":
        return cls(
            plan_name=data.get("plan_name"),
            daily_limit=data.get("daily_limit"),
            monthly_limit=data.get("monthly_limit"),
            daily_usage=data.get("daily_usage"),
            monthly_usage=data.get("monthly_usage"),
            day_reset_at=data.get("day_reset_at"),
            month_reset_at=data.get("month_reset_at"),
        )
