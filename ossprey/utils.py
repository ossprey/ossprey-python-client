from __future__ import annotations

from ossprey.models import QuotaUsage


def format_quota_usage(quota: QuotaUsage) -> str:
    if not quota:
        return ""

    lines = ["", "--- Quota Usage ---"]
    if quota.plan_name:
        lines.append(f"Plan: {quota.plan_name}")

    if quota.daily_limit is not None and quota.daily_usage is not None:
        daily_pct = (quota.daily_usage / quota.daily_limit * 100) if quota.daily_limit > 0 else 0
        lines.append(
            f"Daily:   {quota.daily_usage}/{quota.daily_limit} ({daily_pct:.1f}%) - Resets {quota.day_reset_at}"
        )

    if quota.monthly_limit is not None and quota.monthly_usage is not None:
        monthly_pct = (quota.monthly_usage / quota.monthly_limit * 100) if quota.monthly_limit > 0 else 0
        lines.append(
            f"Monthly: {quota.monthly_usage}/{quota.monthly_limit} ({monthly_pct:.1f}%) - Resets {quota.month_reset_at}"
        )

    return "\n".join(lines)
