"""Risk scoring engine. Pure local computation, fully configurable."""
from __future__ import annotations

from datetime import date, datetime

from personashield.config import RiskThresholds
from personashield.models import BreachRecord, RiskAssessment, RiskLevel


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def assess_risk(
    records: list[BreachRecord],
    thresholds: RiskThresholds | None = None,
) -> RiskAssessment:
    thresholds = thresholds or RiskThresholds()
    reasons: list[str] = []

    if not records:
        return RiskAssessment(
            level=RiskLevel.NONE, score=0, breach_count=0,
            reasons=["No matching records found in local database."],
        )

    count = len(records)
    score = 0

    # base score from breach count
    if count <= thresholds.low_max:
        score += 1
        reasons.append(f"{count} breach record(s) found.")
    elif count <= thresholds.medium_max:
        score += 3
        reasons.append(f"{count} breach records found across multiple sources.")
    elif count <= thresholds.high_max:
        score += 5
        reasons.append(f"{count} breach records found — widespread exposure.")
    else:
        score += 7
        reasons.append(f"{count} breach records found — extensive exposure.")

    has_password = any(r.has_password for r in records)
    if has_password:
        score += thresholds.password_hash_weight
        reasons.append("At least one breach exposed a password hash.")

    has_phone = any(r.phone for r in records)
    if has_phone:
        score += thresholds.phone_weight
        reasons.append("Phone number exposed in at least one breach.")

    sources = {r.source for r in records}
    if len(sources) >= thresholds.multi_source_bonus_threshold:
        score += 2
        reasons.append(f"Data appears across {len(sources)} distinct sources.")

    recent = False
    today = date.today()
    for r in records:
        d = _parse_date(r.breach_date)
        if d and (today - d).days <= thresholds.recent_breach_days:
            recent = True
            break
    if recent:
        score += thresholds.recency_weight
        reasons.append("At least one breach occurred within the last year.")

    if score <= 2:
        level = RiskLevel.LOW
    elif score <= 5:
        level = RiskLevel.MEDIUM
    elif score <= 9:
        level = RiskLevel.HIGH
    else:
        level = RiskLevel.CRITICAL

    # Explicit override: password hash + recency => at least HIGH
    if has_password and recent and level in (RiskLevel.LOW, RiskLevel.MEDIUM):
        level = RiskLevel.HIGH
        reasons.append("Escalated to HIGH: recent breach with password exposure.")

    # multiple sensitive fields + recent => CRITICAL
    sensitive_field_count = sum([has_password, has_phone, any(r.full_name for r in records)])
    if sensitive_field_count >= 2 and recent:
        level = RiskLevel.CRITICAL
        reasons.append("Escalated to CRITICAL: multiple sensitive fields exposed recently.")

    return RiskAssessment(level=level, score=score, breach_count=count, reasons=reasons)
