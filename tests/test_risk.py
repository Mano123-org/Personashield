from datetime import date, timedelta

from personashield.models import BreachRecord
from personashield.modules.risk import assess_risk
from personashield.models import RiskLevel


def test_no_records():
    result = assess_risk([])
    assert result.level == RiskLevel.NONE


def test_low_risk_single_old_breach():
    old_date = (date.today() - timedelta(days=1000)).isoformat()
    records = [BreachRecord(source="S1", email="a@b.com", breach_date=old_date)]
    result = assess_risk(records)
    assert result.level == RiskLevel.LOW


def test_high_risk_password_and_recent():
    recent = (date.today() - timedelta(days=10)).isoformat()
    records = [
        BreachRecord(source="S1", email="a@b.com", has_password=True, breach_date=recent),
    ]
    result = assess_risk(records)
    assert result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_critical_multi_sensitive_recent():
    recent = (date.today() - timedelta(days=5)).isoformat()
    records = [
        BreachRecord(
            source="S1", email="a@b.com", has_password=True,
            phone="+15550000000", full_name="A B", breach_date=recent,
        )
    ]
    result = assess_risk(records)
    assert result.level == RiskLevel.CRITICAL
