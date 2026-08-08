"""
Configuration for PersonaShield.

Everything here is local. No API keys are read, required, or supported
for the core breach-intelligence and reporting features.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os

# Root data directory. Overridable via PERSONASHIELD_HOME for tests/CI.
APP_HOME = Path(os.environ.get("PERSONASHIELD_HOME", Path.home() / ".personashield"))
DATA_DIR = APP_HOME / "data"
REPORTS_DIR = APP_HOME / "reports"
DB_PATH = DATA_DIR / "personashield.db"

SAMPLE_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "sample"


@dataclass
class RiskThresholds:
    """Configurable thresholds for the risk engine (breach counts -> tier)."""
    low_max: int = 1
    medium_max: int = 3
    high_max: int = 6
    # anything above high_max => CRITICAL, subject to modifiers below
    recent_breach_days: int = 365
    password_hash_weight: int = 2
    phone_weight: int = 1
    recency_weight: int = 2
    multi_source_bonus_threshold: int = 3


@dataclass
class Settings:
    app_home: Path = field(default_factory=lambda: APP_HOME)
    data_dir: Path = field(default_factory=lambda: DATA_DIR)
    reports_dir: Path = field(default_factory=lambda: REPORTS_DIR)
    db_path: Path = field(default_factory=lambda: DB_PATH)
    risk: RiskThresholds = field(default_factory=RiskThresholds)
    request_timeout: float = 6.0
    max_concurrent_requests: int = 30

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
