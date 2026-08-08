"""Data models used across PersonaShield."""
from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TargetType(str, Enum):
    EMAIL = "EMAIL"
    USERNAME = "USERNAME"
    PHONE = "PHONE"
    DOMAIN = "DOMAIN"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    NONE = "NONE"


class BreachRecord(BaseModel):
    id: Optional[int] = None
    source: str
    domain: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    has_password: bool = False          # never store/print plaintext
    hash_type: Optional[str] = None
    full_name: Optional[str] = None
    ip_address: Optional[str] = None
    breach_date: Optional[str] = None   # ISO date string
    description: Optional[str] = None

    def compromised_fields(self) -> list[str]:
        fields = []
        if self.email:
            fields.append("Email")
        if self.username:
            fields.append("Username")
        if self.has_password:
            fields.append("Password Hash")
        if self.phone:
            fields.append("Phone")
        if self.full_name:
            fields.append("Full Name")
        if self.ip_address:
            fields.append("IP Address")
        return fields


class RiskAssessment(BaseModel):
    level: RiskLevel
    score: int
    breach_count: int
    reasons: list[str] = Field(default_factory=list)


class UsernameHit(BaseModel):
    platform: str
    username: str
    url: str
    status: str            # Found / Not Found / Error / Unknown
    response_ms: Optional[int] = None


class DomainIntel(BaseModel):
    domain: str
    a_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    has_spf: bool = False
    has_dmarc: bool = False
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None


class TargetReport(BaseModel):
    target: str
    target_type: TargetType
    breaches: list[BreachRecord] = Field(default_factory=list)
    risk: RiskAssessment
    generated_at: str
