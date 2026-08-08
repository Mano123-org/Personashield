"""Target-type detection (thin re-export for a stable top-level import path)."""
from personashield.utils.validators import detect_target_type, is_domain, is_email, is_phone

__all__ = ["detect_target_type", "is_domain", "is_email", "is_phone"]
