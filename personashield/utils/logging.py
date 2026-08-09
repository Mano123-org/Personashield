"""Logging helpers that avoid ever writing sensitive values to logs."""
from __future__ import annotations

import logging
import sys

_SENSITIVE_KEYS = {"password", "password_hash", "pwd", "hash", "secret"}


def get_logger(name: str = "personashield") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def redact(data: dict) -> dict:
    """Return a copy of data with sensitive keys masked, for safe logging."""
    out = {}
    for k, v in data.items():
        if k.lower() in _SENSITIVE_KEYS:
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out
