"""Breach dataset import and local search orchestration."""
from __future__ import annotations

import csv
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from personashield.database import Database
from personashield.models import BreachRecord, TargetType
from personashield.utils.normalization import normalize_row
from personashield.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ImportPreview:
    """Result of parsing a dataset without writing to the database."""
    valid_records: list[BreachRecord] = field(default_factory=list)
    skipped_count: int = 0
    warnings: list[str] = field(default_factory=list)
    field_coverage: dict[str, int] = field(default_factory=dict)

    @property
    def total_rows(self) -> int:
        return len(self.valid_records) + self.skipped_count

    def compute_coverage(self) -> None:
        counts: dict[str, int] = {}
        for r in self.valid_records:
            for f in ("email", "username", "phone", "domain", "full_name", "ip_address"):
                if getattr(r, f):
                    counts[f] = counts.get(f, 0) + 1
            if r.has_password:
                counts["password_hash"] = counts.get("password_hash", 0) + 1
        self.field_coverage = counts


def _row_to_breach_record(row: dict, default_source: str) -> tuple[BreachRecord | None, str | None]:
    """Returns (record, warning). record is None if the row lacks identifiers."""
    normalized = normalize_row(row)
    if not any(k in normalized for k in ("email", "username", "phone")):
        return None, "row has no email/username/phone identifier"

    if "email" in normalized and "@" not in str(normalized["email"]):
        return None, f"malformed email skipped: {normalized['email']!r}"

    has_password = bool(normalized.get("password_hash"))
    # NEVER carry plaintext password value forward — only note that one existed.
    record = BreachRecord(
        source=str(normalized.get("source", default_source)),
        domain=normalized.get("domain"),
        email=normalized.get("email"),
        username=normalized.get("username"),
        phone=normalized.get("phone"),
        has_password=has_password,
        hash_type=normalized.get("hash_type"),
        full_name=normalized.get("full_name"),
        ip_address=normalized.get("ip_address"),
        breach_date=normalized.get("breach_date"),
        description=normalized.get("description"),
    )
    return record, None


def _parse_csv(path: Path, default_source: str) -> ImportPreview:
    preview = ImportPreview()
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames:
            unmapped = [c for c in reader.fieldnames if normalize_row({c: "x"}) == {}]
            if unmapped:
                preview.warnings.append(f"unrecognized columns ignored: {', '.join(unmapped)}")
        for row in reader:
            rec, warn = _row_to_breach_record(row, default_source)
            if rec is None:
                preview.skipped_count += 1
                continue
            preview.valid_records.append(rec)
    preview.compute_coverage()
    return preview


def _parse_json(path: Path, default_source: str) -> ImportPreview:
    preview = ImportPreview()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get("records") or data.get("data") or [data]
    for row in data:
        if not isinstance(row, dict):
            preview.skipped_count += 1
            continue
        rec, warn = _row_to_breach_record(row, default_source)
        if rec is None:
            preview.skipped_count += 1
            continue
        preview.valid_records.append(rec)
    preview.compute_coverage()
    return preview


def _parse_sqlite(path: Path, default_source: str) -> ImportPreview:
    preview = ImportPreview()
    src_conn = sqlite3.connect(path)
    src_conn.row_factory = sqlite3.Row
    tables = [
        r[0] for r in src_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    ]
    table = "breaches" if "breaches" in tables else (tables[0] if tables else None)
    if table is None:
        src_conn.close()
        preview.warnings.append("no tables found in source SQLite file")
        return preview

    rows = src_conn.execute(f"SELECT * FROM {table}").fetchall()
    for row in rows:
        rec, warn = _row_to_breach_record(dict(row), default_source)
        if rec is None:
            preview.skipped_count += 1
            continue
        preview.valid_records.append(rec)
    src_conn.close()
    preview.compute_coverage()
    return preview


def parse_file(path: Path, source_hint: str | None = None) -> ImportPreview:
    """Parse and validate a dataset without writing anything to the database."""
    default_source = source_hint or path.stem
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return _parse_csv(path, default_source)
    if suffix == ".json":
        return _parse_json(path, default_source)
    if suffix in (".db", ".sqlite", ".sqlite3"):
        return _parse_sqlite(path, default_source)
    raise ValueError(f"Unsupported import format: {suffix}")


def import_file(
    path: Path, db: Database, source_hint: str | None = None, dry_run: bool = False,
) -> tuple[int, int, ImportPreview]:
    """
    Parse a dataset and, unless dry_run, write valid records to the database.
    Returns (imported_count, skipped_count, preview). imported_count is 0
    when dry_run is True.
    """
    preview = parse_file(path, source_hint)
    if dry_run:
        return 0, preview.skipped_count, preview
    imported = db.insert_many(preview.valid_records)
    return imported, preview.skipped_count, preview


# Backwards-compatible thin wrappers (used directly by earlier tests/tools).
def import_csv(path: Path, db: Database, source_hint: str | None = None) -> tuple[int, int]:
    imported, skipped, _ = import_file(path, db, source_hint)
    return imported, skipped


def import_json(path: Path, db: Database, source_hint: str | None = None) -> tuple[int, int]:
    imported, skipped, _ = import_file(path, db, source_hint)
    return imported, skipped


def import_sqlite(path: Path, db: Database, source_hint: str | None = None) -> tuple[int, int]:
    imported, skipped, _ = import_file(path, db, source_hint)
    return imported, skipped


def search_target(db: Database, target: str, target_type: TargetType) -> list[BreachRecord]:
    if target_type == TargetType.EMAIL:
        return db.search_email(target)
    if target_type == TargetType.USERNAME:
        return db.search_username(target)
    if target_type == TargetType.PHONE:
        return db.search_phone(target)
    if target_type == TargetType.DOMAIN:
        return db.search_source(target)
    return []
