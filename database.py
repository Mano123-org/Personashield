"""SQLite-backed local breach database. No network, no API keys."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Optional

from personashield.models import BreachRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS breaches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    domain TEXT,
    email TEXT,
    username TEXT,
    phone TEXT,
    has_password INTEGER NOT NULL DEFAULT 0,
    hash_type TEXT,
    full_name TEXT,
    ip_address TEXT,
    breach_date TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_breaches_email ON breaches(email);
CREATE INDEX IF NOT EXISTS idx_breaches_username ON breaches(username);
CREATE INDEX IF NOT EXISTS idx_breaches_phone ON breaches(phone);
CREATE INDEX IF NOT EXISTS idx_breaches_domain ON breaches(domain);
CREATE INDEX IF NOT EXISTS idx_breaches_source ON breaches(source);
"""


class Database:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def exists(self) -> bool:
        return self.db_path.exists()

    def insert_breach(self, record: BreachRecord) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO breaches
                (source, domain, email, username, phone, has_password,
                 hash_type, full_name, ip_address, breach_date, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.source,
                    record.domain,
                    record.email.lower() if record.email else None,
                    record.username.lower() if record.username else None,
                    record.phone,
                    int(record.has_password),
                    record.hash_type,
                    record.full_name,
                    record.ip_address,
                    record.breach_date,
                    record.description,
                ),
            )
            return cur.lastrowid

    def insert_many(self, records: Iterable[BreachRecord]) -> int:
        count = 0
        with self.connect() as conn:
            for record in records:
                conn.execute(
                    """
                    INSERT INTO breaches
                    (source, domain, email, username, phone, has_password,
                     hash_type, full_name, ip_address, breach_date, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.source,
                        record.domain,
                        record.email.lower() if record.email else None,
                        record.username.lower() if record.username else None,
                        record.phone,
                        int(record.has_password),
                        record.hash_type,
                        record.full_name,
                        record.ip_address,
                        record.breach_date,
                        record.description,
                    ),
                )
                count += 1
        return count

    def _row_to_record(self, row: sqlite3.Row) -> BreachRecord:
        return BreachRecord(
            id=row["id"],
            source=row["source"],
            domain=row["domain"],
            email=row["email"],
            username=row["username"],
            phone=row["phone"],
            has_password=bool(row["has_password"]),
            hash_type=row["hash_type"],
            full_name=row["full_name"],
            ip_address=row["ip_address"],
            breach_date=row["breach_date"],
            description=row["description"],
        )

    def search_email(self, email: str) -> list[BreachRecord]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM breaches WHERE email = ? ORDER BY breach_date DESC",
                (email.lower(),),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def search_username(self, username: str) -> list[BreachRecord]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM breaches WHERE username = ? ORDER BY breach_date DESC",
                (username.lower(),),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def search_phone(self, phone: str) -> list[BreachRecord]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM breaches WHERE phone = ? ORDER BY breach_date DESC",
                (phone,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def search_source(self, source: str) -> list[BreachRecord]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM breaches WHERE source LIKE ? ORDER BY breach_date DESC",
                (f"%{source}%",),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def stats(self) -> dict:
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM breaches").fetchone()["c"]
            sources = conn.execute(
                "SELECT COUNT(DISTINCT source) c FROM breaches"
            ).fetchone()["c"]
            emails = conn.execute(
                "SELECT COUNT(DISTINCT email) c FROM breaches WHERE email IS NOT NULL"
            ).fetchone()["c"]
            usernames = conn.execute(
                "SELECT COUNT(DISTINCT username) c FROM breaches WHERE username IS NOT NULL"
            ).fetchone()["c"]
            phones = conn.execute(
                "SELECT COUNT(DISTINCT phone) c FROM breaches WHERE phone IS NOT NULL"
            ).fetchone()["c"]
        return {
            "records": total,
            "sources": sources,
            "emails_indexed": emails,
            "usernames_indexed": usernames,
            "phones_indexed": phones,
        }
