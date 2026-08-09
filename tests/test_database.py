from pathlib import Path

from personashield.database import Database
from personashield.models import BreachRecord


def make_db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "test.db")
    db.init_schema()
    return db


def test_database_creation(tmp_path):
    db = make_db(tmp_path)
    assert db.exists()


def test_insert_and_search_email(tmp_path):
    db = make_db(tmp_path)
    db.insert_breach(BreachRecord(source="TestSrc", email="a@b.com", username="a"))
    results = db.search_email("a@b.com")
    assert len(results) == 1
    assert results[0].source == "TestSrc"


def test_search_username(tmp_path):
    db = make_db(tmp_path)
    db.insert_breach(BreachRecord(source="TestSrc", username="ghost"))
    results = db.search_username("GHOST")  # case-insensitive
    assert len(results) == 1


def test_stats(tmp_path):
    db = make_db(tmp_path)
    db.insert_many([
        BreachRecord(source="S1", email="x@y.com"),
        BreachRecord(source="S2", email="x@y.com", username="x"),
    ])
    stats = db.stats()
    assert stats["records"] == 2
    assert stats["sources"] == 2
    assert stats["emails_indexed"] == 1
