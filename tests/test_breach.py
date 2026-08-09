import json
from pathlib import Path

from personashield.database import Database
from personashield.modules import breach as breach_mod


def make_db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "test.db")
    db.init_schema()
    return db


def test_import_csv(tmp_path):
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text(
        "email,username,password,source,breach_date\n"
        "a@b.com,userA,hash1,SiteA,2024-01-01\n"
        "b@c.com,,,SiteB,2023-01-01\n"
    )
    db = make_db(tmp_path)
    imported, skipped = breach_mod.import_csv(csv_path, db)
    assert imported == 2
    assert skipped == 0
    results = db.search_email("a@b.com")
    assert len(results) == 1
    assert results[0].has_password is True


def test_import_json(tmp_path):
    json_path = tmp_path / "sample.json"
    json_path.write_text(json.dumps([
        {"mail": "x@y.com", "user_name": "xu", "source": "SiteX"},
        {"no_identifiers": "skip me"},
    ]))
    db = make_db(tmp_path)
    imported, skipped = breach_mod.import_json(json_path, db)
    assert imported == 1
    assert skipped == 1


def test_field_normalization_via_import(tmp_path):
    csv_path = tmp_path / "weird.csv"
    csv_path.write_text("Email Address,User Name,Source\nz@w.com,zuser,SiteZ\n")
    db = make_db(tmp_path)
    imported, _ = breach_mod.import_csv(csv_path, db)
    assert imported == 1
    results = db.search_email("z@w.com")
    assert results[0].username == "zuser"


def test_dry_run_does_not_write(tmp_path):
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text("email,username,source\ndry@run.com,dryu,SiteDry\n")
    db = make_db(tmp_path)
    imported, skipped, preview = breach_mod.import_file(csv_path, db, dry_run=True)
    assert imported == 0
    assert len(preview.valid_records) == 1
    assert db.search_email("dry@run.com") == []  # nothing written


def test_dry_run_then_real_import(tmp_path):
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text("email,username,source\nreal@run.com,realu,SiteReal\n")
    db = make_db(tmp_path)
    breach_mod.import_file(csv_path, db, dry_run=True)
    imported, skipped, preview = breach_mod.import_file(csv_path, db, dry_run=False)
    assert imported == 1
    assert len(db.search_email("real@run.com")) == 1


def test_field_coverage_computed(tmp_path):
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text(
        "email,username,phone,password,source\n"
        "a@b.com,au,+15551234567,hash1,SiteA\n"
    )
    preview = breach_mod.parse_file(csv_path)
    assert preview.field_coverage.get("email") == 1
    assert preview.field_coverage.get("password_hash") == 1
