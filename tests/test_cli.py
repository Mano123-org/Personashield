import os

from typer.testing import CliRunner

runner = CliRunner()


def _set_home(tmp_path):
    os.environ["PERSONASHIELD_HOME"] = str(tmp_path)


def test_version(tmp_path):
    _set_home(tmp_path)
    from personashield.cli import app
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0


def test_database_init_and_import(tmp_path):
    _set_home(tmp_path)
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text("email,username,source\na@b.com,au,SiteA\n")
    from personashield.cli import app
    result = runner.invoke(app, ["database", "init"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["import", str(csv_path)])
    assert result.exit_code == 0
    assert "Imported 1" in result.stdout


def test_dash_d_command(tmp_path):
    _set_home(tmp_path)
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text("email,username,source\na@b.com,au,SiteA\n")
    from personashield.cli import app
    runner.invoke(app, ["database", "init"])
    runner.invoke(app, ["import", str(csv_path)])
    result = runner.invoke(app, ["d", "a@b.com"])
    assert result.exit_code == 0
    assert "a@b.com" in result.stdout


def test_import_dry_run_cli(tmp_path):
    _set_home(tmp_path)
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text("email,username,source\ndry@cli.com,dryu,SiteDry\n")
    from personashield.cli import app
    runner.invoke(app, ["database", "init"])
    result = runner.invoke(app, ["import", str(csv_path), "--dry-run"])
    assert result.exit_code == 0
    assert "Dry run" in result.stdout
    # confirm nothing was actually written
    result2 = runner.invoke(app, ["d", "dry@cli.com"])
    assert "Breaches: 0" in result2.stdout


def test_bulk_command(tmp_path):
    _set_home(tmp_path)
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text(
        "email,username,source\n"
        "bulk1@x.com,bu1,SiteA\n"
        "bulk2@x.com,bu2,SiteB\n"
    )
    targets_path = tmp_path / "targets.txt"
    targets_path.write_text("bulk1@x.com\nbulk2@x.com\n# comment line\n")
    from personashield.cli import app
    runner.invoke(app, ["database", "init"])
    runner.invoke(app, ["import", str(csv_path)])
    result = runner.invoke(app, ["bulk", str(targets_path)])
    assert result.exit_code == 0
    assert "bulk1@x.com" in result.stdout
    assert "bulk2@x.com" in result.stdout
