"""PersonaShield CLI entrypoint."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from personashield import __version__
from personashield.config import get_settings
from personashield.database import Database
from personashield.models import BreachRecord, RiskLevel, TargetReport, TargetType
from personashield.modules import breach as breach_mod
from personashield.modules import domain as domain_mod
from personashield.modules import report as report_mod
from personashield.modules import risk as risk_mod
from personashield.modules import username as username_mod
from personashield.utils.validators import detect_target_type
from personashield import output as ui

app = typer.Typer(
    name="personashield",
    help="Local-first OSINT & breach-intelligence CLI. No API keys required.",
    add_completion=False,
    no_args_is_help=True,
)
database_app = typer.Typer(help="Manage the local breach database.")
app.add_typer(database_app, name="database")

console = Console()


def _get_db() -> Database:
    settings = get_settings()
    db = Database(settings.db_path)
    db.init_schema()
    return db


def _build_report(target: str) -> TargetReport:
    target_type = detect_target_type(target)
    db = _get_db()
    records = breach_mod.search_target(db, target, target_type)
    risk = risk_mod.assess_risk(records, get_settings().risk)
    return TargetReport(
        target=target, target_type=target_type, breaches=records,
        risk=risk, generated_at=report_mod.now_iso(),
    )


@app.command()
def version() -> None:
    """Show PersonaShield version."""
    console.print(f"PersonaShield v{__version__}")


@app.command()
def username(
    handle: str = typer.Argument(..., help="Username to search across platforms."),
    timeout: float = typer.Option(6.0, help="Per-request timeout in seconds."),
) -> None:
    """Run username OSINT enumeration across public platforms."""
    ui.print_banner()
    with console.status(f"Checking '{handle}' across platforms..."):
        hits = username_mod.search_username(handle, timeout=timeout)
    ui.print_username_table(hits)


@app.command()
def email(
    address: str = typer.Argument(..., help="Email address to investigate."),
) -> None:
    """Look up an email address in the local breach database + domain posture."""
    ui.print_banner()
    report = _build_report(address)
    ui.print_summary(report.target, report.target_type.value, report.breaches, report.risk)
    console.print()
    intel = domain_mod.lookup_domain(address.split("@")[-1])
    ui.print_domain_intel(intel)


@app.command()
def phone(
    number: str = typer.Argument(..., help="Phone number to investigate."),
) -> None:
    """Look up a phone number in the local breach database."""
    ui.print_banner()
    report = _build_report(number)
    ui.print_summary(report.target, report.target_type.value, report.breaches, report.risk)


@app.command()
def domain(
    name: str = typer.Argument(..., help="Domain to investigate."),
) -> None:
    """Perform DNS / MX / SPF / DMARC lookups for a domain (no API key)."""
    ui.print_banner()
    intel = domain_mod.lookup_domain(name)
    ui.print_domain_intel(intel)


@app.command(name="import")
def import_cmd(
    file: Path = typer.Argument(..., exists=True, help="CSV, JSON, or SQLite file to import."),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Override source label."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Validate and preview the dataset without writing to the database."
    ),
) -> None:
    """Import an authorized local breach dataset (CSV / JSON / SQLite)."""
    db = _get_db()
    imported, skipped, preview = breach_mod.import_file(
        file, db, source_hint=source, dry_run=dry_run
    )
    ui.print_import_preview(preview, file.name, dry_run)
    if not dry_run:
        console.print(f"[green]Imported {imported} record(s)[/green], skipped {skipped} (missing identifiers).")


@app.command()
def report(
    target: str = typer.Argument(..., help="Email, username, phone, or domain."),
) -> None:
    """Generate JSON, CSV, and HTML reports for a target."""
    settings = get_settings()
    rep = _build_report(target)
    paths = report_mod.generate_reports(rep, settings.reports_dir)
    console.print(f"[green]Reports written:[/green]")
    for fmt, p in paths.items():
        console.print(f"  {fmt.upper()}: {p}")


@app.command(name="d", help="Search the local breach database for a target (invoke as: personashield -d <target> [-l]).")
def dash_d(
    target: str = typer.Argument(..., help="Email, username, phone, or domain to search."),
    detailed: bool = typer.Option(False, "-l", "--list", help="Show full detailed breach records."),
) -> None:
    """Search the local breach database for a target (auto-detects type)."""
    ui.print_banner()
    rep = _build_report(target)
    ui.print_summary(rep.target, rep.target_type.value, rep.breaches, rep.risk)
    if detailed:
        console.print("\n[bold]Detailed records:[/bold]")
        ui.print_detailed(rep.breaches)


@app.command()
def bulk(
    targets_file: Path = typer.Argument(
        ..., exists=True, help="Text file with one target (email/username/phone/domain) per line."
    ),
    write_reports: bool = typer.Option(
        False, "--reports", help="Also write JSON/CSV/HTML reports for every target."
    ),
) -> None:
    """Run local breach lookups for every target listed in a text file."""
    ui.print_banner()
    lines = [
        line.strip() for line in targets_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        console.print("[yellow]No targets found in file.[/yellow]")
        raise typer.Exit(code=0)

    settings = get_settings()
    results = []
    with console.status(f"Processing {len(lines)} target(s)..."):
        for target in lines:
            rep = _build_report(target)
            results.append({
                "target": rep.target,
                "type": rep.target_type.value,
                "breaches": len(rep.breaches),
                "risk": rep.risk.level.value,
            })
            if write_reports:
                report_mod.generate_reports(rep, settings.reports_dir)

    ui.print_bulk_summary(results)
    if write_reports:
        console.print(f"[green]Reports written to:[/green] {settings.reports_dir}")


@database_app.command("init")
def database_init() -> None:
    """Initialize the local SQLite breach database."""
    db = _get_db()
    console.print(f"[green]Database ready:[/green] {db.db_path}")


@database_app.command("status")
def database_status() -> None:
    """Show whether the database exists and is initialized."""
    settings = get_settings()
    db = Database(settings.db_path)
    if db.exists():
        console.print(f"[green]Database found:[/green] {db.db_path}")
    else:
        console.print(f"[yellow]No database yet at {db.db_path}. Run 'personashield database init'.[/yellow]")


@database_app.command("stats")
def database_stats() -> None:
    """Show record counts and index coverage."""
    db = _get_db()
    stats = db.stats()
    ui.print_db_stats(stats)


@app.command()
def config() -> None:
    """Show current PersonaShield configuration (all local paths)."""
    settings = get_settings()
    console.print(f"App home:     {settings.app_home}")
    console.print(f"Data dir:     {settings.data_dir}")
    console.print(f"Reports dir:  {settings.reports_dir}")
    console.print(f"Database:     {settings.db_path}")
    console.print("[dim]No API keys are used or required by PersonaShield.[/dim]")


def main() -> None:
    # Click/Typer treat a leading "-d" as an unknown option rather than a
    # command name. Rewrite `personashield -d <target> ...` to the
    # internally-registered `d` command so the documented CLI syntax works.
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        sys.argv[1] = "d"
    app()


if __name__ == "__main__":
    main()
