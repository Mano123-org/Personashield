"""Terminal UI helpers built on Rich."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from personashield.models import BreachRecord, DomainIntel, RiskAssessment, UsernameHit

console = Console()

RISK_STYLES = {
    "NONE": "dim",
    "LOW": "bold green",
    "MEDIUM": "bold yellow",
    "HIGH": "bold dark_orange",
    "CRITICAL": "bold red",
}

BANNER = r"""
[bold cyan]
 ____                                 ____  _     _      _     _
|  _ \ ___ _ __ ___  ___  _ __   __ _/ ___|| |__ (_) ___| | __| |
| |_) / _ \ '__/ __|/ _ \| '_ \ / _` \___ \| '_ \| |/ _ \ |/ _` |
|  __/  __/ |  \__ \ (_) | | | | (_| |___) | | | | |  __/ | (_| |
|_|   \___|_|  |___/\___/|_| |_|\__,_|____/|_| |_|_|\___|_|\__,_|
[/bold cyan]
[dim]Local-first OSINT & breach intelligence — no API keys required[/dim]
"""


def print_banner() -> None:
    console.print(BANNER)


def print_risk_badge(risk: RiskAssessment) -> None:
    style = RISK_STYLES.get(risk.level.value, "white")
    console.print(
        Panel(
            Text(f"{risk.level.value}  (score: {risk.score})", style=style, justify="center"),
            title="Risk Assessment",
            border_style=style,
        )
    )
    for reason in risk.reasons:
        console.print(f"  • {reason}", style="dim")


def print_summary(target: str, target_type: str, records: list[BreachRecord], risk: RiskAssessment) -> None:
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Type:[/bold] {target_type}")
    console.print(f"[bold]Breaches:[/bold] {len(records)}")
    print_risk_badge(risk)

    if records:
        sources = sorted({r.source for r in records})
        console.print("\n[bold]Sources:[/bold]")
        for s in sources:
            console.print(f"  - {s}")

        fields: set[str] = set()
        for r in records:
            fields.update(r.compromised_fields())
        if fields:
            console.print("\n[bold]Compromised fields:[/bold]")
            for f in sorted(fields):
                console.print(f"  [+] {f}")


def print_detailed(records: list[BreachRecord]) -> None:
    if not records:
        console.print("[dim]No detailed records to show.[/dim]")
        return
    for r in records:
        console.print()
        console.print(Panel.fit(
            f"[bold]{r.source}[/bold]\n"
            f"Date: {r.breach_date or 'unknown'}\n"
            f"Compromised fields: {', '.join(r.compromised_fields()) or 'none'}\n"
            f"Hash type: {r.hash_type or 'n/a'}\n"
            f"Description: {r.description or 'n/a'}",
            border_style="cyan",
        ))


def print_username_table(hits: list[UsernameHit]) -> None:
    table = Table(title="Username OSINT Results")
    table.add_column("Platform")
    table.add_column("URL", overflow="fold")
    table.add_column("Status")
    table.add_column("Response (ms)", justify="right")

    status_styles = {"Found": "bold green", "Not Found": "dim", "Error": "red", "Unknown": "yellow"}
    for hit in hits:
        style = status_styles.get(hit.status, "white")
        table.add_row(hit.platform, hit.url, f"[{style}]{hit.status}[/{style}]",
                      str(hit.response_ms) if hit.response_ms is not None else "-")
    console.print(table)


def print_domain_intel(intel: DomainIntel) -> None:
    table = Table(title=f"Domain Intelligence: {intel.domain}")
    table.add_column("Field")
    table.add_column("Value", overflow="fold")
    table.add_row("A records", ", ".join(intel.a_records) or "-")
    table.add_row("MX records", ", ".join(intel.mx_records) or "-")
    table.add_row("SPF", "Present" if intel.has_spf else "Missing")
    table.add_row("DMARC", "Present" if intel.has_dmarc else "Missing")
    console.print(table)


def print_import_preview(preview, path_name: str, dry_run: bool) -> None:
    title = f"Import preview: {path_name}" if dry_run else f"Import: {path_name}"
    table = Table(title=title)
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Total rows", str(preview.total_rows))
    table.add_row("Valid records", str(len(preview.valid_records)))
    table.add_row("Skipped rows", str(preview.skipped_count))
    console.print(table)

    if preview.field_coverage:
        cov = Table(title="Field coverage")
        cov.add_column("Field")
        cov.add_column("Records", justify="right")
        for field_name, count in sorted(preview.field_coverage.items(), key=lambda x: -x[1]):
            cov.add_row(field_name, str(count))
        console.print(cov)

    for w in preview.warnings:
        console.print(f"[yellow]Warning:[/yellow] {w}")

    if dry_run:
        console.print("[dim]Dry run — nothing was written to the database.[/dim]")


def print_bulk_summary(rows: list[dict]) -> None:
    table = Table(title="Bulk Target Results")
    table.add_column("Target")
    table.add_column("Type")
    table.add_column("Breaches", justify="right")
    table.add_column("Risk")

    for row in rows:
        style = RISK_STYLES.get(row["risk"], "white")
        table.add_row(
            row["target"], row["type"], str(row["breaches"]),
            f"[{style}]{row['risk']}[/{style}]",
        )
    console.print(table)


def print_db_stats(stats: dict) -> None:
    table = Table(title="Database")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Breach records", f"{stats['records']:,}")
    table.add_row("Sources", f"{stats['sources']:,}")
    table.add_row("Emails indexed", f"{stats['emails_indexed']:,}")
    table.add_row("Usernames indexed", f"{stats['usernames_indexed']:,}")
    table.add_row("Phones indexed", f"{stats['phones_indexed']:,}")
    console.print(table)
