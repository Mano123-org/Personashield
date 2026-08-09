# PersonaShield

Local-first OSINT and breach-intelligence CLI framework. **No API keys required,
none supported.** Everything runs against public, no-key data sources and a
local SQLite database you populate from datasets you own or are authorized
to analyze.

## Features

- **Username OSINT** — checks public profile existence across ~18 platforms (GitHub, GitLab, Reddit, etc.), Sherlock-inspired but independently implemented.
- **Local breach database** — SQLite-backed, fully offline search by email, username, or phone.
- **Dataset import** — CSV / JSON / SQLite, with automatic field-name normalization (`mail`/`email_address` → `email`, etc.).
- **Domain intelligence** — DNS, MX, SPF, DMARC posture via public DNS (no key needed).
- **Risk engine** — configurable LOW / MEDIUM / HIGH / CRITICAL scoring based on breach count, recency, and sensitivity of exposed fields.
- **Reporting** — JSON, CSV, and styled HTML reports per target.
- **Safety by design** — plaintext passwords are never stored or printed; only a boolean "password hash present" flag and optional hash-type metadata are kept.

## Architecture

```
PersonaShield
     │
 ┌───┴────────────────┐
 │                    │
OSINT Engine      Breach Engine
 │                    │
Sherlock-style     Local SQLite DB
adapter             (CSV/JSON/SQLite import)
 │                    │
 └────────┬───────────┘
          │
     Risk Engine
          │
   Report Generator
          │
   ┌──────┼──────┐
  CLI    JSON   HTML/CSV
```

## Installation

```bash
cd PersonaShield
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
personashield --help
```

By default, data lives under `~/.personashield/`. Override with the
`PERSONASHIELD_HOME` environment variable.

## Commands

```bash
personashield username <username>          # public profile OSINT
personashield email <address>               # local breach + domain posture
personashield phone <number>                 # local breach search
personashield domain <domain>                # DNS / SPF / DMARC
personashield -d <target>                    # auto-detect + local breach search
personashield -d <target> -l                 # same, with full detailed records
personashield import <file.csv|.json|.db>    # import an authorized dataset
personashield import <file> --dry-run        # validate/preview without writing
personashield bulk <targets.txt>             # look up every target in a file
personashield bulk <targets.txt> --reports   # ...and write reports for each
personashield report <target>                # write JSON/CSV/HTML reports
personashield database init                  # create the local DB
personashield database status                # check DB existence
personashield database stats                 # record/index counts
personashield config                         # show local paths in use
personashield version
```

## Database schema

```
breaches
────────
id, source, domain, email, username, phone,
has_password (bool), hash_type, full_name,
ip_address, breach_date, description
```

Indexed on `email`, `username`, `phone`, `domain`, `source`.

## Importing data

```bash
personashield import data/sample/sample_breach.csv
```

Column names are normalized automatically — `mail`, `email_address` → `email`;
`user`, `user_name` → `username`; and so on (see
`personashield/utils/normalization.py`). Plaintext password values are never
carried into the database — only a `has_password` flag and, if present, a
`hash_type` label.

Use `--dry-run` to validate a dataset before committing it — it shows row
counts, per-field coverage, and any unrecognized columns without writing
anything:

```bash
personashield import messy_export.csv --dry-run
```

Only import data you own or are authorized to analyze (e.g., synthetic
classroom data, your own organization's incident-response exports).
PersonaShield does not fetch, scrape, or connect to any breach-data
marketplace, leak site, or hidden service — by design.

## Bulk target processing

Process a whole list of targets against the local database in one pass:

```bash
personashield bulk data/sample/sample_targets.txt
personashield bulk data/sample/sample_targets.txt --reports   # also write per-target reports
```

The input file is one target per line (email, username, phone, or domain);
lines starting with `#` are ignored.

## Risk scoring

Score is derived from breach count, source diversity, recency (last 12
months), and which sensitive fields are exposed (password hash, phone, full
name). Thresholds live in `personashield/config.py::RiskThresholds` and are
adjustable.

| Breaches | Typical tier |
|---|---|
| 1 old breach | LOW |
| 2–3 breaches | MEDIUM |
| 4–6 breaches | HIGH |
| Password hash + recent breach | HIGH or higher |
| Multiple sensitive fields + recent | CRITICAL |

## Reports

```bash
personashield report user@example.com
```

Writes `<safe-name>.json`, `.csv`, and `.html` to the reports directory
(`~/.personashield/reports` by default). The HTML report is a self-contained
static file — nothing is sent externally when it's generated or viewed.

## Sherlock integration

`personashield/integrations/sherlock_adapter.py` implements the same core
idea as Sherlock — request a platform's public profile URL and interpret the
HTTP response — as a small, independent PersonaShield module rather than a
vendored copy of the Sherlock project. Add or edit entries in the `SITES`
list to extend coverage.

## Security considerations

- No plaintext passwords are ever stored, printed, or cracked.
- No API keys are used, read, or required anywhere in the core tool.
- No scraping of, or connections to, criminal marketplaces, leak forums, or
  hidden services.
- Sensitive values are excluded from log output (`personashield/utils/logging.py`).
- Breach records should be treated as sensitive — restrict access to your
  local database file and generated reports as you would any PII.

## Legal / ethical usage

PersonaShield is intended for authorized use only: investigating your own
identity/organization's exposure, classroom security-education exercises
with synthetic data, or engagements where you have explicit authorization.
Do not use it against targets you don't have authorization to investigate.

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

## Sample data

`data/sample/sample_breach.csv` is a fully synthetic dataset
(`*.example.test` addresses, fake hash placeholders) for demos and tests —
no real credentials are included anywhere in this repository.

## Roadmap

- Optional plugin interface for additional no-key OSINT sources
- Configurable output themes for the HTML report
- Scheduled/recurring bulk scans with delta reporting
