#!/usr/bin/env python3
"""
Cloud-DB-Anonymizer — PostgreSQL PII anonymizer & sanitized backup CLI.

    python main.py sanitize --db-url postgresql://user:pass@host/db --rules rules.json
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn, DownloadColumn, MofNCompleteColumn, Progress, SpinnerColumn,
    TextColumn, TimeElapsedColumn, TransferSpeedColumn,
)
from rich.table import Table

import sanitizer as core

__version__ = "1.0.0"
PRO_URL = "https://qhnfvf-jb.myshopify.com/products/cloud-db-anonymizer-pro-suite"

app = typer.Typer(
    name="cloud-db-anonymizer",
    help="Anonymize PostgreSQL PII and export clean, restorable SQL dumps.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
err = Console(stderr=True)


def _salt(salt: Optional[str]) -> str:
    value = salt or os.getenv("ANON_SALT") or core.DEFAULT_SALT
    if value == core.DEFAULT_SALT:
        err.print("[yellow]⚠  Using the default salt. Set ANON_SALT (or --salt) to a long random secret "
                  "so fake values can't be correlated across teams.[/yellow]")
    return value


def _load_rules(path: Path) -> core.Rules:
    try:
        return core.load_rules(path)
    except core.RulesError as exc:
        err.print(f"[bold red]Rules error:[/bold red] {exc}")
        raise typer.Exit(2)


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def _plan_table(plans: list[core.TablePlan]) -> Table:
    t = Table(title="Export plan", header_style="bold cyan", show_lines=False)
    t.add_column("Table")
    t.add_column("≈ Rows", justify="right")
    t.add_column("Anonymized columns")
    for p in plans:
        cols = ", ".join(f"{c}→[magenta]{s}[/magenta]" for c, s in p.rule.columns.items()) or "[dim]—[/dim]"
        if p.rule.skip_data:
            cols = "[dim]schema only (skip_data)[/dim]"
        t.add_row(p.name, f"{p.estimated_rows:,}", cols)
    return t


@app.command()
def sanitize(
    db_url: str = typer.Option(..., "--db-url", envvar="DATABASE_URL",
                               help="PostgreSQL URL, e.g. postgresql://user:pass@host:5432/db"),
    rules: Path = typer.Option(Path("rules.json"), "--rules", "-r", help="Anonymization rules file."),
    output: Optional[Path] = typer.Option(None, "--output", "-o",
                                          help="Output file. Ends in .gz → gzip. Default: sanitized_<db>_<time>.sql.gz"),
    salt: Optional[str] = typer.Option(None, "--salt", envvar="ANON_SALT", help="Secret salt for deterministic hashing."),
    batch_size: int = typer.Option(1000, "--batch-size", help="Rows per INSERT statement / fetch."),
    no_schema: bool = typer.Option(False, "--no-schema", help="Skip pg_dump DDL; export data only."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate rules against the live schema and exit."),
    upload_bucket: Optional[str] = typer.Option(None, "--upload", help="Also upload the dump to this S3-compatible bucket."),
    endpoint_url: Optional[str] = typer.Option(None, "--endpoint-url", envvar="S3_ENDPOINT_URL",
                                               help="S3-compatible endpoint (R2, Spaces, MinIO...)."),
):
    """Connect to PostgreSQL, anonymize PII columns, and export a clean SQL dump."""
    r = _load_rules(rules)
    anon = core.Anonymizer(_salt(salt), locale=r.locale)
    console.print(f"[bold]🔌 Connecting[/bold] to {core.redact_url(db_url)}")

    try:
        san = core.PostgresSanitizer(db_url, r, anon, batch_size=batch_size)
        san.connect()
    except Exception as exc:  # psycopg2.OperationalError and friends
        err.print(f"[bold red]Connection failed:[/bold red] {exc}")
        raise typer.Exit(1)

    try:
        plans, warnings = san.plan()
        console.print(_plan_table(plans))
        for w in warnings + [w for p in plans for w in p.warnings]:
            console.print(f"[yellow]⚠  {w}[/yellow]")
        if dry_run:
            console.print("[green]✔ Dry run OK — rules are valid for this database.[/green]")
            return

        out = output or Path(core.default_output_name(db_url))
        est_total = sum(p.estimated_rows for p in plans if not p.rule.skip_data) or None

        with Progress(
            SpinnerColumn(), TextColumn("[bold blue]{task.description}"), BarColumn(),
            MofNCompleteColumn(), TimeElapsedColumn(), console=console, transient=False,
        ) as progress:
            overall = progress.add_task("All tables", total=est_total)
            current = {"id": None}

            def start(name: str, est: int):
                current["id"] = progress.add_task(f"  {name}", total=est or None)

            def rows(n: int):
                progress.advance(overall, n)
                progress.advance(current["id"], n)

            def done(name: str, count: int):
                progress.update(current["id"], total=max(count, 1), completed=max(count, 1))

            result = san.export(out, include_schema=not no_schema,
                                on_table_start=start, on_rows=rows, on_table_done=done)
            progress.update(overall, total=max(result.rows, 1), completed=max(result.rows, 1))
    except Exception as exc:
        err.print(f"[bold red]Export failed:[/bold red] {exc}")
        raise typer.Exit(1)
    finally:
        san.close()

    for w in result.warnings:
        if w not in warnings:
            console.print(f"[yellow]⚠  {w}[/yellow]")

    console.print(Panel.fit(
        f"[bold green]✔ Sanitized dump ready[/bold green]\n"
        f"File:    {result.path}\n"
        f"Tables:  {result.tables}   Rows: {result.rows:,}   Size: {_human(result.bytes_written)}\n"
        f"Schema:  {'included' if result.schema_included else 'data only'}   Time: {result.seconds:.1f}s\n\n"
        f"Restore: [cyan]{'gunzip -c' if str(result.path).endswith('.gz') else 'cat'} {result.path} | psql $TARGET_DB_URL[/cyan]",
        border_style="green",
    ))

    if upload_bucket:
        _do_upload(result.path, upload_bucket, endpoint_url, prefix="")
    _pro_hint()


def _do_upload(path: Path, bucket: str, endpoint_url: Optional[str], prefix: str) -> None:
    import cloud_sync

    size = path.stat().st_size
    with Progress(
        TextColumn("[bold blue]☁  Uploading"), BarColumn(), DownloadColumn(),
        TransferSpeedColumn(), console=console,
    ) as progress:
        task = progress.add_task("upload", total=size)
        try:
            res = cloud_sync.upload_file(path, bucket, prefix=prefix, endpoint_url=endpoint_url,
                                         on_progress=lambda n: progress.advance(task, n))
        except Exception as exc:
            err.print(f"[bold red]Upload failed:[/bold red] {exc}")
            raise typer.Exit(1)
    console.print(f"[green]✔ Uploaded to {res.uri}[/green]")


@app.command()
def sync(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, help="Dump file to upload."),
    bucket: str = typer.Option(..., "--bucket", "-b", help="Target bucket name."),
    prefix: str = typer.Option("", "--prefix", help="Key prefix / folder inside the bucket."),
    endpoint_url: Optional[str] = typer.Option(None, "--endpoint-url", envvar="S3_ENDPOINT_URL",
                                               help="S3-compatible endpoint (R2, Spaces, MinIO...)."),
):
    """Upload a sanitized dump to one S3-compatible bucket."""
    _do_upload(file, bucket, endpoint_url, prefix)
    _pro_hint()


@app.command()
def preview(
    value: str = typer.Argument(..., help="A sample input value, e.g. jane@corp.com"),
    strategy: str = typer.Option("email", "--strategy", "-s", help=f"One of: {', '.join(core.STRATEGIES)}"),
    salt: Optional[str] = typer.Option(None, "--salt", envvar="ANON_SALT"),
    locale: str = typer.Option("en_US", "--locale"),
):
    """Show what a value becomes — handy for testing rules without a database."""
    if strategy not in core.STRATEGIES:
        err.print(f"[red]Unknown strategy '{strategy}'.[/red] Valid: {', '.join(core.STRATEGIES)}")
        raise typer.Exit(2)
    out = core.Anonymizer(_salt(salt), locale=locale).anonymize(strategy, value)
    console.print(f"[dim]{value}[/dim]  →  [bold green]{out}[/bold green]   [dim]({strategy})[/dim]")


@app.command()
def strategies():
    """List all anonymization strategies."""
    t = Table(header_style="bold cyan")
    t.add_column("Strategy")
    t.add_column("Example output")
    anon = core.Anonymizer("demo-salt")
    for s in core.STRATEGIES:
        t.add_row(s, str(anon.anonymize(s, "sample-value-123")))
    console.print(t)


@app.command()
def init(path: Path = typer.Argument(Path("rules.json"), help="Where to write the starter rules file.")):
    """Write a starter rules.json."""
    if path.exists():
        err.print(f"[yellow]{path} already exists — not overwriting.[/yellow]")
        raise typer.Exit(1)
    starter = {
        "schema": "public",
        "locale": "en_US",
        "include_unlisted_tables": True,
        "exclude_tables": [],
        "tables": {
            "users": {"columns": {"email": "email", "full_name": "name", "phone": "phone"}},
        },
    }
    path.write_text(json.dumps(starter, indent=2) + "\n", encoding="utf-8")
    console.print(f"[green]✔ Wrote {path}[/green] — edit the table/column names to match your schema.")


@app.command()
def version():
    """Print the version."""
    console.print(f"cloud-db-anonymizer {__version__}")


def _pro_hint() -> None:
    console.print(
        f"[dim]🚀 Multi-cloud sync (S3 + R2 + Spaces), scheduled backups, web dashboard & Telegram/Discord alerts → "
        f"Pro Suite: {PRO_URL}[/dim]"
    )


if __name__ == "__main__":
    sys.exit(app())
