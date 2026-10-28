"""
Core anonymization engine for Cloud-DB-Anonymizer.

Streams rows out of PostgreSQL, replaces PII columns with realistic fake values,
and writes a restorable SQL dump (optionally gzip-compressed).

Anonymization is *deterministic*: the same input value + the same salt always
produces the same fake output. That keeps joins, foreign keys and duplicate
detection intact across tables and across runs, while the original value can
never be recovered without the salt (HMAC-SHA256).
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from graphlib import CycleError, TopologicalSorter
from pathlib import Path
from typing import Any, Callable, Optional

from faker import Faker

DEFAULT_SALT = "change-me-please"

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
# Each generator receives a Faker instance that has already been seeded from the
# HMAC of the original value, plus a short hex tag derived from the same digest
# (used to guarantee uniqueness for things like emails and usernames).

Generator = Callable[[Faker, str], Any]

GENERATORS: dict[str, Generator] = {
    "name": lambda f, t: f.name(),
    "first_name": lambda f, t: f.first_name(),
    "last_name": lambda f, t: f.last_name(),
    "email": lambda f, t: f"{f.user_name()}.{t[:8]}@example.com",
    "username": lambda f, t: f"{f.user_name()}_{t[:6]}",
    "phone": lambda f, t: f.numerify("+1-555-###-####"),
    "credit_card": lambda f, t: f.credit_card_number(card_type="visa16"),
    "iban": lambda f, t: f.iban(),
    "ssn": lambda f, t: f.ssn(),
    "address": lambda f, t: f.street_address(),
    "city": lambda f, t: f.city(),
    "postcode": lambda f, t: f.postcode(),
    "company": lambda f, t: f.company(),
    "ip": lambda f, t: f.ipv4_private(),
    "url": lambda f, t: f"https://example.com/{t[:12]}",
    "text": lambda f, t: f.sentence(nb_words=8),
    "date_of_birth": lambda f, t: f.date_of_birth(minimum_age=18, maximum_age=90),
}

# Strategies that don't need Faker.
SPECIAL_STRATEGIES = {"keep", "null", "redact", "hash"}

STRATEGIES = sorted(set(GENERATORS) | SPECIAL_STRATEGIES)

TEXT_TYPES = {"text", "character varying", "character", "citext", "name"}
JSON_TYPES = {"json", "jsonb"}


class RulesError(ValueError):
    """Raised when rules.json is invalid."""


class Anonymizer:
    """Deterministic, salted PII replacement."""

    def __init__(self, salt: str, locale: str = "en_US", cache_size: int = 200_000):
        if not salt:
            raise ValueError("salt must not be empty")
        self._key = salt.encode("utf-8")
        self._faker = Faker(locale)
        self._cache: dict[tuple[str, str], Any] = {}
        self._cache_size = cache_size

    def _digest(self, strategy: str, value: str) -> bytes:
        msg = f"{strategy}\x1f{value}".encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).digest()

    def anonymize(self, strategy: str, value: Any) -> Any:
        if value is None or strategy == "keep":
            return value
        if strategy == "null":
            return None
        if strategy == "redact":
            return "[REDACTED]"

        raw = str(value)
        cache_key = (strategy, raw)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        digest = self._digest(strategy, raw)
        if strategy == "hash":
            result: Any = digest.hex()[:32]
        else:
            gen = GENERATORS.get(strategy)
            if gen is None:
                raise RulesError(f"Unknown strategy '{strategy}'. Valid: {', '.join(STRATEGIES)}")
            self._faker.seed_instance(int.from_bytes(digest[:8], "big"))
            result = gen(self._faker, digest.hex())

        if len(self._cache) >= self._cache_size:
            self._cache.clear()
        self._cache[cache_key] = result
        return result


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@dataclass
class TableRule:
    columns: dict[str, str] = field(default_factory=dict)
    where: Optional[str] = None  # trusted SQL fragment from your own config
    skip_data: bool = False


@dataclass
class Rules:
    schema: str = "public"
    locale: str = "en_US"
    tables: dict[str, TableRule] = field(default_factory=dict)
    exclude_tables: list[str] = field(default_factory=list)
    include_unlisted_tables: bool = True


def load_rules(source: str | Path | dict) -> Rules:
    """Load and validate rules from a path or an already-parsed dict."""
    if isinstance(source, dict):
        data = source
    else:
        path = Path(source)
        if not path.exists():
            raise RulesError(f"Rules file not found: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RulesError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise RulesError("Rules must be a JSON object")

    tables: dict[str, TableRule] = {}
    for tname, tconf in (data.get("tables") or {}).items():
        if not isinstance(tconf, dict):
            raise RulesError(f"tables.{tname} must be an object")
        cols = tconf.get("columns") or {}
        if not isinstance(cols, dict):
            raise RulesError(f"tables.{tname}.columns must be an object of column -> strategy")
        for col, strat in cols.items():
            if strat not in STRATEGIES:
                raise RulesError(
                    f"tables.{tname}.columns.{col}: unknown strategy '{strat}'. "
                    f"Valid: {', '.join(STRATEGIES)}"
                )
        tables[tname] = TableRule(
            columns=dict(cols),
            where=tconf.get("where"),
            skip_data=bool(tconf.get("skip_data", False)),
        )

    return Rules(
        schema=data.get("schema", "public"),
        locale=data.get("locale", "en_US"),
        tables=tables,
        exclude_tables=list(data.get("exclude_tables") or []),
        include_unlisted_tables=bool(data.get("include_unlisted_tables", True)),
    )


# ---------------------------------------------------------------------------
# PostgreSQL export
# ---------------------------------------------------------------------------

@dataclass
class ColumnInfo:
    name: str
    data_type: str
    max_length: Optional[int]
    sequence: Optional[str]
    identity_always: bool


@dataclass
class TablePlan:
    name: str
    columns: list[ColumnInfo]
    rule: TableRule
    estimated_rows: int
    warnings: list[str] = field(default_factory=list)


@dataclass
class ExportResult:
    path: Path
    tables: int
    rows: int
    bytes_written: int
    seconds: float
    schema_included: bool
    warnings: list[str]


def redact_url(url: str) -> str:
    """Hide the password in a connection URL for logs."""
    return re.sub(r"(://[^:/@]+:)[^@]*@", r"\1****@", url)


def _qi(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class PostgresSanitizer:
    def __init__(self, db_url: str, rules: Rules, anonymizer: Anonymizer, batch_size: int = 500):
        self.db_url = db_url
        self.rules = rules
        self.anon = anonymizer
        self.batch_size = max(1, batch_size)
        self._conn = None

    # -- connection ---------------------------------------------------------
    def connect(self):
        import psycopg2
        import psycopg2.extensions

        self._conn = psycopg2.connect(self.db_url)
        # One consistent, read-only snapshot for the whole export.
        self._conn.set_session(
            isolation_level=psycopg2.extensions.ISOLATION_LEVEL_REPEATABLE_READ,
            readonly=True,
        )
        return self._conn

    def close(self):
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- introspection ------------------------------------------------------
    def _tables(self) -> list[str]:
        with self._conn.cursor() as cur:
            cur.execute(
                """SELECT table_name FROM information_schema.tables
                   WHERE table_schema = %s AND table_type = 'BASE TABLE'
                   ORDER BY table_name""",
                (self.rules.schema,),
            )
            return [r[0] for r in cur.fetchall()]

    def _fk_order(self, tables: list[str]) -> tuple[list[str], Optional[str]]:
        """Order tables so parents are inserted before children."""
        with self._conn.cursor() as cur:
            cur.execute(
                """SELECT ch.relname, pa.relname
                   FROM pg_constraint c
                   JOIN pg_class ch ON ch.oid = c.conrelid
                   JOIN pg_class pa ON pa.oid = c.confrelid
                   JOIN pg_namespace n ON n.oid = ch.relnamespace
                   WHERE c.contype = 'f' AND n.nspname = %s AND ch.oid <> pa.oid""",
                (self.rules.schema,),
            )
            edges = cur.fetchall()
        wanted = set(tables)
        graph: dict[str, set[str]] = {t: set() for t in tables}
        for child, parent in edges:
            if child in wanted and parent in wanted:
                graph[child].add(parent)
        try:
            ordered = list(TopologicalSorter(graph).static_order())
            return ordered, None
        except CycleError:
            return tables, "Circular foreign keys detected; tables exported alphabetically. Restore with session_replication_role=replica if inserts fail."

    def _columns(self, table: str) -> list[ColumnInfo]:
        with self._conn.cursor() as cur:
            cur.execute(
                """SELECT column_name, data_type, character_maximum_length,
                          pg_get_serial_sequence(quote_ident(table_schema) || '.' || quote_ident(table_name), column_name),
                          is_generated, identity_generation
                   FROM information_schema.columns
                   WHERE table_schema = %s AND table_name = %s
                   ORDER BY ordinal_position""",
                (self.rules.schema, table),
            )
            cols = []
            for name, dtype, maxlen, seq, generated, identity_gen in cur.fetchall():
                if generated == "ALWAYS":
                    continue  # computed columns are rebuilt on restore
                cols.append(ColumnInfo(name, dtype, maxlen, seq, identity_gen == "ALWAYS"))
            return cols

    def _estimate_rows(self, table: str) -> int:
        with self._conn.cursor() as cur:
            cur.execute(
                """SELECT GREATEST(c.reltuples, 0)::bigint FROM pg_class c
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relname = %s""",
                (self.rules.schema, table),
            )
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def plan(self) -> tuple[list[TablePlan], list[str]]:
        """Resolve which tables/columns will be exported and how."""
        if self._conn is None:
            self.connect()
        warnings: list[str] = []
        all_tables = self._tables()
        existing = set(all_tables)

        for t in self.rules.tables:
            if t not in existing:
                warnings.append(f"Rule for table '{t}' ignored: table not found in schema '{self.rules.schema}'.")

        selected = [
            t for t in all_tables
            if t not in self.rules.exclude_tables
            and (self.rules.include_unlisted_tables or t in self.rules.tables)
        ]
        ordered, fk_warning = self._fk_order(selected)
        if fk_warning:
            warnings.append(fk_warning)

        plans = []
        for t in ordered:
            rule = self.rules.tables.get(t, TableRule())
            cols = self._columns(t)
            colmap = {c.name: c for c in cols}
            tw = []
            for cname, strat in rule.columns.items():
                c = colmap.get(cname)
                if c is None:
                    tw.append(f"{t}.{cname}: column not found, rule ignored")
                elif strat not in ("keep", "null") and c.data_type not in TEXT_TYPES and not (
                    strat == "date_of_birth" and c.data_type == "date"
                ):
                    tw.append(f"{t}.{cname}: strategy '{strat}' writes text into a '{c.data_type}' column")
            plans.append(TablePlan(t, cols, rule, self._estimate_rows(t), tw))
        return plans, warnings

    # -- export -------------------------------------------------------------
    def _pg_dump_schema(self) -> Optional[str]:
        if shutil.which("pg_dump") is None:
            return None
        cmd = ["pg_dump", "--schema-only", "--no-owner", "--no-privileges", "-n", self.rules.schema]
        for t in self.rules.exclude_tables:
            cmd += ["-T", f"{_qi(self.rules.schema)}.{_qi(t)}"]
        proc = subprocess.run(cmd + [self.db_url], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "pg_dump failed")
        # Restoring into a fresh database where the schema (e.g. "public") already
        # exists must not fail.
        return re.sub(r"^CREATE SCHEMA (\S+);", r"CREATE SCHEMA IF NOT EXISTS \1;",
                      proc.stdout, flags=re.MULTILINE)

    def export(
        self,
        output: str | Path,
        include_schema: bool = True,
        on_table_start: Callable[[str, int], None] | None = None,
        on_rows: Callable[[int], None] | None = None,
        on_table_done: Callable[[str, int], None] | None = None,
    ) -> ExportResult:
        from psycopg2 import sql
        from psycopg2.extras import Json

        started = time.monotonic()
        plans, warnings = self.plan()
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        opener = gzip.open if out_path.suffix == ".gz" else open

        schema_included = False
        schema_sql = None
        if include_schema:
            try:
                schema_sql = self._pg_dump_schema()
                if schema_sql is None:
                    warnings.append("pg_dump not found on PATH; exported data only (use --no-schema to silence).")
            except RuntimeError as exc:
                warnings.append(f"pg_dump schema export failed ({exc}); exported data only.")

        total_rows = 0
        mog = self._conn.cursor()
        sch = self.rules.schema

        with opener(out_path, "wt", encoding="utf-8") as fh:
            fh.write("-- Cloud-DB-Anonymizer sanitized dump\n")
            fh.write(f"-- Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
            fh.write(f"-- Source: {redact_url(self.db_url)}  schema={sch}\n")
            fh.write("-- PII columns were replaced with deterministic fake values.\n\n")
            if schema_sql:
                fh.write(schema_sql)
                fh.write("\n")
                schema_included = True
            fh.write("SET client_encoding = 'UTF8';\nSET standard_conforming_strings = on;\nBEGIN;\n\n")

            for idx, p in enumerate(plans):
                if on_table_start:
                    on_table_start(p.name, p.estimated_rows)
                if p.rule.skip_data or not p.columns:
                    if on_table_done:
                        on_table_done(p.name, 0)
                    continue

                strategies = [p.rule.columns.get(c.name, "keep") for c in p.columns]
                is_json = [c.data_type in JSON_TYPES for c in p.columns]
                maxlens = [c.max_length if c.data_type in TEXT_TYPES else None for c in p.columns]
                col_list = ", ".join(_qi(c.name) for c in p.columns)
                overriding = " OVERRIDING SYSTEM VALUE" if any(c.identity_always for c in p.columns) else ""
                insert_head = f"INSERT INTO {_qi(sch)}.{_qi(p.name)} ({col_list}){overriding} VALUES\n"
                template = "(" + ",".join(["%s"] * len(p.columns)) + ")"

                query = sql.SQL("SELECT {cols} FROM {sch}.{tbl}").format(
                    cols=sql.SQL(", ").join(sql.Identifier(c.name) for c in p.columns),
                    sch=sql.Identifier(sch),
                    tbl=sql.Identifier(p.name),
                )
                if p.rule.where:
                    query = query + sql.SQL(" WHERE ") + sql.SQL(p.rule.where)

                table_rows = 0
                with self._conn.cursor(name=f"cdba_{idx}") as cur:
                    cur.itersize = self.batch_size
                    cur.execute(query)
                    while True:
                        batch = cur.fetchmany(self.batch_size)
                        if not batch:
                            break
                        values = []
                        for row in batch:
                            out = []
                            for i, v in enumerate(row):
                                strat = strategies[i]
                                if strat != "keep":
                                    v = self.anon.anonymize(strat, v)
                                    if maxlens[i] and isinstance(v, str):
                                        v = v[: maxlens[i]]
                                if is_json[i] and v is not None and not isinstance(v, str):
                                    v = Json(v)
                                out.append(v)
                            values.append(mog.mogrify(template, out).decode("utf-8"))
                        fh.write(insert_head + ",\n".join(values) + ";\n")
                        table_rows += len(batch)
                        if on_rows:
                            on_rows(len(batch))

                for c in p.columns:
                    if c.sequence:
                        tbl = f"{_qi(sch)}.{_qi(p.name)}"
                        col = _qi(c.name)
                        seq = c.sequence.replace("'", "''")
                        fh.write(
                            f"SELECT setval('{seq}', COALESCE((SELECT MAX({col}) FROM {tbl}), 1), "
                            f"(SELECT MAX({col}) FROM {tbl}) IS NOT NULL);\n"
                        )
                fh.write("\n")
                total_rows += table_rows
                if on_table_done:
                    on_table_done(p.name, table_rows)

            fh.write("COMMIT;\n")

        mog.close()
        for p in plans:
            warnings.extend(p.warnings)
        return ExportResult(
            path=out_path,
            tables=len(plans),
            rows=total_rows,
            bytes_written=out_path.stat().st_size,
            seconds=time.monotonic() - started,
            schema_included=schema_included,
            warnings=warnings,
        )


def default_output_name(db_url: str, compress: bool = True) -> str:
    from urllib.parse import urlparse

    dbname = re.sub(r"[^A-Za-z0-9_-]", "_", urlparse(db_url).path.strip("/") or "db")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"sanitized_{dbname}_{stamp}.sql" + (".gz" if compress else "")
