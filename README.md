<div align="center">

# 🛡️ Cloud-DB-Anonymizer

### PostgreSQL PII Anonymizer & Database Sanitizer CLI — safe production dumps for dev, staging and CI

**Export your production PostgreSQL database, replace every email, name, phone, credit card and IBAN with realistic fake data, and get a clean, restorable SQL dump — in one command.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12%2B-336791.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![GDPR friendly](https://img.shields.io/badge/GDPR-friendly-8A2BE2.svg)](#-why-deterministic-anonymization)

</div>

> [!TIP]
> ### 🚀 Need Multi-Cloud Sync, Docker Dashboard, and Telegram Webhooks?
> **[Get the Pro Enterprise Suite for $29 →](https://qhnfvf-jb.myshopify.com/products/cloud-db-anonymizer-pro-suite)**
>
> Scheduled backups • Parallel upload to **AWS S3 + Cloudflare R2 + DigitalOcean Spaces** • Next.js web dashboard • **Telegram & Discord** alerts • One-command `docker compose up`

---

## Why?

Copying production data to your laptop, a staging server or a CI pipeline is how most data leaks happen. But developers *need* realistic data to reproduce bugs, test migrations and demo features.

**Cloud-DB-Anonymizer** gives you both: a real copy of your schema and data, with personal information replaced by believable fakes — before the dump ever touches disk.

```console
$ python main.py sanitize --db-url $DATABASE_URL --rules rules.json
🔌 Connecting to postgresql://app:****@db.internal:5432/production
  All tables ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1,284,330/1,284,330 0:00:41
    users    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   48,210/48,210
    payments ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  201,877/201,877
╭───────────────────────────────────────────────────────────╮
│ ✔ Sanitized dump ready                                    │
│ File:    sanitized_production_20261028T031500Z.sql.gz     │
│ Tables:  23   Rows: 1,284,330   Size: 61.4 MB             │
╰───────────────────────────────────────────────────────────╯
```

| Before (production) | After (sanitized) |
|---|---|
| `jane.doe@acme.com` | `antoniomacdonald.faa812c4@example.com` |
| `Jane Doe` | `Maria Harmon` |
| `+212 600-111222` | `+1-555-726-7654` |
| `4111 1111 1111 1111` | `4756410247684656` *(Luhn-valid)* |
| `GB82WEST12345698765432` | `GB17NPNE05766470207453` |

## ✨ Features

- **Deterministic anonymization** — HMAC-SHA256 seeded fakes: the same input always maps to the same output, so **foreign keys, joins and unique constraints keep working** across tables.
- **20 strategies** — `email`, `name`, `phone`, `credit_card` (Luhn-valid), `iban`, `ssn`, `address`, `ip`, `date_of_birth`, `hash`, `redact`, `null` and more.
- **Restorable output** — full schema via `pg_dump` + batched `INSERT`s in foreign-key order, sequence resets, identity columns, JSON/JSONB, arrays, generated columns.
- **Consistent snapshot** — single `REPEATABLE READ, READ ONLY` transaction; never writes to your database.
- **Streams large tables** — server-side cursors, constant memory, gzip on the fly.
- **Row filtering & table control** — `where` clauses to subset data, `exclude_tables`, `skip_data` for schema-only tables.
- **Respects column limits** — fake values are truncated to `varchar(n)` so restores don't fail.
- **One-shot cloud upload** — push the dump to any S3-compatible bucket (S3, R2, Spaces, MinIO, B2, Wasabi).
- **Beautiful terminal UX** — `rich` progress bars, dry-run plan table, clear errors.

## 📦 Installation

```bash
git clone https://github.com/fadadyounes-pixel/cloud-db-anonymizer.git
cd cloud-db-anonymizer
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Prefer a zip? [Download the latest release](https://qhnfvf-jb.myshopify.com/products/cloud-db-anonymizer-cli-free) · Project page: [PostgreSQL PII Anonymizer](https://qhnfvf-jb.myshopify.com/pages/postgresql-pii-anonymizer)

`pg_dump` (from the PostgreSQL client tools) is recommended so the dump includes your schema. Without it you get a data-only dump.

## ⚡ Quick start

**1. Create a salt** (keep it secret and stable — it determines every fake value):

```bash
export ANON_SALT=$(openssl rand -hex 32)
```

**2. Describe your PII** in `rules.json` (or run `python main.py init` for a starter):

```json
{
  "schema": "public",
  "exclude_tables": ["audit_logs", "sessions"],
  "tables": {
    "users":    { "columns": { "email": "email", "full_name": "name", "phone": "phone" } },
    "payments": { "columns": { "card_number": "credit_card", "iban": "iban" } },
    "support_tickets": {
      "columns": { "body": "redact" },
      "where": "created_at > now() - interval '90 days'"
    },
    "uploads":  { "skip_data": true }
  }
}
```

**3. Check the plan** against your live schema:

```bash
python main.py sanitize --db-url "postgresql://user:pass@host:5432/db" --rules rules.json --dry-run
```

**4. Export:**

```bash
python main.py sanitize --db-url "postgresql://user:pass@host:5432/db" --rules rules.json
```

**5. Restore anywhere:**

```bash
gunzip -c sanitized_db_*.sql.gz | psql "postgresql://localhost/dev_copy"
```

Want to try it without touching a real database? Load the demo: `psql $DATABASE_URL -f examples/demo_schema.sql`.

## 🧰 CLI reference

| Command | What it does |
|---|---|
| `sanitize` | Connect, anonymize and export a SQL dump |
| `sync FILE --bucket NAME` | Upload a dump to one S3-compatible bucket |
| `preview VALUE -s STRATEGY` | Show what a value becomes (no DB needed) |
| `strategies` | List all strategies with examples |
| `init` | Write a starter `rules.json` |
| `version` | Print version |

**`sanitize` options**

| Option | Default | Description |
|---|---|---|
| `--db-url` | `$DATABASE_URL` | PostgreSQL connection URL |
| `--rules, -r` | `rules.json` | Rules file |
| `--output, -o` | `sanitized_<db>_<time>.sql.gz` | Ends in `.gz` → gzip-compressed |
| `--salt` | `$ANON_SALT` | Secret salt for deterministic hashing |
| `--batch-size` | `1000` | Rows per fetch / INSERT |
| `--no-schema` | off | Data only, skip `pg_dump` DDL |
| `--dry-run` | off | Validate rules against the schema and exit |
| `--upload BUCKET` | — | Upload the result to an S3-compatible bucket |
| `--endpoint-url` | `$S3_ENDPOINT_URL` | Endpoint for R2 / Spaces / MinIO |

**Cloud upload** uses standard AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` or `~/.aws`):

```bash
# AWS S3
python main.py sanitize --db-url $DATABASE_URL --upload my-backups
# Cloudflare R2
python main.py sync dump.sql.gz -b my-backups --endpoint-url https://<ACCOUNT_ID>.r2.cloudflarestorage.com
# DigitalOcean Spaces
python main.py sync dump.sql.gz -b my-backups --endpoint-url https://fra1.digitaloceanspaces.com
```

## 🎭 Strategies

| Strategy | Example output | Notes |
|---|---|---|
| `email` | `kelly16.9a95ccd2@example.com` | Unique per input, safe for `UNIQUE` columns |
| `name` / `first_name` / `last_name` | `Maria Harmon` | Locale-aware (`"locale": "fr_FR"`, `"ar_AA"`, …) |
| `username` | `jsmith_1f0c2a` | Unique per input |
| `phone` | `+1-555-726-7654` | Uses the reserved 555 range |
| `credit_card` | `4756410247684656` | Luhn-valid test number |
| `iban`, `ssn` | `GB17NPNE05766470207453` | Format-valid |
| `address`, `city`, `postcode`, `company` | `832 Alice Loaf Suite 281` | |
| `ip` | `10.83.232.109` | Private ranges only |
| `url` | `https://example.com/9a95ccd2…` | |
| `text` | `Lorem-style sentence` | For free-text fields |
| `date_of_birth` | `1956-09-03` | Ages 18–90; works on `date` columns |
| `hash` | `b43539078cd8f5f170a0ad2e3aca2aa0` | Opaque, deterministic token |
| `redact` | `[REDACTED]` | |
| `null` | `NULL` | |
| `keep` | *(unchanged)* | Explicitly mark a column as safe |

## 🔐 Why deterministic anonymization?

Random fakes break your data: `orders.customer_email` no longer matches `users.email`, duplicates appear, unique indexes fail on restore.

Cloud-DB-Anonymizer computes `HMAC-SHA256(salt, strategy + value)` and uses it to seed the fake-data generator. That means:

- the **same real value always becomes the same fake value** — in every table and every run, so referential integrity and analytics still work;
- **without the salt, the mapping can't be reversed or reproduced** — rotate `ANON_SALT` to get a completely new data set;
- dumps are **reproducible**, which makes them diff-able and cache-friendly in CI.

> Anonymization is only as good as your rules. Review new columns when your schema changes, and use `--dry-run` in CI to catch rules that point at renamed columns. This tool helps with GDPR/CCPA data-minimization; it isn't legal advice.

## 🤖 DevOps auto-backup: nightly sanitized dumps with GitHub Actions

```yaml
# .github/workflows/sanitized-dump.yml
name: Nightly sanitized dump
on:
  schedule: [{ cron: "15 3 * * *" }]
  workflow_dispatch:
jobs:
  dump:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: sudo apt-get install -y postgresql-client && pip install -r requirements.txt
      - run: python main.py sanitize --rules rules.json --upload ${{ vars.BACKUP_BUCKET }}
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          ANON_SALT: ${{ secrets.ANON_SALT }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_REGION: us-east-1
```

Prefer a server that does this on its own, with a dashboard and alerts? 👇

## 🆚 Free CLI vs Pro Enterprise Suite

| | Free CLI (this repo) | **Pro Suite** |
|---|:---:|:---:|
| Deterministic PII anonymization (20 strategies) | ✅ | ✅ |
| Restorable, gzip SQL dumps | ✅ | ✅ |
| Upload to one S3-compatible bucket | ✅ | ✅ |
| **Parallel multi-cloud sync** (AWS S3 + Cloudflare R2 + DigitalOcean Spaces) | — | ✅ |
| **Built-in scheduler** (any cron) + retention pruning | — | ✅ |
| **Web dashboard** (Next.js + Tailwind): run, history, rules editor | — | ✅ |
| **Telegram & Discord** success/failure alerts | — | ✅ |
| **Docker Compose** deploy, no Python/Node on the server | — | ✅ |
| Client deployments | MIT | Agency License |

> [!IMPORTANT]
> ### 🚀 Need Multi-Cloud Sync, Docker Dashboard, and Telegram Webhooks?
> **[Get the Pro Enterprise Suite for $29 →](https://qhnfvf-jb.myshopify.com/products/cloud-db-anonymizer-pro-suite)**
>
> One-time payment. Self-hosted — your data never leaves your infrastructure. `docker compose up -d` and you're done. Agencies deploying for clients: see the [Agency License](https://qhnfvf-jb.myshopify.com/products/cloud-db-anonymizer-agency-license) ($79).

## ❓ FAQ

<details><summary><b>Does it modify my production database?</b></summary>
No. It opens a read-only transaction and only runs <code>SELECT</code>s. A read-only database user is enough.
</details>

<details><summary><b>How big a database can it handle?</b></summary>
Rows are streamed with server-side cursors and written in batches, so memory stays flat regardless of table size. Speed depends mostly on network latency to the database and how many columns are anonymized.
</details>

<details><summary><b>Which PostgreSQL versions are supported?</b></summary>
PostgreSQL 12 and newer. Use a <code>pg_dump</code> whose major version is the same as or newer than your server. Managed services (RDS, Aurora, Cloud SQL, Supabase, Neon, DigitalOcean, Heroku) work out of the box.
</details>

<details><summary><b>What about MySQL / MongoDB?</b></summary>
PostgreSQL only for now. Open an issue with your use case — it helps prioritize.
</details>

<details><summary><b>Can I use it to make test fixtures?</b></summary>
Yes. Combine <code>where</code> filters (e.g. last 30 days) with <code>skip_data</code> on huge log tables to produce small, realistic, shareable dev databases.
</details>

## 📚 Guides

- [How to anonymize a PostgreSQL database in GitHub Actions (CI rules check + nightly sanitized dump)](https://qhnfvf-jb.myshopify.com/blogs/developer-guides/anonymize-postgresql-github-actions-ci)
- [Open-source PostgreSQL data masking tools compared (2026): Greenmask vs PostgreSQL Anonymizer vs pganonymize vs Cloud-DB-Anonymizer](https://qhnfvf-jb.myshopify.com/blogs/developer-guides/postgresql-data-masking-tools-compared)
- [How to anonymize a PostgreSQL production database for staging (without breaking foreign keys)](https://qhnfvf-jb.myshopify.com/blogs/developer-guides/anonymize-postgresql-database-for-staging)
- [GDPR and test data: stop copying real customer data into dev and staging](https://qhnfvf-jb.myshopify.com/blogs/developer-guides/gdpr-test-data-postgresql)
- [Nightly sanitized PostgreSQL backups to AWS S3, Cloudflare R2 and DigitalOcean Spaces](https://qhnfvf-jb.myshopify.com/blogs/developer-guides/nightly-sanitized-postgresql-backups-s3-r2-spaces)

## 🧪 Development

```bash
pip install -r requirements-dev.txt
pytest -q
```

## 🤝 Contributing

Issues and pull requests are welcome — new strategies, docs and bug reports especially. If this saved you time, **⭐ star the repo** so other developers can find it.

## 📄 License

MIT © Cloud-DB-Anonymizer contributors. The Pro Suite is sold separately under a commercial license.

---

<sub>Keywords: PostgreSQL PII anonymizer, database sanitizer, Postgres data masking, anonymize production database, GDPR test data, pg_dump anonymize, fake data for staging, DevOps auto-backup, sanitized database backup, S3 backup PostgreSQL, data obfuscation CLI.</sub>
