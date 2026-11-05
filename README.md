# ScamTrace — Scam Detection and Pattern Analysis

ScamTrace is a DBMS mini project for submitting scam reports, reviewing them, analyzing risk, and searching linked indicators. Its relational design follows the supplied Chen ER diagram and Review‑1 schema: **20 core tables and 22 foreign keys**. The 20 tables comprise 15 entity tables and five associative tables for the many-to-many relationships.

## Stack

- **Backend:** FastAPI, SQLAlchemy, Jinja2; JSON API and a server-rendered UI.
- **Frontend:** Next.js App Router and React.
- **Primary database:** MySQL 8.0 or later. The local test/demo fallback uses SQLite.
- **Optional second database:** MongoDB for unstructured evidence notes and text search.

## Run the local demo

From the repository root in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SCAMTRACE_SEED_DEMO="1"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The local demo creates an ignored SQLite file named `scamtrace_demo.db` and synthetic sample records. Do not point demo seeding at a real database. To run without sample records, set `SCAMTRACE_SEED_DEMO=0`.

The API health check is `/health`; the interactive API documentation is `/api/docs`.

## MySQL setup

Create a **new or empty** database, then use a MySQL CLI session:

```sql
CREATE DATABASE IF NOT EXISTS scamtrace CHARACTER SET utf8mb4;
USE scamtrace;
SOURCE C:/path/to/ScamTrace-Group21-DBMS/sql/01_core_schema.sql;
SOURCE C:/path/to/ScamTrace-Group21-DBMS/sql/08_reference_data.sql;
SOURCE C:/path/to/ScamTrace-Group21-DBMS/sql/02_routines_triggers.sql;
SOURCE C:/path/to/ScamTrace-Group21-DBMS/sql/04_validation.sql;
SOURCE C:/path/to/ScamTrace-Group21-DBMS/sql/05_review1_consistency.sql;
```

`01_core_schema.sql` is DDL-only: it creates the 20 core tables without dropping existing tables or including the `ddl_test` scratch table. `08_reference_data.sql` adds only synthetic role, category, pattern, and risk-factor lookups; it contains no users, password hashes, reports, or real indicators. The routine script replaces named procedures, functions, triggers, and a view; it also reconciles pattern report counts. Back up an existing database before applying schema or routine setup to a database that contains data you need to preserve.

Set these values in a private `.env` file or the process environment before using MySQL:

```text
DATABASE_URL=mysql+pymysql://scamtrace_app:URL_ENCODED_PASSWORD@127.0.0.1:3306/scamtrace
SCAMTRACE_SECRET_KEY=<random secret of at least 32 characters>
SCAMTRACE_SEED_DEMO=0
COOKIE_SECURE=0   # local HTTP only; use 1 behind HTTPS
```

Before signing in to a fresh MySQL database, create your own administrator. The command prompts for a password without echoing it:

```powershell
python -m app.bootstrap_admin --email admin@example.invalid
```

Replace the example address with the email you want to use.

For the Docker services, copy `.env.example` to `.env`, replace every placeholder with unique local secrets, then run `docker compose up -d mysql mongodb`. Docker initializes MySQL only on its first start with an empty data volume. Docker and the MySQL initialization scripts are optional for the SQLite demo.

## Next.js interface

FastAPI must be running first. In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). `frontend/.env.local.example` documents the server-side `BACKEND_URL` override when the API is not at `http://127.0.0.1:8000`. The current package pins Next.js 14.2.31 and React 18.3.1; keep this interface bound to localhost until Next.js is updated to a supported, patched release.

## Partitioning exercise

MySQL InnoDB does not allow user-partitioned tables to participate in foreign-key relationships. The core ERD therefore keeps all 22 foreign keys. `sql/07_partitioning_demo.sql` creates an isolated `scamtrace_partition_lab` database with a partitioned audit-log-shaped table and synthetic sample rows. It does not alter or copy data from `scamtrace`. Run it once in MySQL 8.0+ and inspect the `EXPLAIN PARTITIONS` result for pruning.

The partitioned table uses `DATETIME` with `RANGE COLUMNS`; its primary key includes the partition column, as MySQL requires for unique keys on partitioned tables. The separate `sql/06_ddl_demonstration.sql` is also an isolated optional DDL lab.

## Schema and review findings

See [docs/SCHEMA_AND_REVIEW_ANALYSIS.md](docs/SCHEMA_AND_REVIEW_ANALYSIS.md) for the table-by-table ERD mapping and comparison of both submitted PDFs. The ERD draws `USER` twice to reduce crossing lines; both boxes refer to the same `user` table. The later SQL snapshot adds `user.last_login`, retained as an implementation extension. The Review‑2 `ddl_test` table and attempted duplicate `chk_report_count` constraint are excluded; the canonical schema contains one `chk_report_count` and one `chk_risk_score` constraint.

## Verification

Run the Python checks with:

```powershell
python -m pytest -q
```

The tests exercise the SQLite demo app and statically check the 20 table names, 22 foreign keys, and ORM mapping. They do not claim to execute MySQL routines, triggers, or partitioning. MySQL execution needs a local MySQL 8 server (or Docker); Next.js should be upgraded before deployment.

## Configuration and safety

- Never commit `.env`, live database files, or real imported records. `.gitignore` excludes them.
- Use a least-privilege MySQL application account; run schema setup separately with a database administrator.
- Set a fresh `SCAMTRACE_SECRET_KEY` and use HTTPS with secure cookies outside local development.
- The included sample data is synthetic. Do not use seeded demo accounts in a deployed environment.
