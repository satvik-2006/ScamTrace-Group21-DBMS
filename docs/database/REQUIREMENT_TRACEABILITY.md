# DBMS project requirement traceability

| Course requirement | ScamTrace implementation / evidence |
|---|---|
| Two database paradigms | MySQL 8 relational system of record + MongoDB evidence documents; `SECOND_DATABASE_MONGODB.md` |
| SQL ERD and relational schema | `docs/ScamTrace_ERD_Chen.svg`, `docs/SCHEMA_AND_REVIEW_ANALYSIS.md`, `app/models.py`, `sql/01_core_schema.sql` |
| DDL / keys / constraints / indexes | `sql/01_core_schema.sql`; `sql/02_routines_triggers.sql`; `sql/04_validation.sql`; isolated CREATE/ALTER/DROP lab in `sql/06_ddl_demonstration.sql` |
| Partitioning | `sql/07_partitioning_demo.sql` (isolated lab schema; not one of the 20 core tables; live MySQL execution still required) |
| DML and analytical queries | `sql/03_queries.sql` (SELECT, INSERT/UPDATE/DELETE examples, joins, grouping, HAVING, ordering, aggregates and subqueries) |
| Four advanced database concepts | Transactions, views, stored procedures/functions, triggers and indexes in the MySQL scripts |
| Vector search optional | Not implemented. MongoDB $text document search is implemented instead; it is lexical rather than embedding similarity search. |
| Next.js interface | `frontend/` (Next.js App Router) |
| Backend/API integration | FastAPI JSON endpoints under `/api/v1`; Next rewrites `/backend/*` to FastAPI |
| Environment-based credentials | `.env.example`; SQLAlchemy reads `DATABASE_URL`; Mongo reads `MONGODB_URI` |
| Authentication / 2+ roles | USER, MODERATOR, ADMIN; signed HttpOnly session cookie and PBKDF2 password hashes |
| Validation / integrity | API and server validation plus SQL constraints, FKs and triggers |
| Security | Parameterized ORM queries, CSRF header checks, role checks, password hashing, HttpOnly cookie, no credentials in frontend bundle |
| Project report and evidence | `docs/ScamTrace_DBMS_Project_Report.docx` (guide/course fields intentionally blank; screenshots are labeled by their actual SQLite/Jinja source) |

## Important deployment note

The repository includes both a legacy Jinja2 demo UI and the Next.js UI. Run the Next frontend on port 3000 and FastAPI on port 8000. MySQL is the intended relational deployment; SQLite is the local test/demo fallback. MongoDB must be configured to demonstrate the second paradigm. Do not claim that a MySQL routine/trigger, partition, or MongoDB connection was live-tested unless it has been executed against the relevant service.

## DDL demonstration

`sql/06_ddl_demonstration.sql` creates ddl_demo_note in a separate scamtrace_ddl_lab database, demonstrates ALTER on that lab table, and creates then drops ddl_drop_demo in the same lab. It does not drop or alter an application-schema object.
