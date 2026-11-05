# ScamTrace second database: MongoDB evidence store

## Requirement mapping

ScamTrace uses **Option 1 (SQL + NoSQL)**. MySQL 8 is the mandatory relational system of record. MongoDB is the document database for unstructured report evidence. SQLite is retained only as a local test/demo fallback and does not count as the mandatory SQL submission database.

## Responsibility split

| Data | Database | Reason |
|---|---|---|
| Users, roles, categories, patterns | MySQL | Relational integrity and foreign keys |
| Scam reports, risk scores, moderation | MySQL | Transactions, constraints and auditability |
| Indicator entities and report junctions | MySQL | Unique identifiers and many-to-many relations |
| Evidence notes / free-text supporting material | MongoDB | Flexible document metadata and text retrieval |

SQL is authoritative for report lifecycle and visibility. MongoDB is a searchable evidence index/store; it does not decide whether a report is verified. The SQL `evidence` row is also retained for traceability and relational joins.

## MongoDB document model

Database: `scamtrace_evidence`

Collection: `evidence`

Example document:

```json
{
  "_id": "ObjectId(...) ",
  "report_id": 42,
  "evidence_type": "TEXT_NOTE",
  "content": "The sender demanded an upfront verification fee...",
  "metadata": { "submitted_by": 17 },
  "tags": ["text_note", "scamtrace"],
  "created_at": "2026-11-05T05:30:00Z"
}
```

`report_id` is the relational report identifier (application-level reference, not a Mongo foreign key). `content` holds unstructured text. `metadata` is extensible and can hold source, uploader, capture metadata or provenance. `tags` supports future filtering.

## Indexes and retrieval

- Text index: `content` and `tags` (`evidence_text_search`) supports MongoDB `$text` search.
- Compound index: `(report_id, created_at DESC)` (`evidence_report_lookup`) supports loading evidence for a report in chronological order.
- Retrieval: `GET /api/v1/evidence-search?q=<terms>` uses MongoDB `$text` and textScore ranking; it returns snippets and the related SQL report ID. Minimum query length is three characters.
- SQL indicator search remains a separate exact/substring lookup against verified reports only.

## Write path and consistency

When a report is submitted, the application writes the report, risk analysis, risk factors and SQL evidence note in one SQL transaction. After SQL commit, the evidence note is written to MongoDB. This is a deliberately simple dual-store pattern for the mini-project. SQL remains authoritative if MongoDB is offline; the health endpoint reports MongoDB status. For production, replace the best-effort second write with a transactional outbox/retry worker so evidence indexing is eventually consistent and recoverable.

## Run locally

```bash
docker compose up -d mongodb
cp .env.example .env
# Set DATABASE_URL to MySQL and set MONGODB_URI / MONGODB_DATABASE in .env
pip install -r requirements.txt
```

MongoDB is optional for the SQL-only test harness. It becomes an active second database when `MONGODB_URI` is configured and `pymongo` is installed. Check `/health` or the analytics API's `mongo` object for connection state.
