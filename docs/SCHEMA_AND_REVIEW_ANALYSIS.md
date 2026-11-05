# Schema and Review Analysis

## Source material examined

- `PES2UG24CS448_PES2UG24CS447_G21.pdf` — Review‑1 report and evidence.
- `PES2UG24CS448_PES2UG24CS447_G21_with_placeholders.pdf` — Review‑2 report and evidence.
- `scamtracefinal.sql` — submitted MySQL dump.
- `ScamTrace_ERD_Chen(1).drawio(1).svg` — Chen ER diagram, copied to [ScamTrace_ERD_Chen.svg](ScamTrace_ERD_Chen.svg).

## Findings from the two PDFs

### Review‑1

- The screenshot on page 4 lists 20 tables.
- Pages 2–3 contain the Chen ER diagram and relational mapping.
- Page 5 shows the `user`, `scam_report`, `risk_analysis`, and `moderation_action` structures.
- Page 6 reports 22 foreign-key links with `NO ACTION` behavior.

### Review‑2

- Page 3 shows the 20-table starting schema. Page 7 then adds a `ddl_test` demonstration table, which makes the later screenshot show 21 tables. That scratch table is not part of the ERD and is excluded from the core schema.
- Page 6 records the later `user.last_login` column and a wider phone column. The SQL snapshot’s `last_login` is retained as a later implementation extension; the diagram’s original entity/relationship structure remains the guide.
- Page 8 records a failed attempt to add `chk_report_count` because that constraint name already exists on `scam_pattern`. The clean schema defines it once. It also defines `chk_risk_score` once on `scam_report`.
- Page 9 shows 22 foreign-key links and an index on report status. Its `EXPLAIN` output has no selected partition, so it does not demonstrate table partitioning.
- Later pages demonstrate views, DML, transactions, procedures, a function, and a trigger. Page 14’s broad update of all pending reports is not copied into the new project’s runnable query examples.

## Canonical 20-table design

The SQL dump contains 20 ERD tables plus `ddl_test`. The repository’s clean `sql/01_core_schema.sql` contains exactly the 20 ERD tables and their 22 foreign keys, without the dump’s sample rows, password hashes, `DROP TABLE` statements, or scratch table.

| ERD role | Tables | Relationship represented |
| --- | --- | --- |
| Identity and access | `role`, `user` | One role has many users; one user submits many reports and generates audit records. |
| Reports and classification | `scam_category`, `scam_pattern`, `scam_report` | A category classifies reports and patterns; patterns can be associated with many reports. |
| Analysis | `risk_analysis`, `risk_factor`, `analysis_risk_factor` | A report has analyses; each analysis can include many risk factors through the associative table. |
| Report support | `evidence`, `report_confirmation`, `moderation_action`, `audit_log` | Evidence, confirmations, and moderation actions attach to reports; confirmations and moderation actions also reference their users. Audit records reference users. |
| Indicator entities | `phone_number`, `email_address`, `url`, `upi_id` | Each indicator entity can be referenced by many reports. |
| Indicator associative tables | `report_phone`, `report_email`, `report_url`, `report_upi` | Four junction tables implement the report-to-indicator many-to-many relationships. |

The ERD’s second visual `USER` box is a repeated drawing of the same entity, used to reduce crossing lines. It does not represent a twenty-first table. The five associative tables are `analysis_risk_factor` and the four `report_*` indicator tables.

### Foreign-key inventory

The core schema keeps these 22 links from the SQL snapshot:

| Child table | Foreign-key links |
| --- | --- |
| `analysis_risk_factor` | `analysis_id → risk_analysis.analysis_id`; `factor_id → risk_factor.factor_id` |
| `audit_log` | `user_id → user.user_id` |
| `email_address` | none |
| `evidence` | `report_id → scam_report.report_id` |
| `moderation_action` | `report_id → scam_report.report_id`; `moderator_id → user.user_id` |
| `phone_number` | none |
| `report_confirmation` | `report_id → scam_report.report_id`; `user_id → user.user_id` |
| `report_email` | `report_id → scam_report.report_id`; `email_id → email_address.email_id` |
| `report_phone` | `report_id → scam_report.report_id`; `phone_id → phone_number.phone_id` |
| `report_upi` | `report_id → scam_report.report_id`; `upi_id → upi_id.upi_id` |
| `report_url` | `report_id → scam_report.report_id`; `url_id → url.url_id` |
| `risk_analysis` | `report_id → scam_report.report_id` |
| `role` | none |
| `scam_category` | none |
| `scam_pattern` | `category_id → scam_category.category_id` |
| `scam_report` | `user_id → user.user_id`; `category_id → scam_category.category_id`; `pattern_id → scam_pattern.pattern_id` |
| `upi_id` | none |
| `url` | none |
| `user` | `role_id → role.role_id` |
| `risk_factor` | none |

No new cascade behavior is added, so the supplied no-action relationships are preserved. The ORM represents all 20 tables and 22 foreign-key links.

## Partition design

The Review‑2 PDF contains no partitioned table. The optional partition exercise is implemented in `sql/07_partitioning_demo.sql` as a separate synthetic audit-log projection in `scamtrace_partition_lab`. The 20-table `scamtrace` schema and its foreign keys remain intact. The lab uses `DATETIME` range partitions and keeps the partition column in its primary key.

This separation follows MySQL’s current InnoDB limitation: partitioned InnoDB tables cannot have or be referenced by foreign keys. MySQL also requires each unique key, including the primary key, to include the partitioning column. See the [MySQL foreign-key restrictions](https://dev.mysql.com/doc/refman/8.4/en/create-table-foreign-keys.html) and [partitioning-key rules](https://dev.mysql.com/doc/refman/8.4/en/partitioning-limitations-partitioning-keys-unique-keys.html).

The lab’s `EXPLAIN PARTITIONS` query is intended to show partition pruning. The script has not yet been run against a MySQL 8 server, so its execution still needs to be verified locally.
