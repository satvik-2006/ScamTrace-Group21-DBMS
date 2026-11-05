#!/bin/bash
set -euo pipefail
# Use a URL-safe alphanumeric password in MYSQL_APP_PASSWORD.
mysql --protocol=socket -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS 'scamtrace_app'@'%' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON scamtrace.* TO 'scamtrace_app'@'%';
FLUSH PRIVILEGES;
SQL
