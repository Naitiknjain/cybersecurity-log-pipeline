"""Creates cybersecurity_db (if missing) and applies schema.sql.  Run: python -m database.init_db"""
from pathlib import Path

import psycopg2
from psycopg2 import sql

from config.config import PG_DB, PG_HOST, PG_PASSWORD, PG_PORT, PG_USER

SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"


def main():
    admin = psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname="postgres",
                             user=PG_USER, password=PG_PASSWORD, connect_timeout=10)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (PG_DB,))
        if cur.fetchone() is None:
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(PG_DB)))
            print(f"Created database {PG_DB}")
        else:
            print(f"Database {PG_DB} already exists")
    admin.close()

    conn = psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB,
                            user=PG_USER, password=PG_PASSWORD, connect_timeout=10)
    with conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_FILE.read_text(encoding="utf-8"))
    conn.close()
    print("Schema applied: security_logs, security_alerts, ip_window_stats")


if __name__ == "__main__":
    main()
