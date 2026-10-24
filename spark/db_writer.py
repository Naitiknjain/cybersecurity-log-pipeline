"""foreachBatch writers: Spark micro-batch -> PostgreSQL (idempotent upserts via ON CONFLICT)."""
import time

import psycopg2
from psycopg2.extras import execute_values
from pyspark.sql import functions as F

from config.config import PG_DB, PG_HOST, PG_PASSWORD, PG_PORT, PG_USER
from spark.threat_detection import stats_to_alerts

TS_FMT = "yyyy-MM-dd HH:mm:ss.SSS"   # Spark session timezone is UTC; PG connection is forced to UTC
MAX_RETRIES = 3

LOG_COLS = ["event_id", "event_time", "ip_address", "username", "event_type", "action", "status",
            "endpoint", "http_method", "response_code", "response_time", "bytes_sent"]
STATS_COLS = ["window_start", "window_end", "ip_address", "total_requests", "failed_logins",
              "error_responses", "privileged_events", "avg_response_time", "max_response_time", "total_bytes"]
ALERT_COLS = ["alert_time", "window_start", "ip_address", "threat_type", "severity", "description", "event_count"]

LOG_SQL = f"INSERT INTO security_logs ({', '.join(LOG_COLS)}) VALUES %s ON CONFLICT (event_id) DO NOTHING"

STATS_SQL = (
    f"INSERT INTO ip_window_stats ({', '.join(STATS_COLS)}) VALUES %s "
    "ON CONFLICT (window_start, ip_address) DO UPDATE SET "
    "window_end=EXCLUDED.window_end, total_requests=EXCLUDED.total_requests, "
    "failed_logins=EXCLUDED.failed_logins, error_responses=EXCLUDED.error_responses, "
    "privileged_events=EXCLUDED.privileged_events, avg_response_time=EXCLUDED.avg_response_time, "
    "max_response_time=EXCLUDED.max_response_time, total_bytes=EXCLUDED.total_bytes"
)

ALERT_SQL = (
    f"INSERT INTO security_alerts ({', '.join(ALERT_COLS)}) VALUES %s "
    "ON CONFLICT (window_start, ip_address, threat_type) DO UPDATE SET "
    "alert_time=EXCLUDED.alert_time, severity=EXCLUDED.severity, "
    "description=EXCLUDED.description, event_count=EXCLUDED.event_count"
)


def get_conn():
    return psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER,
                            password=PG_PASSWORD, connect_timeout=10, options="-c timezone=UTC")


def _write(sql, rows, label, batch_id):
    """Single transaction per call, retried; raises after MAX_RETRIES so Spark replays the batch (no data loss)."""
    if not rows:
        return
    for attempt in range(1, MAX_RETRIES + 1):
        conn = None
        try:
            conn = get_conn()
            with conn:
                with conn.cursor() as cur:
                    execute_values(cur, sql, rows, page_size=500)
            print(f"[batch {batch_id}] {label}: wrote {len(rows)} rows")
            return
        except psycopg2.Error as exc:
            print(f"[batch {batch_id}] {label}: attempt {attempt}/{MAX_RETRIES} failed: {exc}")
            time.sleep(2 * attempt)
        finally:
            if conn is not None:
                conn.close()
    raise RuntimeError(f"[batch {batch_id}] {label}: PostgreSQL write failed after {MAX_RETRIES} attempts")


def _ts(col):
    return F.date_format(col, TS_FMT).alias(col)


def write_logs_batch(batch_df, batch_id):
    df = batch_df.select(
        "event_id", _ts("event_time"), "ip_address", "username", "event_type", "action", "status",
        "endpoint", "http_method", "response_code", "response_time", "bytes_sent")
    _write(LOG_SQL, [tuple(r) for r in df.collect()], "security_logs", batch_id)


def write_stats_and_alerts_batch(batch_df, batch_id):
    stats_rows = batch_df.select(
        _ts("window_start"), _ts("window_end"), "ip_address", "total_requests", "failed_logins",
        "error_responses", "privileged_events", "avg_response_time", "max_response_time", "total_bytes")
    _write(STATS_SQL, [tuple(r) for r in stats_rows.collect()], "ip_window_stats", batch_id)

    alerts = stats_to_alerts(batch_df).select(
        _ts("alert_time"), _ts("window_start"), "ip_address", "threat_type", "severity",
        "description", "event_count")
    _write(ALERT_SQL, [tuple(r) for r in alerts.collect()], "security_alerts", batch_id)
