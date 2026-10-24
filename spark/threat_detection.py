"""Windowed per-IP aggregation (streaming) and rule-based threat detection (applied per micro-batch)."""
from pyspark.sql import DataFrame
from pyspark.sql import functions as F

WINDOW_DURATION = "1 minute"
WATERMARK_DELAY = "2 minutes"

# Rule thresholds (per IP, per 1-minute window)
BRUTE_FORCE_THRESHOLD = 5        # failed LOGIN / SSH_LOGIN attempts
HIGH_VOLUME_THRESHOLD = 60       # requests
ERROR_SPIKE_THRESHOLD = 15       # 4xx/5xx responses
PRIVILEGED_THRESHOLD = 5         # admin/root user or sensitive endpoint events
SLOW_AVG_MS = 2000               # average response time (ms)
SLOW_MIN_EVENTS = 3

SENSITIVE_ENDPOINT_REGEX = r"^/(admin|api/admin|etc/passwd|\.env)"


def build_ip_window_stats(events: DataFrame) -> DataFrame:
    """Streaming aggregation: one row per (1-minute window, ip_address)."""
    failed_login = (F.col("event_type").isin("LOGIN", "SSH_LOGIN") & (F.col("status") == "FAILED")).cast("int")
    error_resp = (F.col("response_code") >= 400).cast("int")
    privileged = (F.col("username").isin("admin", "root")
                  | F.col("endpoint").rlike(SENSITIVE_ENDPOINT_REGEX)).cast("int")

    return (
        events.withWatermark("event_time", WATERMARK_DELAY)
        .groupBy(F.window("event_time", WINDOW_DURATION).alias("w"), "ip_address")
        .agg(
            F.count("*").alias("total_requests"),
            F.sum(failed_login).alias("failed_logins"),
            F.sum(error_resp).alias("error_responses"),
            F.sum(privileged).alias("privileged_events"),
            F.round(F.avg("response_time"), 2).alias("avg_response_time"),
            F.round(F.max("response_time"), 2).alias("max_response_time"),
            F.sum("bytes_sent").alias("total_bytes"),
        )
        .select(
            F.col("w.start").alias("window_start"),
            F.col("w.end").alias("window_end"),
            "ip_address", "total_requests", "failed_logins", "error_responses",
            "privileged_events", "avg_response_time", "max_response_time", "total_bytes",
        )
    )


def _alert(df, condition, threat_type, severity, description, count_col):
    return df.filter(condition).select(
        F.current_timestamp().alias("alert_time"),
        "window_start",
        "ip_address",
        F.lit(threat_type).alias("threat_type"),
        severity.alias("severity"),
        description.alias("description"),
        F.col(count_col).cast("int").alias("event_count"),
    )


def stats_to_alerts(stats: DataFrame) -> DataFrame:
    """Batch (non-streaming) DataFrame of window stats -> alerts DataFrame."""
    ip = F.col("ip_address")

    brute = _alert(
        stats, F.col("failed_logins") >= BRUTE_FORCE_THRESHOLD, "BRUTE_FORCE_LOGIN",
        F.when(F.col("failed_logins") >= 10, "CRITICAL").otherwise("HIGH"),
        F.format_string("Brute force suspected: %d failed login attempts from %s within 1 minute",
                        F.col("failed_logins"), ip),
        "failed_logins")

    volume = _alert(
        stats, F.col("total_requests") >= HIGH_VOLUME_THRESHOLD, "SUSPICIOUS_IP_ACTIVITY",
        F.when(F.col("total_requests") >= 100, "HIGH").otherwise("MEDIUM"),
        F.format_string("Unusually high request volume: %d requests from %s within 1 minute",
                        F.col("total_requests"), ip),
        "total_requests")

    errors = _alert(
        stats, F.col("error_responses") >= ERROR_SPIKE_THRESHOLD, "SERVER_ERROR_SPIKE",
        F.when(F.col("error_responses") >= 30, "HIGH").otherwise("MEDIUM"),
        F.format_string("High 4xx/5xx error count: %d error responses for %s within 1 minute",
                        F.col("error_responses"), ip),
        "error_responses")

    privileged = _alert(
        stats, F.col("privileged_events") >= PRIVILEGED_THRESHOLD, "PRIVILEGE_ADMIN_ACTIVITY",
        F.when(F.col("privileged_events") >= 8, "CRITICAL").otherwise("HIGH"),
        F.format_string("Repeated admin/root or sensitive endpoint access: %d events from %s within 1 minute",
                        F.col("privileged_events"), ip),
        "privileged_events")

    slow = _alert(
        stats,
        (F.col("avg_response_time") >= SLOW_AVG_MS) & (F.col("total_requests") >= SLOW_MIN_EVENTS),
        "ABNORMAL_RESPONSE_TIME",
        F.when(F.col("avg_response_time") >= 5000, "HIGH")
         .when(F.col("avg_response_time") >= 3500, "MEDIUM").otherwise("LOW"),
        F.format_string("Abnormal response time: avg %.0f ms (max %.0f ms) over %d requests from %s",
                        F.col("avg_response_time"), F.col("max_response_time"), F.col("total_requests"), ip),
        "total_requests")

    return brute.unionByName(volume).unionByName(errors).unionByName(privileged).unionByName(slow)
