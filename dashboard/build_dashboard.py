"""Single source of truth for Grafana panels. Generates grafana_dashboard.json and grafana_queries.sql.
Run (optional, outputs are already included): python dashboard/build_dashboard.py"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DS = {"type": "grafana-postgresql-datasource", "uid": "${DS_POSTGRES}"}
LOGIN_TYPES = "event_type IN ('LOGIN','SSH_LOGIN')"

# (title, panel type, format, x, y, w, h, color/None, sql)
PANELS = [
    ("Total Logs", "stat", "table", 0, 0, 6, 4, "blue",
     "SELECT COUNT(*) AS total_logs FROM security_logs WHERE $__timeFilter(event_time);"),
    ("Failed Logins", "stat", "table", 6, 0, 6, 4, "orange",
     f"SELECT COUNT(*) AS failed_logins FROM security_logs WHERE $__timeFilter(event_time) AND {LOGIN_TYPES} AND status = 'FAILED';"),
    ("Threats Detected", "stat", "table", 12, 0, 6, 4, "purple",
     "SELECT COUNT(*) AS threats_detected FROM security_alerts WHERE $__timeFilter(alert_time);"),
    ("High Severity Alerts", "stat", "table", 18, 0, 6, 4, "red",
     "SELECT COUNT(*) AS high_severity_alerts FROM security_alerts WHERE $__timeFilter(alert_time) AND severity IN ('HIGH','CRITICAL');"),

    ("Logs Over Time (by event type)", "timeseries", "time_series", 0, 4, 12, 8, None,
     "SELECT $__timeGroupAlias(event_time,'1m'), event_type AS metric, COUNT(*) AS value\n"
     "FROM security_logs WHERE $__timeFilter(event_time)\nGROUP BY 1, 2 ORDER BY 1;"),
    ("Failed vs Successful Login Attempts", "timeseries", "time_series", 12, 4, 12, 8, None,
     "SELECT $__timeGroupAlias(event_time,'1m'),\n"
     "       COUNT(*) FILTER (WHERE status = 'FAILED')  AS failed,\n"
     "       COUNT(*) FILTER (WHERE status = 'SUCCESS') AS successful\n"
     f"FROM security_logs WHERE $__timeFilter(event_time) AND {LOGIN_TYPES}\nGROUP BY 1 ORDER BY 1;"),

    ("Threats by Type", "bargauge", "table", 0, 12, 8, 8, None,
     "SELECT threat_type, COUNT(*) AS alerts FROM security_alerts WHERE $__timeFilter(alert_time)\n"
     "GROUP BY threat_type ORDER BY alerts DESC;"),
    ("Threats by Severity", "piechart", "table", 8, 12, 8, 8, None,
     "SELECT severity, COUNT(*) AS alerts FROM security_alerts WHERE $__timeFilter(alert_time)\n"
     "GROUP BY severity ORDER BY alerts DESC;"),
    ("Top Suspicious IPs", "bargauge", "table", 16, 12, 8, 8, None,
     "SELECT ip_address, COUNT(*) AS alerts FROM security_alerts WHERE $__timeFilter(alert_time)\n"
     "GROUP BY ip_address ORDER BY alerts DESC LIMIT 10;"),

    ("HTTP Status Code Distribution", "piechart", "table", 0, 20, 8, 8, None,
     "SELECT response_code::text AS status_code, COUNT(*) AS requests FROM security_logs\n"
     "WHERE $__timeFilter(event_time) GROUP BY response_code ORDER BY response_code;"),
    ("Average Response Time (ms)", "timeseries", "time_series", 8, 20, 8, 8, None,
     "SELECT $__timeGroupAlias(event_time,'1m'), ROUND(AVG(response_time)::numeric, 2) AS avg_response_time_ms\n"
     "FROM security_logs WHERE $__timeFilter(event_time)\nGROUP BY 1 ORDER BY 1;"),
    ("Requests per Minute", "timeseries", "time_series", 16, 20, 8, 8, None,
     "SELECT $__timeGroupAlias(event_time,'1m'), COUNT(*) AS requests_per_minute\n"
     "FROM security_logs WHERE $__timeFilter(event_time)\nGROUP BY 1 ORDER BY 1;"),

    ("Latest Security Alerts", "table", "table", 0, 28, 24, 10, None,
     "SELECT alert_time, ip_address, threat_type, severity, description, event_count\n"
     "FROM security_alerts WHERE $__timeFilter(alert_time)\nORDER BY alert_time DESC LIMIT 50;"),
]


def build_panel(pid, title, kind, fmt, x, y, w, h, color, sql):
    panel = {
        "id": pid, "title": title, "type": kind, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [{"refId": "A", "datasource": DS, "format": fmt, "rawQuery": True,
                     "editorMode": "code", "rawSql": sql}],
        "fieldConfig": {"defaults": {}, "overrides": []},
        "options": {},
    }
    reduce_values = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True}}
    if kind == "stat":
        panel["options"] = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                            "colorMode": "background", "graphMode": "none", "textMode": "value"}
        panel["fieldConfig"]["defaults"] = {
            "color": {"mode": "thresholds"},
            "thresholds": {"mode": "absolute", "steps": [{"color": color, "value": None}]}}
    elif kind == "timeseries":
        panel["fieldConfig"]["defaults"] = {"custom": {"drawStyle": "line", "fillOpacity": 15, "lineWidth": 2}}
        panel["options"] = {"legend": {"displayMode": "list", "placement": "bottom"}}
    elif kind == "piechart":
        panel["options"] = {**reduce_values, "pieType": "donut", "displayLabels": ["name"],
                            "legend": {"displayMode": "table", "placement": "right", "values": ["value"]}}
    elif kind == "bargauge":
        panel["options"] = {**reduce_values, "orientation": "horizontal", "displayMode": "gradient"}
        panel["fieldConfig"]["defaults"] = {"color": {"mode": "continuous-GrYlRd"}}
    elif kind == "table":
        panel["options"] = {"showHeader": True}
    return panel


def main():
    panels = [build_panel(i + 1, *p) for i, p in enumerate(PANELS)]
    dashboard = {
        "__inputs": [{"name": "DS_POSTGRES", "label": "PostgreSQL", "description": "",
                      "type": "datasource", "pluginId": "grafana-postgresql-datasource",
                      "pluginName": "PostgreSQL"}],
        "title": "Cybersecurity Log Analytics", "uid": "cyber-log-analytics", "tags": ["security", "kafka", "spark"],
        "timezone": "browser", "schemaVersion": 39, "version": 1, "refresh": "5s",
        "time": {"from": "now-15m", "to": "now"}, "panels": panels,
    }
    (HERE / "grafana_dashboard.json").write_text(json.dumps(dashboard, indent=2), encoding="utf-8")

    lines = ["-- Grafana panel queries (PostgreSQL data source: cybersecurity_db)",
             "-- Grafana macros used: $__timeFilter(col), $__timeGroupAlias(col, interval)", ""]
    for title, *_rest, sql in PANELS:
        lines += [f"-- {title}", sql, ""]
    (HERE / "grafana_queries.sql").write_text("\n".join(lines), encoding="utf-8")
    print("Wrote grafana_dashboard.json and grafana_queries.sql")


if __name__ == "__main__":
    main()
