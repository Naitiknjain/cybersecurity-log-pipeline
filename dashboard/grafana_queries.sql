-- Grafana panel queries (PostgreSQL data source: cybersecurity_db)
-- Grafana macros used: $__timeFilter(col), $__timeGroupAlias(col, interval)

-- Total Logs
SELECT COUNT(*) AS total_logs FROM security_logs WHERE $__timeFilter(event_time);

-- Failed Logins
SELECT COUNT(*) AS failed_logins FROM security_logs WHERE $__timeFilter(event_time) AND event_type IN ('LOGIN','SSH_LOGIN') AND status = 'FAILED';

-- Threats Detected
SELECT COUNT(*) AS threats_detected FROM security_alerts WHERE $__timeFilter(alert_time);

-- High Severity Alerts
SELECT COUNT(*) AS high_severity_alerts FROM security_alerts WHERE $__timeFilter(alert_time) AND severity IN ('HIGH','CRITICAL');

-- Logs Over Time (by event type)
SELECT $__timeGroupAlias(event_time,'1m'), event_type AS metric, COUNT(*) AS value
FROM security_logs WHERE $__timeFilter(event_time)
GROUP BY 1, 2 ORDER BY 1;

-- Failed vs Successful Login Attempts
SELECT $__timeGroupAlias(event_time,'1m'),
       COUNT(*) FILTER (WHERE status = 'FAILED')  AS failed,
       COUNT(*) FILTER (WHERE status = 'SUCCESS') AS successful
FROM security_logs WHERE $__timeFilter(event_time) AND event_type IN ('LOGIN','SSH_LOGIN')
GROUP BY 1 ORDER BY 1;

-- Threats by Type
SELECT threat_type, COUNT(*) AS alerts FROM security_alerts WHERE $__timeFilter(alert_time)
GROUP BY threat_type ORDER BY alerts DESC;

-- Threats by Severity
SELECT severity, COUNT(*) AS alerts FROM security_alerts WHERE $__timeFilter(alert_time)
GROUP BY severity ORDER BY alerts DESC;

-- Top Suspicious IPs
SELECT ip_address, COUNT(*) AS alerts FROM security_alerts WHERE $__timeFilter(alert_time)
GROUP BY ip_address ORDER BY alerts DESC LIMIT 10;

-- HTTP Status Code Distribution
SELECT response_code::text AS status_code, COUNT(*) AS requests FROM security_logs
WHERE $__timeFilter(event_time) GROUP BY response_code ORDER BY response_code;

-- Average Response Time (ms)
SELECT $__timeGroupAlias(event_time,'1m'), ROUND(AVG(response_time)::numeric, 2) AS avg_response_time_ms
FROM security_logs WHERE $__timeFilter(event_time)
GROUP BY 1 ORDER BY 1;

-- Requests per Minute
SELECT $__timeGroupAlias(event_time,'1m'), COUNT(*) AS requests_per_minute
FROM security_logs WHERE $__timeFilter(event_time)
GROUP BY 1 ORDER BY 1;

-- Latest Security Alerts
SELECT alert_time, ip_address, threat_type, severity, description, event_count
FROM security_alerts WHERE $__timeFilter(alert_time)
ORDER BY alert_time DESC LIMIT 50;
