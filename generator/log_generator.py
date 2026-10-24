"""Generates realistic normal + suspicious security events (dicts, JSON-serialisable)."""
import random
import uuid
from datetime import datetime, timezone

NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 40)] + [f"10.0.0.{i}" for i in range(5, 15)]
ATTACKER_IPS = ["185.220.101.34", "45.155.205.233", "103.77.192.18", "91.240.118.172",
                "198.51.100.77", "203.0.113.45", "77.247.181.163", "141.98.10.60"]
NORMAL_USERS = ["alice", "bob", "charlie", "diana", "eve", "frank", "grace", "henry", "irene", "jack"]
ADMIN_USERS = ["admin", "root"]
API_ENDPOINTS = ["/api/users", "/api/orders", "/api/products", "/api/search",
                 "/api/cart", "/api/profile", "/api/payments"]
FILE_ENDPOINTS = ["/files/report.pdf", "/files/invoice.xlsx", "/files/docs/readme.txt", "/files/backup.zip"]
SENSITIVE_ENDPOINTS = ["/admin", "/admin/config", "/api/admin/users", "/etc/passwd",
                       "/.env", "/api/admin/export"]
EVENT_TYPES = ["API_REQUEST", "LOGIN", "LOGOUT", "FILE_ACCESS", "PASSWORD_CHANGE",
               "SSH_LOGIN", "DATABASE_ACCESS"]


def _now():
    # UTC, millisecond precision, no zone suffix -> matches Spark pattern yyyy-MM-dd'T'HH:mm:ss.SSS
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "")


def make_event(ip, username, event_type, action, status, endpoint, method, code, rt, nbytes):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _now(),
        "ip_address": ip,
        "username": username,
        "event_type": event_type,
        "action": action,
        "status": status,
        "endpoint": endpoint,
        "http_method": method,
        "response_code": code,
        "response_time": round(rt, 2),
        "bytes_sent": nbytes,
    }


def normal_event():
    ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)
    etype = random.choices(EVENT_TYPES, weights=[50, 12, 10, 12, 2, 4, 10])[0]
    rt = random.uniform(20, 400) if random.random() > 0.03 else random.uniform(500, 1500)
    nbytes = random.randint(200, 50_000)

    if etype == "API_REQUEST":
        endpoint, method, action = random.choice(API_ENDPOINTS), random.choice(["GET", "GET", "GET", "POST", "PUT", "DELETE"]), "api_call"
    elif etype == "LOGIN":
        endpoint, method, action = "/api/login", "POST", "login"
    elif etype == "LOGOUT":
        endpoint, method, action = "/api/logout", "POST", "logout"
    elif etype == "FILE_ACCESS":
        endpoint, method, action, nbytes = random.choice(FILE_ENDPOINTS), "GET", "file_read", random.randint(10_000, 5_000_000)
    elif etype == "PASSWORD_CHANGE":
        endpoint, method, action = "/api/password/change", "PUT", "password_change"
    elif etype == "SSH_LOGIN":
        endpoint, method, action = "/ssh", "SSH", "ssh_auth"
    else:
        endpoint, method, action = "/db/query", "POST", "db_query"

    status, code = "SUCCESS", random.choices([200, 201, 204, 304], weights=[80, 8, 6, 6])[0]
    if etype in ("LOGIN", "SSH_LOGIN") and random.random() < 0.05:
        status, code = "FAILED", 401
    elif random.random() < 0.04:
        status, code = "FAILED", random.choice([400, 403, 404, 500, 502, 503])

    event = make_event(ip, user, etype, action, status, endpoint, method, code, rt, nbytes)
    if random.random() < 0.01:  # ~1% malformed records to demonstrate validation in Spark
        event["ip_address"] = "invalid_ip"
        event["response_code"] = 999
    return event


# ---------------------------------------------------------------- attack scenarios
def brute_force():
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(NORMAL_USERS + ["guest", "test"])
    ssh = random.random() < 0.4
    return [make_event(ip, user, "SSH_LOGIN" if ssh else "LOGIN", "ssh_auth" if ssh else "login",
                       "FAILED", "/ssh" if ssh else "/api/login", "SSH" if ssh else "POST",
                       401, random.uniform(50, 300), random.randint(150, 400))
            for _ in range(random.randint(6, 12))]


def high_volume():
    ip = random.choice(ATTACKER_IPS)
    return [make_event(ip, "anonymous", "API_REQUEST", "api_call", "SUCCESS",
                       random.choice(API_ENDPOINTS), "GET", 200,
                       random.uniform(10, 120), random.randint(200, 3000))
            for _ in range(random.randint(70, 110))]


def error_spike():
    ip = random.choice(ATTACKER_IPS)
    paths = API_ENDPOINTS + ["/wp-login.php", "/phpmyadmin", "/backup.sql", "/server-status"]
    return [make_event(ip, "anonymous", "API_REQUEST", "api_call", "FAILED",
                       random.choice(paths), "GET", random.choice([404, 404, 403, 500, 502, 503]),
                       random.uniform(10, 200), random.randint(100, 800))
            for _ in range(random.randint(16, 30))]


def admin_abuse():
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(ADMIN_USERS)
    events = []
    for _ in range(random.randint(6, 10)):
        etype = random.choice(["FILE_ACCESS", "DATABASE_ACCESS", "PASSWORD_CHANGE", "API_REQUEST"])
        ok = random.random() < 0.6
        events.append(make_event(ip, user, etype, "privileged_access", "SUCCESS" if ok else "FAILED",
                                 random.choice(SENSITIVE_ENDPOINTS), random.choice(["GET", "POST"]),
                                 200 if ok else 403, random.uniform(30, 500), random.randint(500, 100_000)))
    return events


def slow_response():
    ip = random.choice(NORMAL_IPS + ATTACKER_IPS)
    return [make_event(ip, random.choice(NORMAL_USERS), random.choice(["API_REQUEST", "DATABASE_ACCESS"]),
                       "slow_operation", "SUCCESS", random.choice(["/api/search", "/db/query", "/api/orders"]),
                       "POST", 200, random.uniform(2500, 9000), random.randint(1000, 20_000))
            for _ in range(random.randint(4, 8))]


# (scenario function, probability per one-second tick)
SCENARIOS = [(brute_force, 0.06), (high_volume, 0.03), (error_spike, 0.04),
             (admin_abuse, 0.05), (slow_response, 0.04)]


def generate_batch(events_per_second=10):
    """One second worth of traffic: normal events + occasional attack bursts."""
    batch = [normal_event() for _ in range(events_per_second)]
    for scenario, prob in SCENARIOS:
        if random.random() < prob:
            batch.extend(scenario())
    random.shuffle(batch)
    return batch


if __name__ == "__main__":
    import json
    for ev in generate_batch(5)[:5]:
        print(json.dumps(ev))
