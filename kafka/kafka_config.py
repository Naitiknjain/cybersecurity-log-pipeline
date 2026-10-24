from config.config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC  # noqa: F401  (re-exported)

TOPIC_PARTITIONS = 3
TOPIC_REPLICATION = 1

PRODUCER_CONFIG = {
    "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
    "client.id": "security-log-producer",
    "acks": "all",
    "retries": 5,
    "linger.ms": 50,
}
