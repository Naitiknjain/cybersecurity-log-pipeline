"""Central configuration. All values come from environment variables / .env."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

# Kafka
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security_logs")
KAFKA_STARTING_OFFSETS = os.getenv("KAFKA_STARTING_OFFSETS", "latest")

# PostgreSQL
PG_HOST = os.getenv("PG_HOST", "localhost")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB = os.getenv("PG_DB", "cybersecurity_db")
PG_USER = os.getenv("PG_USER", "postgres")
PG_PASSWORD = os.getenv("PG_PASSWORD", "")

# Generator
EVENTS_PER_SECOND = int(os.getenv("EVENTS_PER_SECOND", "10"))

# Spark
_ckpt = Path(os.getenv("SPARK_CHECKPOINT_DIR", "checkpoints"))
SPARK_CHECKPOINT_DIR = _ckpt if _ckpt.is_absolute() else ROOT_DIR / _ckpt
SPARK_KAFKA_PACKAGE = os.getenv(
    "SPARK_KAFKA_PACKAGE", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1"
)
