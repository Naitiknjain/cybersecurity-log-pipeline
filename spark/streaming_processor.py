"""Spark Structured Streaming job. Run from project root: python -m spark.streaming_processor"""
import os
import sys

# Make PySpark workers use this exact interpreter (important on Windows)
os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType, IntegerType, LongType, StringType, StructField, StructType

from config.config import (KAFKA_BOOTSTRAP_SERVERS, KAFKA_STARTING_OFFSETS, KAFKA_TOPIC,
                           SPARK_CHECKPOINT_DIR, SPARK_KAFKA_PACKAGE)
from spark.db_writer import write_logs_batch, write_stats_and_alerts_batch
from spark.threat_detection import build_ip_window_stats

# Must match generator/log_generator.py output
EVENT_SCHEMA = StructType([
    StructField("event_id", StringType()),
    StructField("timestamp", StringType()),
    StructField("ip_address", StringType()),
    StructField("username", StringType()),
    StructField("event_type", StringType()),
    StructField("action", StringType()),
    StructField("status", StringType()),
    StructField("endpoint", StringType()),
    StructField("http_method", StringType()),
    StructField("response_code", IntegerType()),
    StructField("response_time", DoubleType()),
    StructField("bytes_sent", LongType()),
])

TS_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS"
IPV4_REGEX = r"^(\d{1,3}\.){3}\d{1,3}$"
VALID_EVENT_TYPES = ["LOGIN", "LOGOUT", "API_REQUEST", "FILE_ACCESS", "PASSWORD_CHANGE",
                     "SSH_LOGIN", "DATABASE_ACCESS"]


def parse_and_clean(raw):
    """Kafka value bytes -> typed, validated events. Malformed JSON / invalid rows are dropped."""
    parsed = raw.select(F.from_json(F.col("value").cast("string"), EVENT_SCHEMA).alias("e")).select("e.*")
    df = (
        parsed
        .withColumn("event_time", F.to_timestamp("timestamp", TS_PATTERN))
        .withColumn("ip_address", F.trim("ip_address"))
        .withColumn("username", F.lower(F.trim("username")))
        .withColumn("event_type", F.upper(F.trim("event_type")))
        .withColumn("status", F.upper(F.trim("status")))
        .withColumn("http_method", F.upper(F.trim("http_method")))
        .withColumn("bytes_sent", F.coalesce(F.col("bytes_sent"), F.lit(0)).cast("long"))
    )
    valid = (
        F.col("event_id").isNotNull()
        & F.col("event_time").isNotNull()
        & F.col("ip_address").rlike(IPV4_REGEX)
        & F.col("event_type").isin(*VALID_EVENT_TYPES)
        & F.col("status").isin("SUCCESS", "FAILED")
        & F.col("response_code").between(100, 599)
        & (F.col("response_time") >= 0)
    )
    return df.filter(valid).select(
        "event_id", "event_time", "ip_address", "username", "event_type", "action", "status",
        "endpoint", "http_method", "response_code", "response_time", "bytes_sent")


def main():
    spark = (
        SparkSession.builder.master("local[*]").appName("CybersecurityLogPipeline")
        .config("spark.jars.packages", SPARK_KAFKA_PACKAGE)
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.ui.showConsoleProgress", "false")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    raw = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP_SERVERS)
        .option("subscribe", KAFKA_TOPIC)
        .option("startingOffsets", KAFKA_STARTING_OFFSETS)
        .option("failOnDataLoss", "false")
        .option("maxOffsetsPerTrigger", 5000)
        .load()
    )

    events = parse_and_clean(raw)
    ip_stats = build_ip_window_stats(events)

    ckpt = SPARK_CHECKPOINT_DIR.resolve()

    logs_query = (
        events.writeStream.queryName("logs_to_postgres")
        .outputMode("append")
        .foreachBatch(write_logs_batch)
        .option("checkpointLocation", (ckpt / "logs").as_uri())
        .trigger(processingTime="5 seconds")
        .start()
    )

    threats_query = (
        ip_stats.writeStream.queryName("threats_to_postgres")
        .outputMode("update")
        .foreachBatch(write_stats_and_alerts_batch)
        .option("checkpointLocation", (ckpt / "threats").as_uri())
        .trigger(processingTime="10 seconds")
        .start()
    )

    print(f"[INFO] Streaming from topic '{KAFKA_TOPIC}' -> PostgreSQL. Queries: "
          f"{logs_query.name}, {threats_query.name}. Ctrl+C to stop.")
    try:
        spark.streams.awaitAnyTermination()
    except KeyboardInterrupt:
        print("\n[INFO] Stopping streaming queries...")
        for q in spark.streams.active:
            q.stop()
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
