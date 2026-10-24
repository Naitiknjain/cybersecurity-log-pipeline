"""Continuously generates security events and publishes them to Kafka. Run: python -m kafka.producer"""
import json
import sys
import time

from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient, NewTopic

from config.config import EVENTS_PER_SECOND
from generator.log_generator import generate_batch
from kafka.kafka_config import (KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, PRODUCER_CONFIG,
                                         TOPIC_PARTITIONS, TOPIC_REPLICATION)

stats = {"sent": 0, "failed": 0}


def on_delivery(err, msg):
    if err is not None:
        stats["failed"] += 1
        print(f"[ERROR] delivery failed: {err}", file=sys.stderr)
    else:
        stats["sent"] += 1


def ensure_topic():
    """Returns True when Kafka is reachable and the topic exists (creates it if needed)."""
    admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})
    try:
        metadata = admin.list_topics(timeout=10)
    except Exception as exc:
        print(f"[WARN] Kafka not reachable at {KAFKA_BOOTSTRAP_SERVERS}: {exc}")
        return False
    if KAFKA_TOPIC in metadata.topics:
        return True
    futures = admin.create_topics([NewTopic(KAFKA_TOPIC, num_partitions=TOPIC_PARTITIONS,
                                            replication_factor=TOPIC_REPLICATION)])
    for _, future in futures.items():
        try:
            future.result()
            print(f"[INFO] Created topic '{KAFKA_TOPIC}'")
        except Exception as exc:
            print(f"[WARN] Topic creation: {exc}")
    return True


def main():
    while not ensure_topic():
        print("[INFO] Retrying in 5 seconds (is Kafka running?)")
        time.sleep(5)

    producer = Producer(PRODUCER_CONFIG)
    print(f"[INFO] Producing ~{EVENTS_PER_SECOND}+ events/sec to '{KAFKA_TOPIC}' on {KAFKA_BOOTSTRAP_SERVERS}. Ctrl+C to stop.")
    last_report = time.time()
    try:
        while True:
            tick = time.time()
            for event in generate_batch(EVENTS_PER_SECOND):
                payload = json.dumps(event)
                try:
                    producer.produce(KAFKA_TOPIC, key=event["ip_address"], value=payload, callback=on_delivery)
                except BufferError:
                    producer.poll(1)
                    producer.produce(KAFKA_TOPIC, key=event["ip_address"], value=payload, callback=on_delivery)
                except Exception as exc:
                    stats["failed"] += 1
                    print(f"[ERROR] produce failed: {exc}", file=sys.stderr)
            producer.poll(0)
            if time.time() - last_report >= 5:
                print(f"[INFO] sent={stats['sent']} failed={stats['failed']}")
                last_report = time.time()
            time.sleep(max(0.0, 1.0 - (time.time() - tick)))
    except KeyboardInterrupt:
        print("\n[INFO] Stopping producer...")
    finally:
        producer.flush(10)
        print(f"[INFO] Final: sent={stats['sent']} failed={stats['failed']}")


if __name__ == "__main__":
    main()
