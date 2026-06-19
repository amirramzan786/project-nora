"""
Project N.O.R.A.
Phase 3 Validation Log Generator
Dataset 08 - Burst Attack

This generator creates Apache-style access logs that simulate a short, high-intensity
burst attack. The dataset contains normal baseline traffic, a concentrated burst
window, and a recovery period to test N.O.R.A's burst detection, anomaly scoring,
alert generation, and source attribution behaviour.
"""

from datetime import datetime, timedelta
import os
import random


OUTPUT_FILE = "logs/phase3_validation_burst_attack.log"
START_TIME = datetime(2026, 6, 17, 16, 0, 0)
DURATION_MINUTES = 60

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.15",
    "10.0.0.21",
    "10.0.0.22",
]

BURST_ATTACK_IPS = [
    "45.155.205.233",
    "185.220.101.42",
    "91.240.118.172",
    "103.21.244.18",
    "203.0.113.77",
]

NORMAL_PATHS = [
    "/",
    "/products",
    "/login",
    "/api/status",
    "/checkout",
    "/help",
]

BURST_ATTACK_PATHS = [
    "/login",
    "/login",
    "/wp-login.php",
    "/admin",
    "/checkout",
    "/api/status",
]


def apache_log_line(ip, timestamp, method, path, status, size):
    """Build one Apache-style access log line."""
    return (
        f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"{method} {path} HTTP/1.1" {status} {size}'
    )


def generate_burst_attack_log():
    """Generate a burst attack validation dataset."""
    lines = []

    for minute in range(DURATION_MINUTES):
        timestamp = START_TIME + timedelta(minutes=minute)

        # Normal baseline traffic throughout the session.
        normal_request_count = random.randint(4, 10)

        for _ in range(normal_request_count):
            ip = random.choice(NORMAL_IPS)
            path = random.choice(NORMAL_PATHS)
            status = random.choice([200, 200, 200, 200, 304])
            second_offset = random.randint(0, 59)

            lines.append(
                apache_log_line(
                    ip=ip,
                    timestamp=timestamp + timedelta(seconds=second_offset),
                    method="GET",
                    path=path,
                    status=status,
                    size=random.randint(800, 3600),
                )
            )

        # Burst window: short, intense, and clearly above baseline.
        if 24 <= minute <= 31:
            burst_request_count = random.randint(150, 230)
        elif 32 <= minute <= 36:
            burst_request_count = random.randint(70, 120)
        else:
            burst_request_count = 0

        for _ in range(burst_request_count):
            ip = random.choice(BURST_ATTACK_IPS)
            path = random.choice(BURST_ATTACK_PATHS)
            status = random.choice([200, 200, 401, 403, 429, 503])
            second_offset = random.randint(0, 59)

            lines.append(
                apache_log_line(
                    ip=ip,
                    timestamp=timestamp + timedelta(seconds=second_offset),
                    method=random.choice(["GET", "GET", "POST"]),
                    path=path,
                    status=status,
                    size=random.randint(500, 2600),
                )
            )

    lines.sort()

    output_directory = os.path.dirname(OUTPUT_FILE)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as log_file:
        log_file.write("\n".join(lines))

    print(f"Created {OUTPUT_FILE}")
    print(f"Total lines: {len(lines)}")
    print("Dataset type: Burst attack")
    print(f"Burst sources: {len(BURST_ATTACK_IPS)}")
    print("Burst window: 16:24 to 16:36")


if __name__ == "__main__":
    generate_burst_attack_log()