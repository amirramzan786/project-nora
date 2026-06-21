"""
Project N.O.R.A.
Phase 3 Validation Log Generator
Dataset 09 - Sustained Distributed Attack

This generator creates Apache-style access logs that simulate a sustained distributed
DDoS attack. The dataset contains normal baseline traffic, a prolonged elevated
attack window, and a recovery period to test N.O.R.A's sustained attack detection,
anomaly scoring, alert generation, and source attribution behaviour.
"""

from datetime import datetime, timedelta
import os
import random


OUTPUT_FILE = "logs/phase3_validation_sustained_attack.log"
START_TIME = datetime(2026, 6, 17, 16, 0, 0)
DURATION_MINUTES = 80

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.15",
    "10.0.0.21",
    "10.0.0.22",
]

SUSTAINED_ATTACK_IPS = [
    "45.155.205.233",
    "185.220.101.42",
    "91.240.118.172",
    "103.21.244.18",
    "203.0.113.77",
    "198.51.100.91",
    "192.0.2.44",
    "156.146.62.18",
]

NORMAL_PATHS = [
    "/",
    "/products",
    "/login",
    "/api/status",
    "/checkout",
    "/help",
]

SUSTAINED_ATTACK_PATHS = [
    "/",
    "/login",
    "/products",
    "/checkout",
    "/api/status",
    "/search",
    "/wp-login.php",
]


def apache_log_line(ip, timestamp, method, path, status, size):
    """Build one Apache-style access log line."""
    return (
        f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"{method} {path} HTTP/1.1" {status} {size}'
    )


def generate_sustained_attack_log():
    """Generate a sustained distributed attack validation dataset."""
    random.seed(43)
    lines = []

    for minute in range(DURATION_MINUTES):
        timestamp = START_TIME + timedelta(minutes=minute)

        # Normal baseline traffic throughout the session.
        normal_request_count = random.randint(5, 11)

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

        # Sustained window: prolonged elevation without a single sharp burst spike.
        if 22 <= minute <= 25:
            attack_request_count = random.randint(65, 95)
        elif 26 <= minute <= 52:
            attack_request_count = random.randint(115, 155)
        elif 53 <= minute <= 58:
            attack_request_count = random.randint(70, 105)
        else:
            attack_request_count = 0

        for _ in range(attack_request_count):
            ip = random.choice(SUSTAINED_ATTACK_IPS)
            path = random.choice(SUSTAINED_ATTACK_PATHS)
            status = random.choice([200, 200, 200, 403, 429, 503])
            second_offset = random.randint(0, 59)

            lines.append(
                apache_log_line(
                    ip=ip,
                    timestamp=timestamp + timedelta(seconds=second_offset),
                    method=random.choice(["GET", "GET", "GET", "POST"]),
                    path=path,
                    status=status,
                    size=random.randint(500, 4200),
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
    print("Dataset type: Sustained distributed attack")
    print(f"Attack sources: {len(SUSTAINED_ATTACK_IPS)}")
    print("Sustained attack window: 16:22 to 16:58")


if __name__ == "__main__":
    generate_sustained_attack_log()