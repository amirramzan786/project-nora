

"""
Project N.O.R.A.
Phase 3 Validation Log Generator
Dataset 06 - Low-and-Slow Reconnaissance / Slow Attack Pattern

This generator creates Apache-style access logs that simulate a low-and-slow
attack pattern. The traffic avoids obvious burst spikes but maintains persistent,
coordinated activity across several external sources.
"""

from datetime import datetime, timedelta
import os
import random


OUTPUT_FILE = "logs/phase3_validation_low_slow.log"
START_TIME = datetime(2026, 6, 17, 9, 0, 0)
DURATION_MINUTES = 120

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.15",
    "10.0.0.21",
    "10.0.0.22",
]

SLOW_ATTACK_IPS = [
    "185.220.101.42",
    "45.155.205.233",
    "91.240.118.172",
    "103.21.244.18",
]

NORMAL_PATHS = [
    "/",
    "/products",
    "/login",
    "/api/status",
    "/checkout",
    "/help",
]

SLOW_ATTACK_PATHS = [
    "/login",
    "/login",
    "/wp-login.php",
    "/admin",
    "/account",
    "/api/status",
    "/checkout",
]

USER_AGENTS = [
    "Mozilla/5.0",
    "Chrome/120.0",
    "Safari/605.1",
    "Edge/120.0",
]


def apache_log_line(ip, timestamp, method, path, status, size):
    """Build one Apache-style access log line."""
    return (
        f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"{method} {path} HTTP/1.1" {status} {size}'
    )


def generate_low_slow_log():
    """Generate a low-and-slow validation dataset."""
    lines = []

    for minute in range(DURATION_MINUTES):
        timestamp = START_TIME + timedelta(minutes=minute)

        # Normal background activity remains present but does not dominate the dataset.
        normal_request_count = random.randint(3, 7)

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

        # Low-and-slow activity starts quietly, increases gradually, then persists.
        # The pattern avoids sudden burst spikes but creates clear long-duration pressure.
        if minute < 20:
            slow_attack_request_count = random.randint(1, 3)
        elif minute < 45:
            slow_attack_request_count = random.randint(5, 9)
        elif minute < 90:
            slow_attack_request_count = random.randint(9, 15)
        else:
            slow_attack_request_count = random.randint(7, 12)

        for _ in range(slow_attack_request_count):
            ip = random.choice(SLOW_ATTACK_IPS)
            path = random.choice(SLOW_ATTACK_PATHS)
            status = random.choice([200, 200, 401, 401, 403, 429, 503])
            second_offset = random.randint(0, 59)

            lines.append(
                apache_log_line(
                    ip=ip,
                    timestamp=timestamp + timedelta(seconds=second_offset),
                    method=random.choice(["GET", "POST", "POST"]),
                    path=path,
                    status=status,
                    size=random.randint(500, 2800),
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
    print("Dataset type: Low-and-slow reconnaissance / slow attack pattern")


if __name__ == "__main__":
    generate_low_slow_log()