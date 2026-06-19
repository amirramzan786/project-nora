"""
Project N.O.R.A.
Phase 3 Validation Log Generator
Dataset 09 - Wave Attack

This generator creates Apache-style access logs that simulate a wave-based DDoS
pattern. The dataset contains normal baseline traffic, three escalating attack
waves, partial recovery periods between each wave, and a final recovery window.
It is designed to test whether N.O.R.A can distinguish repeated attack cycles
from a single burst, sustained attack, or slow-build escalation.
"""

from datetime import datetime, timedelta
import os
import random


OUTPUT_FILE = "logs/phase3_validation_wave_attack.log"
START_TIME = datetime(2026, 6, 17, 18, 30, 0)
DURATION_MINUTES = 75

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.15",
    "10.0.0.21",
    "10.0.0.22",
]

WAVE_ATTACK_IPS = [
    "45.155.205.233",
    "185.220.101.42",
    "91.240.118.172",
    "103.21.244.18",
    "203.0.113.77",
    "198.51.100.24",
]

NORMAL_PATHS = [
    "/",
    "/products",
    "/login",
    "/api/status",
    "/checkout",
    "/help",
]

WAVE_ATTACK_PATHS = [
    "/",
    "/products",
    "/checkout",
    "/api/status",
    "/search",
    "/login",
    "/admin",
]


def apache_log_line(ip, timestamp, method, path, status, size):
    """Build one Apache-style access log line."""
    return (
        f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"{method} {path} HTTP/1.1" {status} {size}'
    )


def get_wave_attack_request_count(minute):
    """Return attack request volume for a repeated wave attack profile."""
    # Wave 1: moderate attack wave.
    if 12 <= minute <= 18:
        return random.randint(60, 100)

    # Recovery after wave 1.
    if 19 <= minute <= 24:
        return random.randint(20, 40)

    # Wave 2: stronger attack wave.
    if 25 <= minute <= 33:
        return random.randint(120, 180)

    # Recovery after wave 2.
    if 34 <= minute <= 40:
        return random.randint(25, 50)

    # Wave 3: strongest attack wave.
    if 41 <= minute <= 50:
        return random.randint(180, 260)

    # Final recovery period.
    if 51 <= minute <= 56:
        return random.randint(40, 70)

    return 0


def generate_wave_attack_log():
    """Generate a wave attack validation dataset."""
    lines = []

    for minute in range(DURATION_MINUTES):
        timestamp = START_TIME + timedelta(minutes=minute)

        # Normal baseline traffic throughout the session.
        normal_request_count = random.randint(5, 12)

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

        # Wave attack traffic appears in repeated cycles with partial recovery.
        attack_request_count = get_wave_attack_request_count(minute)

        for _ in range(attack_request_count):
            ip = random.choice(WAVE_ATTACK_IPS)
            path = random.choice(WAVE_ATTACK_PATHS)
            status = random.choice([200, 200, 200, 401, 403, 429, 503])
            second_offset = random.randint(0, 59)

            lines.append(
                apache_log_line(
                    ip=ip,
                    timestamp=timestamp + timedelta(seconds=second_offset),
                    method=random.choice(["GET", "GET", "GET", "POST"]),
                    path=path,
                    status=status,
                    size=random.randint(500, 3200),
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
    print("Dataset type: Wave attack")
    print(f"Wave sources: {len(WAVE_ATTACK_IPS)}")
    print("Baseline window: 18:30 to 18:41")
    print("Wave 1: 18:42 to 18:48")
    print("Recovery 1: 18:49 to 18:54")
    print("Wave 2: 18:55 to 19:03")
    print("Recovery 2: 19:04 to 19:10")
    print("Wave 3: 19:11 to 19:20")
    print("Final recovery: 19:21 to 19:26")


if __name__ == "__main__":
    generate_wave_attack_log()