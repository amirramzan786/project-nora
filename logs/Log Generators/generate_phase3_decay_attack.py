"""
Project N.O.R.A.
Phase 3 Validation Log Generator
Dataset 10 - Decay Attack

This generator creates Apache-style access logs that simulate a decay-based
DDoS pattern. Traffic rapidly spikes to a high volume and then gradually
reduces over time until normal traffic levels are restored.

Purpose:
- Validate decay attack detection.
- Differentiate decay behaviour from sustained attacks.
- Test confidence reduction as attack intensity decreases.
"""

from datetime import datetime, timedelta
import os
import random


OUTPUT_FILE = "logs/phase3_validation_decay_attack.log"
START_TIME = datetime(2026, 6, 17, 20, 0, 0)
DURATION_MINUTES = 70

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.15",
    "10.0.0.21",
    "10.0.0.22",
]

DECAY_ATTACK_IPS = [
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

DECAY_ATTACK_PATHS = [
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


def get_decay_attack_request_count(minute):
    """Return attack volume for a decay attack profile."""

    # Initial aggressive attack peak.
    if 10 <= minute <= 15:
        return random.randint(220, 300)

    # Strong decay phase.
    if 16 <= minute <= 22:
        return random.randint(170, 220)

    # Moderate decay phase.
    if 23 <= minute <= 30:
        return random.randint(110, 170)

    # Continued decline.
    if 31 <= minute <= 40:
        return random.randint(60, 110)

    # Weak residual activity.
    if 41 <= minute <= 50:
        return random.randint(25, 60)

    # Return towards baseline.
    if 51 <= minute <= 58:
        return random.randint(5, 25)

    return 0


def generate_decay_attack_log():
    """Generate a decay attack validation dataset."""
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

        # Decay attack traffic spikes and then gradually decreases.
        attack_request_count = get_decay_attack_request_count(minute)

        for _ in range(attack_request_count):
            ip = random.choice(DECAY_ATTACK_IPS)
            path = random.choice(DECAY_ATTACK_PATHS)
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
    print("Dataset type: Decay attack")
    print(f"Decay sources: {len(DECAY_ATTACK_IPS)}")
    print("Baseline window: 20:00 to 20:09")
    print("Attack peak: 20:10 to 20:15")
    print("Strong decay: 20:16 to 20:22")
    print("Moderate decay: 20:23 to 20:30")
    print("Continued decline: 20:31 to 20:40")
    print("Residual activity: 20:41 to 20:50")
    print("Recovery: 20:51 onwards")


if __name__ == "__main__":
    generate_decay_attack_log()