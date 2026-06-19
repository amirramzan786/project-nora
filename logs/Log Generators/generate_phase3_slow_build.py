"""
Project N.O.R.A.
Phase 3 Validation Log Generator
Dataset 08 - Slow Build Attack

This generator creates Apache-style access logs that simulate a gradual slow-build
DDoS pattern. The dataset contains normal baseline traffic, a controlled ramp-up
period, a sustained elevated window, and a late peak to test whether N.O.R.A can
identify attacks that develop slowly rather than appearing as an immediate burst.
"""

from datetime import datetime, timedelta
import os
import random


OUTPUT_FILE = "logs/phase3_validation_slow_build_attack.log"
START_TIME = datetime(2026, 6, 17, 17, 0, 0)
DURATION_MINUTES = 75

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.15",
    "10.0.0.21",
    "10.0.0.22",
]

SLOW_BUILD_ATTACK_IPS = [
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

SLOW_BUILD_PATHS = [
    "/",
    "/products",
    "/checkout",
    "/api/status",
    "/search",
    "/login",
]


def apache_log_line(ip, timestamp, method, path, status, size):
    """Build one Apache-style access log line."""
    return (
        f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"{method} {path} HTTP/1.1" {status} {size}'
    )


def get_slow_build_request_count(minute):
    """Return attack request volume for a gradual slow-build profile."""
    if 15 <= minute <= 24:
        return random.randint(15, 30)
    if 25 <= minute <= 34:
        return random.randint(35, 60)
    if 35 <= minute <= 44:
        return random.randint(65, 95)
    if 45 <= minute <= 54:
        return random.randint(100, 135)
    if 55 <= minute <= 64:
        return random.randint(140, 180)
    if 65 <= minute <= 70:
        return random.randint(110, 150)
    return 0


def generate_slow_build_attack_log():
    """Generate a slow-build attack validation dataset."""
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

        # Slow-build attack traffic gradually increases over time.
        attack_request_count = get_slow_build_request_count(minute)

        for _ in range(attack_request_count):
            ip = random.choice(SLOW_BUILD_ATTACK_IPS)
            path = random.choice(SLOW_BUILD_PATHS)
            status = random.choice([200, 200, 200, 200, 401, 403, 429])
            second_offset = random.randint(0, 59)

            lines.append(
                apache_log_line(
                    ip=ip,
                    timestamp=timestamp + timedelta(seconds=second_offset),
                    method=random.choice(["GET", "GET", "GET", "POST"]),
                    path=path,
                    status=status,
                    size=random.randint(600, 3200),
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
    print("Dataset type: Slow-build attack")
    print(f"Slow-build sources: {len(SLOW_BUILD_ATTACK_IPS)}")
    print("Baseline window: 17:00 to 17:14")
    print("Ramp-up window: 17:15 to 17:54")
    print("Peak window: 17:55 to 18:04")
    print("Recovery window: 18:05 to 18:10")


if __name__ == "__main__":
    generate_slow_build_attack_log()