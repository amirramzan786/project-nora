
"""
Project N.O.R.A.
Phase 3 Validation Log Generator
Dataset 07 - Distributed Low-Volume Attack

This generator creates Apache-style access logs that simulate a distributed
low-volume attack pattern. The campaign uses many external sources, each with
low individual request volume, to test whether N.O.R.A can identify distributed
coordination without relying on obvious per-source spikes.
"""

from datetime import datetime, timedelta
import os
import random


OUTPUT_FILE = "logs/phase3_validation_distributed_low_volume.log"
START_TIME = datetime(2026, 6, 17, 13, 0, 0)
DURATION_MINUTES = 90

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.15",
    "10.0.0.21",
    "10.0.0.22",
]

# Many sources, each individually low volume.
DISTRIBUTED_ATTACK_IPS = [
    f"203.0.113.{index}" for index in range(10, 40)
] + [
    f"198.51.100.{index}" for index in range(20, 50)
]

NORMAL_PATHS = [
    "/",
    "/products",
    "/login",
    "/api/status",
    "/checkout",
    "/help",
]

ATTACK_PATHS = [
    "/login",
    "/login",
    "/wp-login.php",
    "/admin",
    "/account",
    "/api/status",
]


def apache_log_line(ip, timestamp, method, path, status, size):
    """Build one Apache-style access log line."""
    return (
        f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"{method} {path} HTTP/1.1" {status} {size}'
    )


def generate_distributed_low_volume_log():
    """Generate a distributed low-volume validation dataset."""
    lines = []

    for minute in range(DURATION_MINUTES):
        timestamp = START_TIME + timedelta(minutes=minute)

        # Normal traffic remains present throughout the session.
        normal_request_count = random.randint(4, 9)

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

        # Distributed campaign: many sources, low request volume per source.
        # This avoids obvious single-source spikes while creating broad coordination.
        if minute < 20:
            active_sources = random.sample(DISTRIBUTED_ATTACK_IPS, 8)
            requests_per_source = random.randint(1, 2)
        elif minute < 60:
            active_sources = random.sample(DISTRIBUTED_ATTACK_IPS, 18)
            requests_per_source = random.randint(1, 3)
        else:
            active_sources = random.sample(DISTRIBUTED_ATTACK_IPS, 12)
            requests_per_source = random.randint(1, 2)

        for ip in active_sources:
            for _ in range(requests_per_source):
                path = random.choice(ATTACK_PATHS)
                status = random.choice([200, 200, 401, 403, 429])
                second_offset = random.randint(0, 59)

                lines.append(
                    apache_log_line(
                        ip=ip,
                        timestamp=timestamp + timedelta(seconds=second_offset),
                        method=random.choice(["GET", "POST"]),
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
    print("Dataset type: Distributed low-volume attack")
    print(f"Distributed sources available: {len(DISTRIBUTED_ATTACK_IPS)}")


if __name__ == "__main__":
    generate_distributed_low_volume_log()