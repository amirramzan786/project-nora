from datetime import datetime, timedelta
import random

output = "logs/phase3_validation_sample.log"
start = datetime(2026, 6, 13, 18, 0, 0)

normal_ips = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "10.0.0.21",
]

attacker_ips = [
    "45.155.205.233",
    "185.220.101.42",
    "91.240.118.172",
    "103.21.244.18",
]

paths = ["/", "/login", "/products", "/api/status", "/checkout"]
lines = []

# Normal baseline traffic
for minute in range(0, 20):
    timestamp = start + timedelta(minutes=minute)
    for _ in range(random.randint(3, 8)):
        ip = random.choice(normal_ips)
        path = random.choice(paths)
        lines.append(
            f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {path} HTTP/1.1" 200 {random.randint(800, 3200)}'
        )

# Slow build phase
for minute in range(20, 30):
    timestamp = start + timedelta(minutes=minute)
    request_count = 15 + ((minute - 20) * 6)

    for _ in range(request_count):
        ip = random.choice(attacker_ips[:2])
        lines.append(
            f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET /login HTTP/1.1" 200 {random.randint(900, 2500)}'
        )

# Coordinated burst attack
for minute in range(30, 37):
    timestamp = start + timedelta(minutes=minute)

    for _ in range(random.randint(160, 230)):
        ip = random.choice(attacker_ips)
        path = random.choice(["/login", "/api/status", "/checkout"])
        status = random.choice([200, 200, 200, 429, 503])
        lines.append(
            f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {path} HTTP/1.1" {status} {random.randint(500, 2200)}'
        )

# Decay / recovery phase
for minute in range(37, 48):
    timestamp = start + timedelta(minutes=minute)
    request_count = max(12, 90 - ((minute - 37) * 7))

    for _ in range(request_count):
        ip = random.choice(attacker_ips + normal_ips)
        path = random.choice(paths)
        lines.append(
            f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%M:%S +0000")}] '
            f'"GET {path} HTTP/1.1" 200 {random.randint(700, 2800)}'
        )

# Return to baseline
for minute in range(48, 60):
    timestamp = start + timedelta(minutes=minute)

    for _ in range(random.randint(4, 10)):
        ip = random.choice(normal_ips)
        path = random.choice(paths)
        lines.append(
            f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {path} HTTP/1.1" 200 {random.randint(800, 3200)}'
        )

random.shuffle(lines)

with open(output, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print(f"Created {output}")
print(f"Total lines: {len(lines)}")