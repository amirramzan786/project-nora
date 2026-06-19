from datetime import datetime, timedelta
import random

output = "logs/normal_traffic_validation_v2.log"
start = datetime(2026, 6, 13, 18, 0, 0)

normal_ips = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "10.0.0.21",
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

# Continuous normal business traffic
for minute in range(0, 60):
    timestamp = start + timedelta(minutes=minute)

    for _ in range(random.randint(6, 14)):
        ip = random.choice(normal_ips)
        path = random.choice(paths)
        status = random.choice([200, 200, 200, 200, 304])

        lines.append(
            f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {path} HTTP/1.1" {status} {random.randint(800, 3200)}'
        )

random.shuffle(lines)

with open(output, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print(f"Created {output}")
print(f"Total lines: {len(lines)}")