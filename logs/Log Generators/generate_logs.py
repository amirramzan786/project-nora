import random
from datetime import datetime, timedelta

ips = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.2",
    "203.0.113.1",
    "192.168.1.3",
    "192.168.1.4"
]

endpoints = ["/", "/login", "/api/data", "/home", "/contact"]

start_time = datetime(2026, 4, 24, 22, 0, 0)

lines = []

for i in range(1000):
    # --- NORMAL TRAFFIC ---
    if i < 600:
        ip = random.choice(ips)
        timestamp = start_time + timedelta(seconds=i * random.randint(1, 3))

    # --- BURST ATTACK ---
    elif 600 <= i < 800:
        ip = "10.0.0.99"
        timestamp = start_time + timedelta(seconds=600 + random.randint(0, 5))

    # --- SUSTAINED ATTACK ---
    else:
        ip = "172.16.99.1"
        timestamp = start_time + timedelta(seconds=800 + (i - 800))

    endpoint = random.choice(endpoints)

    log_line = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" 200 {random.randint(200,1500)}'
    lines.append(log_line)

# Save file
with open("logs/test/high_res.log", "w") as f:
    for line in lines:
        f.write(line + "\n")

print("✅ 1000-line log generated: logs/test/high_res.log")