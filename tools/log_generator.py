

import random
from datetime import datetime, timedelta


LEGITIMATE_ENDPOINTS = [
    '/',
    '/home',
    '/products',
    '/cart',
    '/checkout',
    '/contact',
    '/api/search?q=laptop',
    '/api/search?q=headphones',
    '/assets/logo.png',
    '/assets/banner.jpg',
    '/login',
    '/register'
]


RECON_ENDPOINTS = [
    '/wp-login.php',
    '/phpmyadmin',
    '/.env',
    '/server-status',
    '/admin',
    '/xmlrpc.php'
]


USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
    'curl/7.88.1',
    'python-requests/2.31.0'
]


LEGITIMATE_IPS = [
    '91.240.118.172',
    '84.17.44.201',
    '172.67.211.55',
    '104.26.12.44',
    '45.83.64.12'
]



ATTACKER_IPS = [
    '185.220.101.45',
    '103.145.13.99',
    '89.248.165.74',
    '45.95.147.21',
    '198.98.51.189'
]


# --- Attack campaign configuration ---
ATTACK_CAMPAIGNS = [
    {
        'name': 'recon_wave',
        'start': 1200,
        'duration': 900,
        'intensity': (2, 6),
        'generator': 'recon'
    },
    {
        'name': 'credential_stuffing_wave',
        'start': 3200,
        'duration': 1200,
        'intensity': (4, 10),
        'generator': 'credential'
    },
    {
        'name': 'ddos_wave',
        'start': 6200,
        'duration': 1400,
        'intensity': (12, 28),
        'generator': 'ddos'
    }
]


HTTP_METHODS = ['GET', 'POST']


STATUS_CODES = {
    'legitimate': [200, 200, 200, 301, 302],
    'recon': [403, 404, 404, 401],
    'credential_stuffing': [401, 401, 401, 403],
    'ddos': [200, 429, 503]
}


OUTPUT_FILE = 'logs/generated_attack_mix.log'


def generate_timestamp(base_time, offset_seconds):
    timestamp = base_time + timedelta(seconds=offset_seconds)
    return timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')


def generate_log_line(ip, timestamp, method, endpoint, status, size, user_agent):
    return (
        f'{ip} - - [{timestamp}] "{method} {endpoint} HTTP/1.1" '
        f'{status} {size} "-" "{user_agent}"'
    )


def generate_legitimate_traffic(base_time, current_second):
    endpoint = random.choice(LEGITIMATE_ENDPOINTS)
    return generate_log_line(
        ip=random.choice(LEGITIMATE_IPS),
        timestamp=generate_timestamp(base_time, current_second),
        method=random.choice(HTTP_METHODS),
        endpoint=endpoint,
        status=random.choice(STATUS_CODES['legitimate']),
        size=random.randint(400, 12000),
        user_agent=random.choice(USER_AGENTS)
    )


def generate_recon_traffic(base_time, current_second):
    endpoint = random.choice(RECON_ENDPOINTS)
    return generate_log_line(
        ip=random.choice(ATTACKER_IPS),
        timestamp=generate_timestamp(base_time, current_second),
        method='GET',
        endpoint=endpoint,
        status=random.choice(STATUS_CODES['recon']),
        size=random.randint(200, 1500),
        user_agent=random.choice(USER_AGENTS)
    )


def generate_credential_stuffing(base_time, current_second):
    return generate_log_line(
        ip=random.choice(ATTACKER_IPS),
        timestamp=generate_timestamp(base_time, current_second),
        method='POST',
        endpoint='/login',
        status=random.choice(STATUS_CODES['credential_stuffing']),
        size=random.randint(500, 2000),
        user_agent=random.choice(USER_AGENTS)
    )



def generate_ddos_traffic(base_time, current_second):
    return generate_log_line(
        ip=random.choice(ATTACKER_IPS),
        timestamp=generate_timestamp(base_time, current_second),
        method='GET',
        endpoint='/api/search?q=flash-sale',
        status=random.choice(STATUS_CODES['ddos']),
        size=random.randint(1000, 6000),
        user_agent=random.choice(USER_AGENTS)
    )


# --- Attack wave generator ---
def generate_attack_wave(base_time, current_second, campaign):
    wave_logs = []

    request_volume = random.randint(
        campaign['intensity'][0],
        campaign['intensity'][1]
    )

    for _ in range(request_volume):

        if campaign['generator'] == 'recon':
            wave_logs.append(
                generate_recon_traffic(base_time, current_second)
            )

        elif campaign['generator'] == 'credential':
            wave_logs.append(
                generate_credential_stuffing(base_time, current_second)
            )

        elif campaign['generator'] == 'ddos':
            wave_logs.append(
                generate_ddos_traffic(base_time, current_second)
            )

    return wave_logs



def generate_log_dataset(total_logs=10000):
    logs = []

    base_time = datetime.utcnow() - timedelta(hours=2)

    current_second = 0

    while len(logs) < total_logs:

        # --- Baseline legitimate traffic ---
        baseline_volume = random.randint(1, 4)

        for _ in range(baseline_volume):
            logs.append(
                generate_legitimate_traffic(base_time, current_second)
            )

        # --- Background suspicious behaviour ---
        background_selector = random.random()

        if background_selector < 0.08:
            logs.append(
                generate_recon_traffic(base_time, current_second)
            )

        elif background_selector < 0.12:
            logs.append(
                generate_credential_stuffing(base_time, current_second)
            )

        # --- Coordinated attack campaigns ---
        for campaign in ATTACK_CAMPAIGNS:

            campaign_start = campaign['start']
            campaign_end = campaign_start + campaign['duration']

            if campaign_start <= current_second <= campaign_end:

                logs.extend(
                    generate_attack_wave(
                        base_time,
                        current_second,
                        campaign
                    )
                )

        # --- Natural traffic fluctuation ---
        if random.random() < 0.03:

            temporary_spike = random.randint(8, 20)

            for _ in range(temporary_spike):
                logs.append(
                    generate_legitimate_traffic(base_time, current_second)
                )

        current_second += 1

    return logs[:total_logs]


def write_logs_to_file(logs, output_file=OUTPUT_FILE):
    with open(output_file, 'w') as file:
        for log in logs:
            file.write(log + '\n')


if __name__ == '__main__':
    generated_logs = generate_log_dataset(total_logs=10000)
    write_logs_to_file(generated_logs)
    print(f'Generated {len(generated_logs)} log entries.')
    print(f'Logs written to: {OUTPUT_FILE}')