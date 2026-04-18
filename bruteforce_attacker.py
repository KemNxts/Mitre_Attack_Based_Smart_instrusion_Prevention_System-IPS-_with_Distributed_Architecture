import requests
import time
import random
import sys
import argparse

# Argument Parsing
parser = argparse.ArgumentParser(description="IPS Stress Tester - Brute Force")
parser.add_argument("target", help="Target IP address")
parser.add_argument("--bot-count", type=int, default=1, help="Number of virtual bots")
args = parser.parse_args()

target_ip = args.target
bot_count = args.bot_count

LOGIN_URL = f"http://{target_ip}:6000/login"
IPS_URL = f"http://{target_ip}:5000/predict"

# Realistic password list
password_list = [
    "123456", "admin", "password", "1234", "qwerty", 
    "letmein", "password123", "secret", "welcome", "administrator"
]

def generate_ips(count):
    if count == 1: return ["192.168.1.50"]
    return [f"192.168.1.{random.randint(2, 254)}" for _ in range(count)]

attack_ips = generate_ips(bot_count)
session = requests.Session()

def run_attack():
    mode_str = f"Distributed ({bot_count} bots)" if bot_count > 1 else "Single-Source"
    print(f"Starting {mode_str} Brute Force Attack against {target_ip}...")
    
    for attempt, pwd in enumerate(password_list, start=1):
        # Rotate source IP!
        src_ip = attack_ips[attempt % len(attack_ips)]
        
        try:
            # 1. Login Attempt
            response = session.post(LOGIN_URL, json={
                "ip": src_ip, "username": "admin", "password": pwd
            }, timeout=2)
            result = response.json()
            
            # 2. Inform IPS
            ips_payload = {
                "ip": src_ip,
                "request_rate": random.randint(50, 100),
                "failed_logins": result.get("failed_attempts", attempt if result['status'] != 'success' else 0),
                "packet_size": random.randint(200, 400),
                "duration": 0.5,
                "protocol": "TCP",
                "attack_type": "Brute Force"
            }
            session.post(IPS_URL, json=ips_payload, timeout=2.0)
            print(f"[{src_ip}] [Attempt {attempt}] Pwd='{pwd}' -> {result['status']}")

            if result['status'] in ['locked', 'success']:
                break
        except Exception as e:
            print(f"Error during attack step: {e}")
            break
        time.sleep(0.5)

if __name__ == "__main__":
    run_attack()