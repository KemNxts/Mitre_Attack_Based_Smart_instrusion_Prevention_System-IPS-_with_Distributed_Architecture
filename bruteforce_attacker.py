import requests
import time
import random
import sys
import argparse

# Argument Parsing
parser = argparse.ArgumentParser(description="IPS Stress Tester - Brute Force")
parser.add_argument("target", help="Target IP address")
parser.add_argument("--bot-count", type=int, default=1, help="Number of virtual bots (Ignored for Brute Force)")
args = parser.parse_args()

target_ip = args.target

LOGIN_URL = f"http://{target_ip}:6000/login"
IPS_URL = f"http://{target_ip}:5000/predict"

# Realistic password list
password_list = [
    "123456", "admin", "password", "1234", "qwerty", 
    "letmein", "password123", "secret", "welcome", "administrator"
]

# Single IP for Brute Force for realism
ip_simulated = "192.168.1.50"

def run_attack():
    print(f"🚨 Starting Single-Source Brute Force Attack against {target_ip}...")
    
    for attempt, pwd in enumerate(password_list, start=1):
        try:
            # 1. Login Attempt
            response = requests.post(LOGIN_URL, json={
                "ip": ip_simulated, "username": "admin", "password": pwd
            }, timeout=2)
            result = response.json()
            
            # 2. Inform IPS
            ips_payload = {
                "ip": ip_simulated,
                "request_rate": random.randint(50, 100),
                "failed_logins": result.get("failed_attempts", attempt if result['status'] != 'success' else 0),
                "packet_size": random.randint(200, 400),
                "duration": 0.5,
                "protocol": "TCP",
                "attack_type": "Brute Force"
            }
            requests.post(IPS_URL, json=ips_payload, timeout=2.0)
            print(f"[Attempt {attempt}] Pwd='{pwd}' -> {result['status']}")

            if result['status'] in ['locked', 'success']:
                break
        except:
            break
        time.sleep(0.5)

if __name__ == "__main__":
    run_attack()