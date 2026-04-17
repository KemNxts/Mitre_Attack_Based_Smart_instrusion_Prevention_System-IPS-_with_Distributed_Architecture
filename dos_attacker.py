import requests
import time
import random
import threading
import sys
import argparse

# Argument Parsing
parser = argparse.ArgumentParser(description="IPS Stress Tester - DoS")
parser.add_argument("target", help="Target IP address")
parser.add_argument("--bot-count", type=int, default=1, help="Number of virtual attackers")
args = parser.parse_args()

target_ip = args.target
bot_count = args.bot_count

URL = f"http://{target_ip}:5000/predict"

def generate_ips(count):
    if count == 1: return ["192.168.1.5"]
    return [f"192.168.1.{random.randint(2, 254)}" for _ in range(count)]

attack_ips = generate_ips(bot_count)

def send_flooding_requests():
    print(f"🌊 Starting DoS Flood with {bot_count} bots against {target_ip}...")
    
    def flood(source_ip):
        # Increased request count for bots
        for _ in range(30):
            payload = {
                "ip": source_ip,
                "request_rate": random.randint(1500, 3000), # Very high rate for DoS
                "failed_logins": 0,
                "packet_size": random.randint(1000, 1500),
                "duration": 0.01,
                "protocol": "TCP",
                "attack_type": "DoS"
            }
            try:
                requests.post(URL, json=payload, timeout=2.0)
            except:
                pass

    while True:
        threads = []
        for i in range(bot_count):
            # Rotate IPs
            src_ip = attack_ips[i % len(attack_ips)]
            t = threading.Thread(target=flood, args=(src_ip,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        time.sleep(1)

if __name__ == "__main__":
    try:
        send_flooding_requests()
    except KeyboardInterrupt:
        print("\n🛑 Flood stopped.")
