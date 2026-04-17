import requests
import time
import random
import threading
import argparse

# Argument Parsing
parser = argparse.ArgumentParser(description="IPS Stress Tester - Bot")
parser.add_argument("target", help="Target IP address")
parser.add_argument("--bot-count", type=int, default=1, help="Number of virtual bots")
args = parser.parse_args()

target_ip = args.target
bot_count = args.bot_count

URL = f"http://{target_ip}:5000/predict"

def generate_ips(count):
    if count == 1: return ["192.168.1.100"]
    return [f"192.168.1.{random.randint(2, 254)}" for _ in range(count)]

attack_ips = generate_ips(bot_count)

def bot_thread(source_ip):
    print(f"🤖 Bot Started: {source_ip} targeting {target_ip}...")
    while True:
        payload = {
            "ip": source_ip,
            "request_rate": random.randint(400, 800),
            "failed_logins": random.randint(0, 2),
            "packet_size": random.randint(500, 1200),
            "duration": 1.0,
            "protocol": "TCP",
            "attack_type": "Bot"
        }
        try:
            requests.post(URL, json=payload, timeout=2.0)
        except:
            pass
        time.sleep(random.uniform(0.5, 3.0))

if __name__ == "__main__":
    threads = []
    print(f"🤖 Launching {bot_count} bot threads...")
    for i in range(bot_count):
        src_ip = attack_ips[i % len(attack_ips)]
        t = threading.Thread(target=bot_thread, args=(src_ip,))
        t.daemon = True
        t.start()
        threads.append(t)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🤖 Multi-Bot simulation stopped.")
