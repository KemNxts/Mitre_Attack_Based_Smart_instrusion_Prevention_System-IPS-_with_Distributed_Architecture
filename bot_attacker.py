import requests
import time
import random
import threading
import argparse

# ---------------- ARGUMENTS ---------------- #
parser = argparse.ArgumentParser(description="Adaptive Bot Attack (Smart Behavior)")
parser.add_argument("target", help="Target IP (use 127.0.0.1)")
parser.add_argument("--bot-count", type=int, default=5)
parser.add_argument("--duration", type=int, default=30)
args = parser.parse_args()

TARGET_IP = args.target
BOT_COUNT = args.bot_count
DURATION = args.duration

LOGIN_URL = f"http://{TARGET_IP}:6000/login"
SEARCH_URL = f"http://{TARGET_IP}:6000/search"
IPS_URL = f"http://{TARGET_IP}:5000/predict"

session = requests.Session()

# ---------------- IP GENERATION ---------------- #
def generate_ip():
    return f"192.168.1.{random.randint(2, 254)}"


# ---------------- BOT BEHAVIOR ---------------- #
def bot_behavior(bot_id):
    source_ip = generate_ip()
    delay = random.uniform(0.2, 1.0)

    end_time = time.time() + DURATION

    while time.time() < end_time:
        try:
            action = random.choice(["login", "search"])

            # ---------------- LOGIN ---------------- #
            if action == "login":
                login_data = {
                    "ip": source_ip,
                    "username": random.choice(["admin", "user", "guest"]),
                    "password": random.choice(["1234", "pass", "wrong"])
                }
                session.post(LOGIN_URL, json=login_data, timeout=1)

                endpoint = "login"
                failed_logins = 1 if login_data["password"] == "wrong" else 0

            # ---------------- SEARCH ---------------- #
            else:
                search_data = {
                    "ip": source_ip,
                    "query": random.choice(["product", "laptop", "phone", "test"])
                }
                session.post(SEARCH_URL, json=search_data, timeout=1)

                endpoint = "search"
                failed_logins = 0

            # ---------------- IPS PAYLOAD ---------------- #
            ips_payload = {
                "ip": source_ip,
                "endpoint": endpoint,   # 🔥 FIX (CRITICAL)
                "request_rate": int(1 / delay * 100),
                "failed_logins": failed_logins,
                "packet_size": random.randint(500, 900),
                "duration": delay,
                "protocol": "HTTP",
                "attack_type": "Bot"
            }

            res = session.post(IPS_URL, json=ips_payload, timeout=2)
            response = res.json()

            status = response.get("status", "allowed")

            # ---------------- ADAPTIVE LOGIC ---------------- #
            if status == "allowed":
                delay = max(0.1, delay - 0.05)

            elif status == "suspicious":
                delay = min(2.0, delay + 0.3)

            elif status == "blocked":
                print(f"[Bot-{bot_id}] Blocked → rotating IP")
                source_ip = generate_ip()
                delay = random.uniform(1.0, 2.0)
                time.sleep(2)

        except:
            pass

        time.sleep(delay)


# ---------------- MAIN ---------------- #
def run_attack():
    print(f"🤖 Adaptive Bot Attack on {TARGET_IP}")
    print(f"Bots: {BOT_COUNT} | Duration: {DURATION}s")
    print("--------------------------------------------------")

    threads = []

    for i in range(BOT_COUNT):
        t = threading.Thread(target=bot_behavior, args=(i,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == "__main__":
    try:
        run_attack()
    except KeyboardInterrupt:
        print("\n🛑 Bot attack stopped.")