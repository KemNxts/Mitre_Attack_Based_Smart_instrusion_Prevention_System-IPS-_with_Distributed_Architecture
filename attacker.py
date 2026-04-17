import requests
import random
import time

# URL of your IPS server
URL = "http://127.0.0.1:5000/predict"

# Attack types
ATTACK_TYPES = ["Normal", "DoS", "Brute Force", "Port Scan", "Bot", "Web Attack"]

# Generate random IP
def generate_ip():
    return f"192.168.1.{random.randint(1, 254)}"

# Generate realistic traffic features
def generate_traffic(attack_type):
    if attack_type == "DoS":
        return {
            "request_rate": random.randint(200, 500),
            "failed_logins": 0,
            "packet_size": random.randint(800, 1500),
            "duration": random.uniform(0.1, 1.0),
            "protocol": random.choice(["TCP", "UDP"])
        }

    elif attack_type == "Brute Force":
        return {
            "request_rate": random.randint(50, 150),
            "failed_logins": random.randint(10, 50),
            "packet_size": random.randint(200, 600),
            "duration": random.uniform(1.0, 5.0),
            "protocol": "TCP"
        }

    elif attack_type == "Port Scan":
        return {
            "request_rate": random.randint(20, 100),
            "failed_logins": 0,
            "packet_size": random.randint(100, 300),
            "duration": random.uniform(0.5, 2.0),
            "protocol": "TCP"
        }

    elif attack_type == "Bot":
        return {
            "request_rate": random.randint(100, 300),
            "failed_logins": random.randint(1, 5),
            "packet_size": random.randint(300, 800),
            "duration": random.uniform(0.5, 3.0),
            "protocol": random.choice(["TCP", "UDP"])
        }

    elif attack_type == "Web Attack":
        return {
            "request_rate": random.randint(10, 50),
            "failed_logins": random.randint(0, 5),
            "packet_size": random.randint(100, 500),
            "duration": random.uniform(0.5, 2.0),
            "protocol": "HTTP"
        }

    else:  # Normal
        return {
            "request_rate": random.randint(5, 30),
            "failed_logins": 0,
            "packet_size": random.randint(50, 300),
            "duration": random.uniform(1.0, 5.0),
            "protocol": random.choice(["TCP", "UDP", "HTTP"])
        }

# Main loop
def run_attacker():
    print("🚀 Starting General Attack Simulation (Background Noise)...")
    print("💡 FOR SPECIALIZED ATTACKS, RUN:")
    print("   - python bruteforce_attacker.py")
    print("   - python dos_attacker.py")
    print("   - python port_scan_attacker.py")
    print("   - python bot_attacker.py")
    print("   - python web_attacker.py\n")

    while True:
        attack_type = random.choice(ATTACK_TYPES)
        ip = generate_ip()
        traffic = generate_traffic(attack_type)

        payload = {
            "ip": ip,
            "attack_type": attack_type,  # for validation/debug
            **traffic
        }

        try:
            response = requests.post(URL, json=payload)
            result = response.json()

            print("===================================")
            print(f"IP: {ip}")
            print(f"Simulated Attack: {attack_type}")
            print(f"Predicted: {result.get('prediction')}")
            print(f"MITRE: {result.get('technique')}")
            print(f"Action: {result.get('action')}")
            print("===================================\n")

        except Exception as e:
            print("❌ Error sending request:", e)

        time.sleep(1)  # simulate real-time traffic


if __name__ == "__main__":
    run_attacker()