import requests
import time
import random

LOGIN_SERVER = "http://127.0.0.1:6000/search"
IPS_SERVER = "http://127.0.0.1:5000/predict"
SOURCE_IP = "192.168.1.100"

PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "' UNION SELECT * FROM users --"
]

def run_attack():
    print("Starting Real-World Web Attack Lab Simulation...")
    print("------------------------------------------------")

    attempts = 6

    for i in range(attempts):
        payload = random.choice(PAYLOADS)  # randomize payload
        print(f"[*] Attempt {i+1} | Payload: {payload}")

        # 1. Send to Vulnerable Login Server
        try:
            target_data = {"ip": SOURCE_IP, "query": payload}
            response = requests.post(LOGIN_SERVER, json=target_data, timeout=2.0)
            res = response.json()
            print(f"    [+] Login Server: {res.get('status')} - {res.get('message')}")
        except Exception as e:
            print(f"    [-] Target Error: {e}")

        # 2. Forward to IPS for Detection
        try:
            ips_payload = {
                "ip": SOURCE_IP,
                "request_rate": random.randint(5, 20),   # add variation
                "failed_logins": 0,
                "packet_size": random.randint(900, 1400) + len(payload),  # avoid always triggering rule
                "duration": round(random.uniform(0.5, 2.0), 2),
                "protocol": "HTTP",
                "attack_type": "Web Attack"
            }

            ips_response = requests.post(IPS_SERVER, json=ips_payload, timeout=2.0)
            res = ips_response.json()

            print(f"    [+] IPS: {res.get('prediction')} | Status: {res.get('status')} | Score: {res.get('score')} | Attempts: {res.get('attempts')}")

        except Exception as e:
            print(f"    [-] IPS Connection Error: {e}")

        print("------------------------------------------------")

        # realistic delay (avoid rapid repeat penalty every time)
        time.sleep(random.uniform(1.2, 2.5))

if __name__ == "__main__":
    run_attack()