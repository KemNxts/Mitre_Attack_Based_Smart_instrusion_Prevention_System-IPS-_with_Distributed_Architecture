import socket
import requests
import time
import argparse
import random

# Argument Parsing
parser = argparse.ArgumentParser(description="IPS Stress Tester - Port Scan")
parser.add_argument("target", help="Target IP address")
parser.add_argument("--bot-count", type=int, default=1, help="Number of virtual scanners")
args = parser.parse_args()

target_ip = args.target
bot_count = args.bot_count

IPS_URL = f"http://{target_ip}:5000/predict"

def generate_ips(count):
    if count == 1: return ["192.168.1.100"]
    return [f"192.168.1.{random.randint(2, 254)}" for _ in range(count)]

attack_ips = generate_ips(bot_count)
session = requests.Session()

def scan_ports(start_port, end_port):
    print(f"Starting Port Scan on {target_ip} using {bot_count} virtual IPs...")
    
    for port in range(start_port, end_port + 1):
        # Rotate source IP for each probe!
        src_ip = attack_ips[port % len(attack_ips)]
        
        try:
            # 1. Real socket attempt
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            # 2. Inform IPS
            payload = {
                "ip": src_ip,
                "request_rate": random.randint(100, 500),
                "failed_logins": 0,
                "packet_size": random.randint(40, 100),
                "duration": 0.01,
                "protocol": "TCP",
                "attack_type": "Port Scan"
            }
            session.post(IPS_URL, json=payload, timeout=2.0)
            print(f"[{src_ip}] Probed Port {port}")
        except:
            pass
        
        time.sleep(0.05)

if __name__ == "__main__":
    scan_ports(20, 100)
