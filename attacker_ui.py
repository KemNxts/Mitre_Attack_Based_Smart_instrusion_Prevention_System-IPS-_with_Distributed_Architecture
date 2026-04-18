from flask import Flask, render_template, jsonify, request
import subprocess
import os
import sys
import signal
import ipaddress
import random

app = Flask(__name__)

# Track running processes and their current "Bot List"
processes = {
    'bruteforce': {'proc': None, 'ips': []},
    'dos': {'proc': None, 'ips': []},
    'portscan': {'proc': None, 'ips': []},
    'bot': {'proc': None, 'ips': []},
    'web': {'proc': None, 'ips': []}
}

ATTACK_SCRIPTS = {
    'bruteforce': 'bruteforce_attacker.py',
    'dos': 'dos_attacker.py',
    'portscan': 'port_scan_attacker.py',
    'bot': 'bot_attacker.py',
    'web': 'web_attacker.py'
}

def is_local_ip(ip):
    if ip.lower() == 'localhost': return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or (addr.is_private and str(addr).startswith("192.168."))
    except: return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/status')
def get_status():
    status = {}
    for key, data in processes.items():
        if data['proc'] and data['proc'].poll() is None:
            status[key] = {'status': 'running', 'num_ips': len(data['ips'])}
        else:
            processes[key]['proc'] = None
            processes[key]['ips'] = []
            status[key] = {'status': 'idle', 'num_ips': 0}
    return jsonify(status)

@app.route('/active-ips')
def get_active_ips():
    all_ips = []
    for key, data in processes.items():
        if data['proc'] and data['proc'].poll() is None:
            all_ips.extend(data['ips'])
    return jsonify(list(set(all_ips)))

@app.route('/launch/<attack_type>', methods=['POST'])
def launch_attack(attack_type):
    if attack_type not in ATTACK_SCRIPTS:
        return jsonify({"message": "Invalid type"}), 400

    params = request.json
    target_ip = params.get('target_ip', '127.0.0.1')
    bot_mode = params.get('bot_mode', False)
    bot_count = int(params.get('bot_count', 1))

    # Security Check
    if not is_local_ip(target_ip):
        return jsonify({"message": "❌ Target rejected (Security Policy)"}), 403

    if processes[attack_type]['proc'] and processes[attack_type]['proc'].poll() is None:
        return jsonify({"message": f"{attack_type} is already active"}), 400

    script_path = os.path.join(os.path.dirname(__file__), ATTACK_SCRIPTS[attack_type])
    
    # Generate list of IPs for status display (scripts will generate their own too, but UI needs a list)
    num_ips = bot_count if bot_mode else 1
    generated_ips = [f"192.168.1.{random.randint(2, 254)}" for _ in range(num_ips)]
    if num_ips == 1: generated_ips = ["192.168.1.100"]

    try:
        # Build command with arguments
        cmd = [sys.executable, script_path, target_ip]
        if bot_mode:
            cmd.extend(['--bot-count', str(bot_count)])

        proc = subprocess.Popen(cmd, cwd=os.path.dirname(__file__))
        processes[attack_type] = {
            'proc': proc,
            'ips': generated_ips
        }
        
        mode_str = f"Bot Mode ({bot_count} IPs)" if bot_mode else "Single IP"
        print(f"[UI] Started {attack_type} in {mode_str} against {target_ip}")
        return jsonify({"message": f"Successfully launched {attack_type} in {mode_str}."})
    except Exception as e:
        return jsonify({"message": f"Launch error: {str(e)}"}), 500

@app.route('/stop/<attack_type>', methods=['POST'])
def stop_attack(attack_type):
    data = processes.get(attack_type)
    if data and data['proc'] and data['proc'].poll() is None:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(data['proc'].pid)], capture_output=True)
        else:
            os.kill(data['proc'].pid, signal.SIGTERM)
        
        processes[attack_type]['proc'] = None
        processes[attack_type]['ips'] = []
        return jsonify({"message": f"Terminated {attack_type}."})
    return jsonify({"message": "Nothing to stop."})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=7000)
