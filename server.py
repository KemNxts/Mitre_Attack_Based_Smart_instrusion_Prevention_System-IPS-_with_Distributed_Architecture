from flask import Flask, jsonify
import psutil
import json
import os

app = Flask(__name__)

# The path where run_hybrid.py writes the HIDS event logs
EVENT_LOG_FILE = os.path.join(os.path.dirname(__file__), "hids", "data", "event_log.json")

@app.route('/logs', methods=['GET'])
def get_logs():
    """
    Reads the HIDS event logs and serves them to the dashboard.
    """
    if not os.path.exists(EVENT_LOG_FILE):
        return jsonify([])
    
    try:
        with open(EVENT_LOG_FILE, "r") as f:
            events = json.load(f)
            # Return the last 100 events, newest first
            return jsonify(events[-100:][::-1])
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading event log: {e}")
        return jsonify([])

@app.route('/stats', methods=['GET'])
def get_stats():
    """
    Computes summary statistics from the HIDS event logs.
    """
    if not os.path.exists(EVENT_LOG_FILE):
        return jsonify({
            "total_attacks": 0,
            "blocked": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "attack_types": {}
        })

    try:
        with open(EVENT_LOG_FILE, "r") as f:
            events = json.load(f)
            
        stats = {
            "total_attacks": len(events),
            "blocked": len([e for e in events if e.get('action') == 'PREVENTED']),
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "attack_types": {}
        }
        
        for e in events:
            # Map known severities or fallback
            sev = e.get('severity', 'LOW').upper()
            if sev not in stats["severity_counts"]:
                sev = "LOW"
            stats["severity_counts"][sev] += 1
            
            # Count attack types
            attack_name = e.get('attack_name', 'Unknown')
            stats["attack_types"][attack_name] = stats["attack_types"].get(attack_name, 0) + 1
            
        return jsonify(stats)
    except (json.JSONDecodeError, IOError):
        return jsonify({
            "total_attacks": 0,
            "blocked": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "attack_types": {}
        })

@app.route('/blocked', methods=['GET'])
def get_blocked():
    """
    Returns a list of recent preventions. Since host-based prevention 
    doesn't strictly "block IPs", we can return mitigated attack names 
    or processes here to satisfy the dashboard UI.
    """
    if not os.path.exists(EVENT_LOG_FILE):
        return jsonify([])
    try:
        with open(EVENT_LOG_FILE, "r") as f:
            events = json.load(f)
        preventions = [f"{e.get('attack_name')} mitigated" for e in events if e.get('action') == 'PREVENTED']
        return jsonify(list(set(preventions)))
    except:
        return jsonify([])

@app.route('/system_stats', methods=['GET'])
def system_stats():
    """
    Provides global host resource usage and top memory-consuming processes.
    """
    mem = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=None)
    
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'cmdline']):
        try:
            pinfo = p.info
            cmd = " ".join(pinfo['cmdline']) if pinfo['cmdline'] else pinfo['name']
            procs.append({
                "pid": pinfo['pid'],
                "user": pinfo['username'],
                "cpu": round(pinfo['cpu_percent'] or 0.0, 1),
                "mem": round(pinfo['memory_percent'] or 0.0, 1),
                "cmd": cmd
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    procs = sorted(procs, key=lambda p: p['mem'], reverse=True)[:100]

    return jsonify({
        "cpu_percent": cpu,
        "ram_percent": mem.percent,
        "ram_used_gb": round(mem.used / (1024**3), 2),
        "ram_total_gb": round(mem.total / (1024**3), 2),
        "top_processes": procs
    })

if __name__ == '__main__':
    print("🚀 API Gateway for Smart HIDS Dashboard Running on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)