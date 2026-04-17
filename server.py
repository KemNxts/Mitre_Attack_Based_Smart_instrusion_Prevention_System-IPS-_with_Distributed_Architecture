from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import joblib
import pandas as pd
from datetime import datetime

from model import train_model
from mitre import get_mitre
from prevention import IPSPrevention
from logger import IPSLogger
from preprocess import IPSPreprocessor

app = Flask(__name__)

# Initialize components
prevention = IPSPrevention()
logger = IPSLogger()
preprocessor = IPSPreprocessor()

# --- CACHED ML COMPONENTS ---
GLOBAL_MODEL = None
print("⚙️ Loading ML Protection Engine...")

def init_ml():
    global GLOBAL_MODEL
    model_path = os.path.join('models', 'ips_model.joblib')
    if not os.path.exists(model_path):
        train_model()
    GLOBAL_MODEL = joblib.load(model_path)
    print("✅ ML Engine Active.")

init_ml()

# Rate limiting
limiter = Limiter(
    get_remote_address, app=app,
    default_limits=["5000 per hour"],
    storage_uri="memory://",
)

logs_history = []

def hybrid_detect(data):
    # Features
    rate = data.get("request_rate", 0)
    failed = data.get("failed_logins", 0)
    size = data.get("packet_size", 0)
    
    # --- RULE-BASED LAYER (Overrides) ---
    if failed >= 5: 
        return "Brute Force", 1.0
    if rate > 1200: 
        return "DoS", 0.99
    if size > 1500 and data.get("protocol") == "HTTP":
        return "Web Attack", 0.95
    if rate > 100 and size < 100:
        return "Port Scan", 0.92

    # --- ML LAYER ---
    try:
        X_scaled = preprocessor.preprocess(data)
        prediction = GLOBAL_MODEL.predict(X_scaled)[0]
        probs = GLOBAL_MODEL.predict_proba(X_scaled)[0]
        confidence = float(max(probs))
        return prediction, confidence
    except Exception as e:
        print(f"ML Error: {e}")
        return "Normal", 0.5

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        ip = data.get("ip", "Unknown")
        
        # 1. Blacklist Check
        if ip in prevention.blocked_ips:
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip, "prediction": "BLOCKED SOURCE", "confidence": 1.0,
                "tactic": "Persistence", "technique": "Blacklisted",
                "description": "IP blocked due to previous malicious activity.",
                "action": "Drop Traffic", "severity": "CRITICAL"
            }
            if not logs_history or logs_history[-1]['ip'] != ip:
                logs_history.append(log_entry)
            return jsonify(log_entry), 403

        # 2. Hybrid Detection
        prediction, confidence = hybrid_detect(data)
        mitre_info = get_mitre(prediction)
        action = prevention.get_action(prediction, ip, confidence)
        severity = prevention.get_severity(prediction, confidence)

        # 3. Final Log
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip, "prediction": prediction, "confidence": confidence,
            "tactic": mitre_info.get("tactic", "Unknown"),
            "technique": mitre_info.get("technique", "Unknown"),
            "description": mitre_info.get("description", ""),
            "action": action, "severity": severity
        }
        logs_history.append(log_entry)

        # 4. Console log for developer
        logger.log_alert(ip, prediction, mitre_info, action, severity, confidence)
        print(f"📡 [IPS] {ip} -> {prediction} ({confidence:.2f}) | Action: {action}")

        return jsonify(log_entry)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/logs', methods=['GET'])
def get_logs(): return jsonify(logs_history[-100:])

@app.route('/stats', methods=['GET'])
def get_stats():
    stats = {
        "total_attacks": len([l for l in logs_history if l['prediction'] not in ['Normal', 'BLOCKED SOURCE']]),
        "severity_counts": {"CRITICAL": 0, "High": 0, "Medium": 0, "Low": 0},
        "attack_types": {}
    }
    for l in logs_history:
        s = l['severity']
        if s in stats["severity_counts"]: stats["severity_counts"][s]+=1
        p = l['prediction']
        stats["attack_types"][p] = stats["attack_types"].get(p, 0) + 1
    return jsonify(stats)

@app.route('/blocked', methods=['GET'])
def get_blocked(): return jsonify(list(prevention.blocked_ips))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)