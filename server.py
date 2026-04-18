from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import joblib
from datetime import datetime

from model import train_model
from mitre import get_mitre
from prevention import IPSPrevention
from logger import IPSLogger
from preprocess import IPSPreprocessor

app = Flask(__name__)

# Components
prevention = IPSPrevention()
logger = IPSLogger()
preprocessor = IPSPreprocessor()

# ML Model
GLOBAL_MODEL = None
print("Loading ML Protection Engine...")

def init_ml():
    global GLOBAL_MODEL
    model_path = os.path.join('models', 'ips_model.joblib')
    if not os.path.exists(model_path):
        train_model()
    GLOBAL_MODEL = joblib.load(model_path)
    print("ML Engine Active.")

init_ml()

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5000 per hour"],
    storage_uri="memory://",
)

logs_history = []

# ---------------- DETECTION ---------------- #
def hybrid_detect(data):
    rate = data.get("request_rate", 0)
    failed = data.get("failed_logins", 0)
    size = data.get("packet_size", 0)
    protocol = data.get("protocol", "")

    if failed >= 2:
        return "Brute Force", 0.95
    if rate >= 1200:
        return "DoS", 0.95
    if protocol == "HTTP" and data.get("attack_type") == "Web Attack":
        if rate > 20 or size > 1200:
            return "Web Attack", 0.85
    if size >= 1800 and protocol == "HTTP":
        return "Web Attack", 0.80
    if rate >= 100 and size <= 100:
        return "Port Scan", 0.85
    if 400 <= rate <= 800 and size >= 500:
        return "Bot", 0.80

    try:
        X_scaled = preprocessor.preprocess(data)
        prediction = GLOBAL_MODEL.predict(X_scaled)[0]
        probs = GLOBAL_MODEL.predict_proba(X_scaled)[0]
        confidence = float(max(probs))
        return prediction, confidence
    except Exception:
        return "Normal", 0.5


# ---------------- STATE ---------------- #
ip_data = {}


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        ip = data.get("ip", "Unknown")
        now = datetime.now().timestamp()

        if ip not in ip_data:
            ip_data[ip] = {
                "score": 0,
                "attempts": 0,
                "last_seen": now,
                "blocked": False,
                "block_reason": None
            }

        ip_state = ip_data[ip]
        time_diff = now - ip_state["last_seen"]

        # Cooldown
        if time_diff > 60:
            ip_state["score"] *= 0.5
            ip_state["attempts"] = max(1, ip_state["attempts"] - 1)

        prediction, confidence = hybrid_detect(data)

        # ---------------- BLOCK HANDLING ---------------- #
        if ip_state["blocked"]:
            ip_state["last_seen"] = now

            mitre_info = get_mitre(prediction)

            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "prediction": prediction,
                "confidence": float(confidence),
                "status": "blocked",
                "score": int(ip_state["score"]),
                "attempts": ip_state["attempts"],
                "tactic": mitre_info.get("tactic", "Unknown"),
                "technique": mitre_info.get("technique", "Unknown"),
                "description": mitre_info.get("description", ""),
                # ✅ FIXED ACTION LINE ONLY
                "action": f"Blocked ({prediction}) | Initial Block: {ip_state.get('block_reason', 'Unknown')}",
                "severity": prevention.get_severity(prediction, confidence)
            }

            logs_history.append(log_entry)

            return jsonify({
                "prediction": prediction,
                "status": "blocked",
                "score": int(ip_state["score"]),
                "attempts": ip_state["attempts"],
                "confidence": float(confidence),
                "block_reason": ip_state.get("block_reason")
            }), 403

        # ---------------- SCORING ---------------- #
        score_increment = 0

        if prediction != "Normal":
            score_increment += 25 if prediction == "Web Attack" else 15
            score_increment += 10

            if time_diff < 1:
                score_increment += 10

            ip_state["attempts"] += 1

            if ip_state["attempts"] > 1:
                ip_state["score"] += score_increment

        # ---------------- STATUS ---------------- #
        status = "allowed"

        if ip_state["attempts"] >= 4 and ip_state["score"] >= 120:
            status = "blocked"
            ip_state["blocked"] = True
            ip_state["block_reason"] = prediction
            prevention.enforce_block(ip)

        elif ip_state["attempts"] >= 2:
            status = "suspicious"

        ip_state["last_seen"] = now

        # ---------------- LOGGING ---------------- #
        mitre_info = get_mitre(prediction)
        action = prevention.get_action(prediction, ip, confidence, status)
        severity = prevention.get_severity(prediction, confidence)

        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "prediction": prediction,
            "confidence": float(confidence),
            "status": status,
            "score": int(ip_state["score"]),
            "attempts": ip_state["attempts"],
            "tactic": mitre_info.get("tactic", "Unknown"),
            "technique": mitre_info.get("technique", "Unknown"),
            "description": mitre_info.get("description", ""),
            "action": action,
            "severity": severity
        }

        logs_history.append(log_entry)

        return jsonify({
            "prediction": prediction,
            "status": status,
            "score": int(ip_state["score"]),
            "attempts": ip_state["attempts"],
            "confidence": float(confidence
        )}), 403 if status == "blocked" else 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- ROUTES ---------------- #

@app.route('/logs', methods=['GET'])
def get_logs():
    return jsonify(logs_history[-100:])


@app.route('/stats', methods=['GET'])
def get_stats():
    stats = {
        "total_attacks": len([l for l in logs_history if l['prediction'] != 'Normal']),
        "blocked": len([l for l in logs_history if l['status'] == 'blocked']),
        "severity_counts": {"CRITICAL": 0, "High": 0, "Medium": 0, "Low": 0},
        "attack_types": {}
    }

    for l in logs_history:
        stats["severity_counts"][l['severity']] += 1
        stats["attack_types"][l['prediction']] = stats["attack_types"].get(l['prediction'], 0) + 1

    recent_logs = logs_history[-60:]
    unique_ips = set(l["ip"] for l in recent_logs)

    ip_count = len(unique_ips)

    if ip_count == 0:
        attack_mode = "No Activity"
    elif ip_count == 1:
        attack_mode = "Single Attacker"
    elif ip_count >= 5:
        attack_mode = "Distributed Attack"
    else:
        attack_mode = "Mixed"

    stats["attack_mode"] = attack_mode
    stats["unique_ips"] = ip_count

    return jsonify(stats)


@app.route('/blocked', methods=['GET'])
def get_blocked():
    return jsonify(list(prevention.blocked_ips))


# ---------------- RUN ---------------- #

if __name__ == '__main__':
    print("🚀 IPS Server Running on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)