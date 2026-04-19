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

prevention = IPSPrevention()
logger = IPSLogger()
preprocessor = IPSPreprocessor()

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

limiter = Limiter(get_remote_address, app=app, default_limits=["5000 per hour"], storage_uri="memory://")

logs_history = []

# ---------------- DETECTION ---------------- #
def hybrid_detect(data, ip_state):
    rate = data.get("request_rate", 0)
    failed = data.get("failed_logins", 0)
    size = data.get("packet_size", 0)
    protocol = data.get("protocol", "")

    now = datetime.now().timestamp()

    # ---------------- EXISTING RULES ---------------- #
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

    # ---------------- ADAPTIVE BOT DETECTION ---------------- #

    # Track timestamps
    ip_state["recent_timestamps"].append(now)
    ip_state["recent_timestamps"] = [t for t in ip_state["recent_timestamps"] if now - t <= 10]

    window_rate = len(ip_state["recent_timestamps"]) / 10.0

    # Track endpoints
    endpoint = data.get("endpoint", "unknown")
    ip_state["endpoints"].add(endpoint)

    # Track timing
    ip_state["last_times"].append(now)
    ip_state["last_times"] = ip_state["last_times"][-10:]

    gaps = []
    if len(ip_state["last_times"]) > 1:
        gaps = [
            ip_state["last_times"][i] - ip_state["last_times"][i - 1]
            for i in range(1, len(ip_state["last_times"]))
        ]

    # 🔥 Strong Bot Detection

    # 1. Sustained activity
    if 2 <= window_rate <= 12:
        if len(ip_state["recent_timestamps"]) >= 8:
            return "Bot", 0.82

    # 2. Endpoint diversity
    if len(ip_state["endpoints"]) >= 2 and window_rate > 2:
        return "Bot", 0.80

    # 3. Timing pattern (relaxed)
    if len(gaps) >= 5:
        avg = sum(gaps) / len(gaps)
        var = sum((g - avg) ** 2 for g in gaps) / len(gaps)

        if var < 0.1 and 2 <= window_rate <= 10:
            return "Bot", 0.78

    # 4. Persistence rule
    if ip_state["attempts"] >= 3 and window_rate > 2:
        return "Bot", 0.85

    # ---------------- ML FALLBACK ---------------- #
    try:
        X_scaled = preprocessor.preprocess(data)
        prediction = GLOBAL_MODEL.predict(X_scaled)[0]
        probs = GLOBAL_MODEL.predict_proba(X_scaled)[0]
        confidence = float(max(probs))
        return prediction, confidence
    except:
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
                "block_reason": None,
                "recent_timestamps": [],
                "endpoints": set(),
                "last_times": []
            }

        ip_state = ip_data[ip]
        time_diff = now - ip_state["last_seen"]

        if time_diff > 60:
            ip_state["score"] *= 0.5
            ip_state["attempts"] = max(1, ip_state["attempts"] - 1)

        prediction, confidence = hybrid_detect(data, ip_state)

        # ---------------- BLOCK HANDLING ---------------- #
        if ip_state["blocked"]:
            ip_state["last_seen"] = now

            mitre_info = get_mitre(prediction)

            logs_history.append({
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
                "action": f"Blocked ({prediction}) | Initial Block: {ip_state.get('block_reason', 'Unknown')}",
                "severity": prevention.get_severity(prediction, confidence)
            })

            return jsonify({
                "prediction": prediction,
                "status": "blocked",
                "score": int(ip_state["score"]),
                "attempts": ip_state["attempts"],
                "confidence": float(confidence)
            }), 403

        # ---------------- SCORING ---------------- #
        score_increment = 0

        if prediction != "Normal":
            if prediction == "Web Attack":
                score_increment += 25
            elif prediction == "Bot":
                score_increment += 12
            else:
                score_increment += 15

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

        logs_history.append({
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
        })

        return jsonify({
            "prediction": prediction,
            "status": status,
            "score": int(ip_state["score"]),
            "attempts": ip_state["attempts"],
            "confidence": float(confidence)
        }), 403 if status == "blocked" else 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


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

    return jsonify(stats)


@app.route('/blocked', methods=['GET'])
def get_blocked():
    return jsonify(list(prevention.blocked_ips))


if __name__ == '__main__':
    print("🚀 IPS Server Running on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)