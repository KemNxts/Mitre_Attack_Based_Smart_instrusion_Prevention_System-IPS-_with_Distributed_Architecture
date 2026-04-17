from flask import Flask, request, jsonify
import os
from datetime import datetime

from model import get_prediction, train_model
from mitre import get_mitre
from prevention import IPSPrevention
from logger import IPSLogger

app = Flask(__name__)

# Initialize components
prevention = IPSPrevention()
logger = IPSLogger()

logs_history = []
blocked_ips = []

# -------------------------------
# PREDICT ENDPOINT
# -------------------------------
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data received"}), 400

        # Extract features correctly
        features = {
            "request_rate": data.get("request_rate", 0),
            "failed_logins": data.get("failed_logins", 0),
            "packet_size": data.get("packet_size", 0),
            "duration": data.get("duration", 0),
            "protocol": data.get("protocol", "TCP")
        }

        ip = data.get("ip", "Unknown")
        simulated_type = data.get("attack_type", "Unknown")

        # ML Prediction
        prediction = get_prediction(features)

        # MITRE Mapping
        mitre_info = get_mitre(prediction)

        # Prevention Action
        action = prevention.get_action(prediction, ip)
        severity = prevention.get_severity(prediction)

        # Create log entry
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "prediction": prediction,
            "simulated_type": simulated_type,
            "tactic": mitre_info.get("tactic", "Unknown"),
            "technique": mitre_info.get("technique", "Unknown"),
            "action": action,
            "severity": severity
        }

        logs_history.append(log_entry)

        # Track blocked IPs
        if action == "Block IP":
            blocked_ips.append(ip)

        # Logging to files
        logger.log_alert(ip, prediction, mitre_info, action)
        logger.log_system(f"Prediction: {prediction} from {ip}")

        return jsonify(log_entry)

    except Exception as e:
        print("❌ ERROR in /predict:", e)
        return jsonify({"error": str(e)}), 500


# -------------------------------
# GET LOGS
# -------------------------------
@app.route('/logs', methods=['GET'])
def get_logs():
    return jsonify(logs_history[-50:])


# -------------------------------
# GET BLOCKED IPS
# -------------------------------
@app.route('/blocked', methods=['GET'])
def get_blocked():
    return jsonify(list(set(blocked_ips)))


# -------------------------------
# MAIN ENTRY POINT
# -------------------------------
if __name__ == '__main__':
    print("🚀 Starting IPS Server...")

    # Ensure model exists
    if not os.path.exists('models/ips_model.joblib'):
        print("📊 Training model...")
        train_model()

    print("✅ Server running at http://127.0.0.1:5000")

    app.run(host='127.0.0.1', port=5000, debug=True)