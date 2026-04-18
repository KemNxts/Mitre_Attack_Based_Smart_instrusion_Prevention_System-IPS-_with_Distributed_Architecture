from flask import Flask, request, jsonify
import time

app = Flask(__name__)

# Dummy credentials
USERNAME = "admin"
PASSWORD = "password123"

# Track failed attempts and lockout time
failed_attempts = {}
lockout_time = {}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    ip = data.get("ip", "unknown")
    username = data.get("username")
    password = data.get("password")

    # Check if locked
    if ip in lockout_time and time.time() < lockout_time[ip]:
        return jsonify({
            "status": "locked",
            "message": f"Account locked. Try again in {int(lockout_time[ip] - time.time())} seconds"
        }), 403

    if username == USERNAME and password == PASSWORD:
        failed_attempts[ip] = 0
        return jsonify({"status": "success", "message": "Login successful"})

    else:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        
        if failed_attempts[ip] >= 5:
            lockout_time[ip] = time.time() + 30  # 30 second lockout
            return jsonify({
                "status": "locked",
                "message": "Account locked due to too many failed attempts",
                "failed_attempts": failed_attempts[ip]
            }), 403

        return jsonify({
            "status": "fail",
            "message": "Invalid credentials",
            "failed_attempts": failed_attempts[ip]
        })


@app.route('/search', methods=['POST'])
def search():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "JSON body required"}), 400
    
    query = data.get('query', '')
    ip = data.get('ip', 'unknown')
    
    q = query.upper()

    # --- Graded SQLi Detection ---
    suspicious_score = 0

    if "' OR" in q:
        suspicious_score += 2
    if "--" in q:
        suspicious_score += 1
    if "UNION" in q:
        suspicious_score += 2
    if "DROP" in q:
        suspicious_score += 3

    # --- Decision Logic ---
    if suspicious_score >= 3:
        status = "suspicious"
    elif suspicious_score > 0:
        status = "low_suspicion"
    else:
        status = "ok"

    return jsonify({
        "status": status,
        "message": f"Processed query: {query}",
        "score": suspicious_score,
        "ip": ip
    }), 200


if __name__ == '__main__':
    print("Login Server Running on http://127.0.0.1:6000")
    print("Search Endpoint: http://127.0.0.1:6000/search")
    app.run(host='127.0.0.1', port=6000)