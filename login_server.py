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

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    # Simulated SQL injection vulnerable endpoint
    if "OR '1'='1'" in query or "UNION SELECT" in query:
        return jsonify({"status": "vulnerable", "message": "SQL Injection pattern detected in search query"}), 200
    return jsonify({"status": "ok", "results": f"Searching for: {query}"}), 200

if __name__ == '__main__':
    print("🔐 Login Server Running on http://127.0.0.1:6000")
    print("🔍 Search Endpoint: http://127.0.0.1:6000/search?q=test")
    app.run(port=6000)