from flask import Flask, request, jsonify

app = Flask(__name__)

# Dummy credentials
USERNAME = "admin"
PASSWORD = "password123"

# Track failed attempts
failed_attempts = {}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    ip = data.get("ip", "unknown")
    username = data.get("username")
    password = data.get("password")

    if username == USERNAME and password == PASSWORD:
        failed_attempts[ip] = 0
        return jsonify({"status": "success", "message": "Login successful"})

    else:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        return jsonify({
            "status": "fail",
            "message": "Invalid credentials",
            "failed_attempts": failed_attempts[ip]
        })

if __name__ == '__main__':
    print("🔐 Login Server Running on http://127.0.0.1:6000")
    app.run(port=6000)