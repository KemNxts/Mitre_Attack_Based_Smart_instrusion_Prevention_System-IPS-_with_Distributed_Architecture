# Smart IPS: MITRE ATT&CK-Based Intrusion Prevention System

### 🛡️ Secure. Intelligent. Distributed.
A professional-grade cybersecurity platform that implements a **Smart Intrusion Prevention System (IPS)** using a high-performance hybrid detection engine (Machine Learning + Rule-Based) mapped against the **MITRE ATT&CK Framework**.

---

## 🚀 Key Features

### 🧠 Advanced Hybrid Detection
- **Random Forest ML Engine**: Sub-millisecond traffic classification using pre-loaded in-memory models and scalers.
- **Strategic Rule Layer**: Immediate, high-precision detection for known malicious signatures (Brute Force, DoS, SQLi).
- **Adaptive Mitigation**: Automated "Drop Traffic", "Account Lockout", and "IP Quarantine" responses.

### 🎮 Web-Based Attacker Control Panel (V3 Bot-Enabled)
- **Bot Mode (Multi-IP Simulation)**: Simulate distributed attacks (DDoS) from up to 50 unique virtual sources (`192.168.1.x`) simultaneously.
- **Threaded Execution**: High-volume, concurrent attack vectors using Python-native threading for realistic stress-testing.
- **Dynamic Targeting**: Specify any local network target (e.g., `192.168.x.x`) directly from the UI.
- **Security Validation**: Built-in dual-layer IP filtering to ensure simulations stay within safe network boundaries.

### 🎯 MITRE ATT&CK Mapping
Every detection is automatically mapped to professional tactics and techniques:
- **T1110 (Brute Force)**: Credential Access
- **T1499 (DoS)**: Impact
- **T1046 (Network Service Discovery)**: Reconnaissance
- **T1059 (Bot/Scripting)**: Execution
- **T1190 (Web/Initial Access)**: Vulnerability exploitation

### 📊 Real-Time Analytics Dashboard
- **Plotly Visualizations**: Dynamic charts for severity distribution and attack frequency.
- **Identity Tracking**: Monitor dozens of attacking IPs in real-time as the botnet scales.
- **Modern UI**: Dark-mode glassmorphism theme with instant state updates.

---

## 🚦 Execution Guide

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Launch the Environment (3 Terminals)
Open three terminals/tabs and run:

```bash
# Terminal 1: IPS Detection Server
python server.py

# Terminal 2: Target Vulnerable App
python login_server.py

# Terminal 3: Smart Monitoring Dashboard
streamlit run app.py
```

### 3. Launch the Attacker UI
Open a fourth terminal to access the central attack controller:
```bash
python attacker_ui.py
```
1. Visit `http://127.0.0.1:7000`.
2. Configure your **Target IP**.
3. Enable **Bot Mode** and set the number of virtual attackers.
4. Click **Launch Attack** on any vector.

---

## 🔍 Attack Vector Mechanics

| Vector | Script | Bot Mode Logic |
| :--- | :--- | :--- |
| **DoS Flood** | `dos_attacker.py` | Threaded multi-source flooding |
| **Botnet** | `bot_attacker.py` | Concurrent multi-IP persistent traffic |
| **Port Scan** | `port_scan_attacker.py` | IP identity rotation per port probe |
| **Web Attack** | `web_attacker.py` | Distributed SQLi payloads |
| **Brute Force** | `bruteforce_attacker.py` | Sequential single-source (Realism) |

---

## 📁 File Structure

```text
├── server.py             # Optimized IPS Engine (Port 5000)
├── app.py                # Streamlit Dashboard (Port 8501)
├── attacker_ui.py        # Web Control Panel (Port 7000)
├── login_server.py       # Vulnerable Simulation Target (Port 6000)
├── model.py              # ML Training & Synthetic Data Logic
├── mitre.py              # ATT&CK Framework Mappings
├── prevention.py         # Advanced Mitigation Rules
├── preprocess.py         # Feature Scaling & Encoding
└── [Attacker Scripts]    # Threaded multi-IP threat simulators
```

---

## ⚠️ Safety Disclaimer
This system is intended for **research and educational purposes only**. The Attacker UI strictly enforces local network boundaries and will only simulate traffic against private IP ranges (`127.0.0.1`, `localhost`, `192.168.x.x`). Internal IP generation is purely virtual and does not involve real packet spoofing at the network level.