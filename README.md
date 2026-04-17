# Smart IPS: MITRE ATT&CK-Based Intrusion Prevention System

### 🛡️ Secure. Intelligent. Distributed.
A professional-grade cybersecurity platform that implements a **Smart Intrusion Prevention System (IPS)** using a high-performance hybrid detection engine (Machine Learning + Rule-Based) mapped against the **MITRE ATT&CK Framework**.

---

## 🚀 Key Features

### 🧠 Advanced Hybrid Detection
- **Random Forest ML Engine**: Sub-millisecond traffic classification using pre-loaded in-memory models and scalers.
- **Strategic Rule Layer**: Immediate, high-precision detection for known malicious signatures (Brute Force, DoS, SQLi).
- **Adaptive Mitigation**: Automated "Drop Traffic", "Account Lockout", and "IP Quarantine" responses.

### 🎮 Web-Based Attacker Control Panel (V2)
- **Dynamic Targeting**: Specify any local network target (e.g., `192.168.x.x`) directly from the UI.
- **Security Validation**: Built-in dual-layer IP filtering to ensure simulations stay within safe network boundaries (`localhost`, `127.0.0.1`, `192.168.0.0/16`).
- **Process Management**: Real-time monitoring and termination of background attack scripts.

### 🎯 MITRE ATT&CK Mapping
Every detection is automatically mapped to professional tactics and techniques:
- **T1110 (Brute Force)**: Credential Access
- **T1499 (DoS)**: Impact
- **T1046 (Network Service Discovery)**: Reconnaissance
- **T1059 (Bot/Scripting)**: Execution
- **T1190 (Web/Initial Access)**: Vulnerability exploitation

### 📊 Real-Time Analytics Dashboard
- **Plotly Visualizations**: Dynamic charts for severity distribution and attack frequency.
- **Persistence Monitoring**: Tracks blocked sources even after high-severity intervention.
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
2. Enter your **Target IP** (e.g., `127.0.0.1` or `192.168.1.10`).
3. Click **Launch Attack** on any vector.

---

## 🔍 Attack Vector Mechanics

| Vector | Script | Mitigation Logic |
| :--- | :--- | :--- |
| **Brute Force** | `bruteforce_attacker.py` | 5s lockout after 5 fails |
| **DoS Flood** | `dos_attacker.py` | Rate-limiting & Socket drop |
| **Port Scan** | `port_scan_attacker.py` | Source port closure |
| **Web Attack** | `web_attacker.py` | WAF-style payload filtering |
| **Botnet** | `bot_attacker.py` | Source quarantine |

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
└── [Attacker Scripts]    # Dynamic Localized Threat Simulators
```

---

## ⚠️ Safety Disclaimer
This system is intended for **research and educational purposes only**. All simulations are strictly restricted to local and private ranges (`127.0.0.1`, `localhost`, `192.168.x.x`). The Attacker UI will reject any attempts to target external or public IP addresses for security reasons.