# Smart IPS: MITRE ATT&CK-Based Intrusion Prevention System

### 🛡️ Secure. Intelligent. Distributed.
A professional-grade cybersecurity platform that implements a **Smart Host-Based Intrusion Detection and Prevention System (HIDS/IPS)** mapped against the **MITRE ATT&CK Framework**.

---

## 🚀 Key Features

### 🧠 Biological OS Telemetry Detection
- **Hybrid Behavioral Engine**: Uses real OS-level signals (process trees, memory usage, configuration files, and `psutil` telemetry) rather than simulated network traffic.
- **Threat Memory**: Stateful detection that logs suspicious behavior on the first occurrence and actively prevents it on the second occurrence.
- **Surgical Prevention**: Uses precise OS commands (e.g., `pkill` on process trees, safely rewriting `crontab`, or deleting malicious systemd files) without destroying legitimate system operations.

### 🎯 7 Canonical MITRE ATT&CK Host Behaviors
The system strictly monitors for the following 7 real-world attack techniques:
1. **Parent-Child Memory Eater (T1496)**: Impact / Resource Exhaustion
2. **Cron Persistence (T1053.003)**: Persistence via scheduled tasks
3. **Systemd User Service Persistence (T1543.002)**: Persistence via rogue services
4. **Discovery Burst (T1082 / T1057)**: Rapid recon commands (whoami, id, etc.)
5. **Staging / Collection (T1074.001)**: Rapid compression of data in `/tmp`
6. **Process Masquerading (T1036.005)**: Deceptive process names running from user directories
7. **Shell RC Persistence (T1546.004)**: Malicious modifications to `.bashrc` or `.zshrc`

### 📊 Real-Time Analytics Dashboard
- **Plotly Visualizations**: Dynamic charts for severity distribution and attack frequency.
- **API Gateway**: A lightweight Flask server that serves real HIDS `event_log.json` telemetry to the dashboard.
- **Modern UI**: Dark-mode glassmorphism theme with instant state updates.

---

## 🚦 Execution Guide

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Launch the Environment
The environment expects a 2-machine testing architecture: an external **Kali Linux attacker** and the protected **Ubuntu Target**.

On the Ubuntu Target, open two terminals and run:

```bash
# Terminal 1: Smart HIDS Engine & API Gateway
python server.py &
python run_hybrid.py

# Terminal 2: Smart Monitoring Dashboard
streamlit run app.py
```

### 3. Attack the Target
From a separate Kali Linux machine, SSH into the Ubuntu target and execute real OS behaviors (e.g., creating a rogue cron job, or running a memory exhaustion script). The HIDS will detect the behavior, map it to MITRE, and the Dashboard will visualize the alert and mitigation.

---

## 📁 File Structure

```text
├── hids/                 # Core Host-Based Intrusion Detection Engine
│   ├── behavioral/       # Hybrid detection logic and OS telemetry collectors
│   ├── response_engine.py# Surgical prevention scripts
│   ├── event_logger.py   # JSON logging for Threat Memory
│   └── data/             # Persistent event logs
├── server.py             # Lightweight API Gateway for the Dashboard (Port 5000)
├── app.py                # Streamlit UI Dashboard (Port 8501)
├── run_hybrid.py         # Entrypoint for the HIDS Engine
└── mitre.py              # ATT&CK Framework Mappings
```

---

## ⚠️ Laboratory Architecture
This system is intended for **research and educational purposes only**. Testing should be performed using an external attacker machine (e.g., Kali Linux) targeting the protected Ubuntu system running this software. Do not run the HIDS on production systems without fully understanding the surgical prevention commands (`pkill`, `os.remove`, etc.) it may execute automatically.