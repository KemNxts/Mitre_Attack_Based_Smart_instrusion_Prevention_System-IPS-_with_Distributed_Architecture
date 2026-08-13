# Production Deployment Guide

This directory contains the `systemd` `.service` templates required to daemonize the HIDS across system reboots.

## 1. Prerequisites
1. Copy the entire repository to `/opt/hids` (or update the `WorkingDirectory` and `ExecStart` paths in the `.service` files to match your clone location).
2. Create a virtual environment and install the optimized requirements:
   ```bash
   cd /opt/hids
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## 2. Configuration
Before installing the services, verify the `User` and `Environment=SUDO_USER` fields in the templates. 
- In `hids-engine.service`, `SUDO_USER=root` is set. Change this to the primary human user (e.g., `khushal`) so the HIDS knows whose home directory to monitor, even though the engine runs as `root`.
- In `hids-api.service` and `hids-dashboard.service`, change `User=root` to your primary unprivileged user (e.g., `khushal`).

## 3. Installation
Copy the service files to the systemd directory:

```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## 4. Enable and Start
Enable the services to start automatically on boot:

```bash
sudo systemctl enable hids-engine.service
sudo systemctl enable hids-api.service
sudo systemctl enable hids-dashboard.service

sudo systemctl start hids-engine.service
sudo systemctl start hids-api.service
sudo systemctl start hids-dashboard.service
```

## 5. Verification
Check the status of the services:

```bash
sudo systemctl status hids-engine.service
sudo systemctl status hids-api.service
sudo systemctl status hids-dashboard.service
```

The Streamlit dashboard will now be permanently available at `http://<your-server-ip>:8501`.
