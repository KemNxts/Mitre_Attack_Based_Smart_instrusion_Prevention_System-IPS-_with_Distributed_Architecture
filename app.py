import streamlit as st
import requests
import time
import pandas as pd

# IPS Server URL
BASE_URL = "http://127.0.0.1:5000"

st.set_page_config(page_title="IPS Dashboard", layout="wide")

st.title("🛡️ Smart Intrusion Prevention System")
st.subheader("MITRE ATT&CK-Based Real-Time Monitoring")

# Auto-refresh toggle
refresh = st.sidebar.checkbox("Auto Refresh", value=True)

# Fetch logs from server
def fetch_logs():
    try:
        response = requests.get(f"{BASE_URL}/logs")
        if response.status_code == 200:
            return response.json()
        else:
            return []
    except:
        return []

# Fetch blocked IPs
def fetch_blocked():
    try:
        response = requests.get(f"{BASE_URL}/blocked")
        if response.status_code == 200:
            return response.json()
        else:
            return []
    except:
        return []

# Main dashboard loop
while True:
    logs = fetch_logs()
    blocked_ips = fetch_blocked()

    # Convert logs to DataFrame
    if logs:
        df = pd.DataFrame(logs)
        df = df[::-1]  # latest on top

        # Latest Alert
        st.markdown("### 🚨 Latest Alert")
        latest = df.iloc[0]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Attack", latest.get("prediction", "N/A"))
        col2.metric("IP", latest.get("ip", "N/A"))
        col3.metric("Technique", latest.get("technique", "N/A"))
        col4.metric("Action", latest.get("action", "N/A"))

        # Full Logs
        st.markdown("### 📜 Attack Logs")
        st.dataframe(df, use_container_width=True)

    else:
        st.warning("No logs yet... waiting for traffic")

    # Blocked IPs
    st.markdown("### 🚫 Blocked IPs")
    if blocked_ips:
        st.write(blocked_ips)
    else:
        st.write("No blocked IPs")

    # Auto refresh
    if refresh:
        time.sleep(2)
        st.rerun()
    else:
        break