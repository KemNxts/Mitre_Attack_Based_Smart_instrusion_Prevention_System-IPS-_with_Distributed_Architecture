import streamlit as st
import requests
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# IPS Server URL
BASE_URL = "http://127.0.0.1:5000"

st.set_page_config(
    page_title="Smart IPS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for glassmorphism and premium feel
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stMetric {
        background: rgba(255, 255, 255, 0.05);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .severity-critical { color: #ff4b4b; font-weight: bold; }
    .severity-high { color: #ff8b4b; font-weight: bold; }
    .severity-medium { color: #ffeb3b; font-weight: bold; }
    .severity-low { color: #4caf50; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Smart Intrusion Prevention System")
st.markdown("### MITRE ATT&CK-Based Real-Time Monitoring & Detection")

# Sidebar
st.sidebar.header("🕹️ Control Panel")
refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", 1, 10, 2)
auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)

if st.sidebar.button("Clear Logs"):
    # Placeholder for clearing logs if implemented on server
    pass

# Helper functions
def fetch_data(endpoint):
    try:
        response = requests.get(f"{BASE_URL}/{endpoint}", timeout=2) # Increased timeout
        return response.json() if response.status_code == 200 else []
    except Exception as e:
        # Show specific error in sidebar if fetch fails
        st.sidebar.error(f"⚠️ Fetch Error ({endpoint}): {e}")
        return []

# Dashboard Layout
logs = fetch_data("logs")
stats = fetch_data("stats")
blocked_ips = fetch_data("blocked")

if not logs and not stats:
    st.error("🚨 Dashboard cannot connect to IPS Server. Please ensure 'python server.py' is running.")
    st.stop()

col_stats, col_graph = st.columns([1, 2])

if logs:
    df = pd.DataFrame(logs)
    df = df[::-1] # latest first
    
    with col_stats:
        st.markdown("### 📊 Live Stats")
        if stats:
            m1, m2 = st.columns(2)
            m1.metric("Total Attacks", stats.get("total_attacks", 0), delta_color="inverse")
            m2.metric("Blocked IPs", len(blocked_ips), delta_color="inverse")
            
            # Severity Pie Chart
            sev_data = stats.get("severity_counts", {})
            fig_sev = px.pie(
                values=list(sev_data.values()), 
                names=list(sev_data.keys()),
                title="Severity Distribution",
                color=list(sev_data.keys()),
                color_discrete_map={
                    "CRITICAL": "#ff4b4b", "High": "#ff8b4b", 
                    "Medium": "#ffeb3b", "Low": "#4caf50"
                },
                hole=0.4
            )
            fig_sev.update_layout(height=300, margin=dict(l=0, r=0, b=0, t=40), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="white")
            st.plotly_chart(fig_sev, use_container_width=True)

    with col_graph:
        st.markdown("### 📈 Attack Timeline")
        # Attack types over time (simplified)
        if not df.empty:
            atype_counts = df['prediction'].value_counts().reset_index()
            fig_bar = px.bar(
                atype_counts, x='prediction', y='count', 
                title="Attack Type Frequency",
                color='prediction',
                labels={'prediction': 'Attack Type', 'count': 'Frequency'}
            )
            fig_bar.update_layout(height=380, margin=dict(l=0, r=0, b=0, t=40), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="white")
            st.plotly_chart(fig_bar, use_container_width=True)

    # Latest Alert Row
    st.markdown("---")
    st.markdown("### 🚨 Active Threats & Latest Alerts")
    
    latest_alerts = df[df['prediction'] != 'Normal'].head(5)
    if not latest_alerts.empty:
        for idx, alert in latest_alerts.iterrows():
            with st.expander(f"🔴 {alert['severity']} Alert: {alert['prediction']} from {alert['ip']} ({alert['timestamp']})"):
                c1, c2, c3 = st.columns(3)
                c1.write(f"**Technique:** {alert['technique']}")
                c2.write(f"**Confidence:** {alert['confidence']:.2f}")
                c3.write(f"**Action Taken:** {alert['action']}")
                st.info(f"**MITRE Description:** {alert['description']}")
    else:
        st.success("No active threats detected.")

    # Full Logs Table
    st.markdown("### 📜 Comprehensive Logs")
    
    # Conditional coloring for severity in dataframe
    def color_severity(val):
        color = 'white'
        if val == 'CRITICAL': color = '#ff4b4b'
        elif val == 'High': color = '#ff8b4b'
        elif val == 'Medium': color = '#ffeb3b'
        elif val == 'Low': color = '#4caf50'
        return f'color: {color}'

    st.dataframe(
        df.style.map(color_severity, subset=['severity']),
        use_container_width=True,
        hide_index=True
    )

else:
    st.info("🛰️ Waiting for traffic data...")

# Blocked IPs Card
with st.sidebar:
    st.markdown("---")
    st.markdown("### 🚫 Blacklisted IPs")
    if blocked_ips:
        for ip in blocked_ips:
            st.error(f"IP: {ip}")
    else:
        st.write("No IPs currently blocked.")

# Auto-refresh logic
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()