import streamlit as st
import requests
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# IPS Server URL (Now acting as API Gateway for HIDS logs)
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
    .main { background-color: #0e1117; }
    .stMetric {
        background: rgba(255, 255, 255, 0.05);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    .severity-CRITICAL { color: #ff4b4b; font-weight: bold; }
    .severity-HIGH { color: #ff8b4b; font-weight: bold; }
    .severity-MEDIUM { color: #ffeb3b; font-weight: bold; }
    .severity-LOW { color: #4caf50; font-weight: bold; }
    .stTabs [data-baseweb="tab-list"] { gap: 20px; }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
        font-weight: 600;
        font-size: 18px;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Smart Host-Based IPS Dashboard")
st.markdown("### MITRE ATT&CK-Based Real-Time Monitoring & Detection")

# Sidebar
st.sidebar.header("🕹️ Control Panel")
refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", 1, 10, 2)
auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)

# Helper functions
if 'http_session' not in st.session_state:
    st.session_state.http_session = requests.Session()

def fetch_data(endpoint):
    try:
        response = st.session_state.http_session.get(f"{BASE_URL}/{endpoint}", timeout=2)
        return response.json() if response.status_code == 200 else []
    except Exception as e:
        st.sidebar.error(f"⚠️ Fetch Error ({endpoint}): {e}")
        return []
    
def fetch_system_stats():
    try:
        response = st.session_state.http_session.get(f"{BASE_URL}/system_stats", timeout=2)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        return None

# Dashboard Layout
logs = fetch_data("logs")
stats = fetch_data("stats")
blocked_items = fetch_data("blocked")
system_stats = fetch_system_stats()

if not logs and not stats and not system_stats:
    st.error("🚨 Dashboard cannot connect to API Gateway. Please ensure 'python server.py' is running.")
    st.stop()

# TABS
tab1, tab2 = st.tabs(["💻 Host IPS (Event Logs)", "📊 System Resource Monitor"])

with tab1:
    col_stats, col_graph = st.columns([1, 2])
    
    if logs:
        df = pd.DataFrame(logs)
        
        with col_stats:
            st.markdown("### 📊 Live Stats")
            if stats:
                m1, m2 = st.columns(2)
                m1.metric("Total Events", stats.get("total_attacks", 0), delta_color="inverse")
                m2.metric("Mitigated Threats", stats.get("blocked", 0), delta_color="inverse")
                
                # Severity Pie Chart
                sev_data = stats.get("severity_counts", {})
                fig_sev = px.pie(
                    values=list(sev_data.values()), 
                    names=list(sev_data.keys()),
                    title="Severity Distribution",
                    color=list(sev_data.keys()),
                    color_discrete_map={
                        "CRITICAL": "#ff4b4b", "HIGH": "#ff8b4b", 
                        "MEDIUM": "#ffeb3b", "LOW": "#4caf50"
                    },
                    hole=0.4
                )
                fig_sev.update_layout(height=300, margin=dict(l=0, r=0, b=0, t=40), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="white")
                st.plotly_chart(fig_sev, use_container_width=True)

        with col_graph:
            st.markdown("### 📈 Attack Timeline")
            if not df.empty and 'attack_name' in df.columns:
                atype_counts = df['attack_name'].value_counts().reset_index()
                fig_bar = px.bar(
                    atype_counts, x='attack_name', y='count', 
                    title="Attack Type Frequency",
                    color='attack_name',
                    labels={'attack_name': 'Attack Type', 'count': 'Frequency'}
                )
                fig_bar.update_layout(height=380, margin=dict(l=0, r=0, b=0, t=40), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="white")
                st.plotly_chart(fig_bar, use_container_width=True)

        # Latest Alert Row
        st.markdown("---")
        st.markdown("### 🚨 Active Threats & Latest Alerts")
        
        # Display the 5 most recent alerts
        latest_alerts = df.head(5)
        if not latest_alerts.empty:
            for idx, alert in latest_alerts.iterrows():
                icon = "🔴" if alert.get('action') == 'PREVENTED' else "🟡"
                with st.expander(f"{icon} {alert.get('severity', 'UNKNOWN')} Alert: {alert.get('attack_name', 'Unknown')} ({alert.get('timestamp', 'Unknown')})"):
                    c1, c2, c3, c4 = st.columns(4)
                    c1.write(f"**MITRE Tactic:** {alert.get('mitre_tactic', 'Unknown')}")
                    c2.write(f"**MITRE ID:** {alert.get('mitre_id', 'Unknown')}")
                    c3.write(f"**Occurrence:** {alert.get('occurrence', 1)}")
                    c4.write(f"**Action Taken:** {alert.get('action', 'Unknown')}")
                    st.info(f"**Details:** {alert.get('details', '')}")
        else:
            st.success("No active threats detected.")

        # Full Logs Table
        st.markdown("### 📜 Comprehensive Logs")
        
        def color_severity(val):
            color = 'white'
            if val == 'CRITICAL': color = '#ff4b4b'
            elif val == 'HIGH': color = '#ff8b4b'
            elif val == 'MEDIUM': color = '#ffeb3b'
            elif val == 'LOW': color = '#4caf50'
            return f'color: {color}'

        if 'severity' in df.columns:
            st.dataframe(
                df.style.map(color_severity, subset=['severity']),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)

    else:
        st.info("🛰️ Waiting for HIDS telemetry data...")

with tab2:
    st.markdown("### 💻 System Resource Monitor (HIDS)")
    if system_stats:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("CPU Usage", f"{system_stats['cpu_percent']}%")
        
        # RAM Visuals
        ram_pct = system_stats['ram_percent']
        c2.metric("RAM Usage", f"{ram_pct}%")
        c3.metric("RAM Used", f"{system_stats['ram_used_gb']} GB")
        c4.metric("RAM Total", f"{system_stats['ram_total_gb']} GB")
        
        st.markdown("#### 🚀 Top Memory-Consuming Processes")
        st.markdown("*(Real-time equivalent of htop)*")
        
        if ram_pct > 85.0:
            st.error(f"🚨 RESOURCE EXHAUSTION DETECTED! RAM at {ram_pct}%")
        
        procs = system_stats.get('top_processes', [])
        if procs:
            proc_df = pd.DataFrame(procs)
            proc_df = proc_df[['pid', 'user', 'cpu', 'mem', 'cmd']]
            proc_df.columns = ['PID', 'USER', 'CPU %', 'MEM %', 'COMMAND']
            
            st.dataframe(
                proc_df.style.background_gradient(cmap='Reds', subset=['MEM %', 'CPU %']),
                use_container_width=True,
                hide_index=True,
                height=500
            )
    else:
        st.warning("⚠️ System stats not available. Ensure server.py is running with psutil installed.")

# Blocked Items Card
with st.sidebar:
    st.markdown("---")
    st.markdown("### 🚫 Recent Mitigations")
    if blocked_items:
        for item in blocked_items:
            st.success(f"✅ {item}")
    else:
        st.write("No active preventions.")

if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()