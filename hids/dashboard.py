"""
=============================================================================
  HIDS Live Dashboard  (Streamlit)
  ---------------------------------
  Real-time web dashboard showing:
    • System status + key metrics (KPIs)
    • Live detection event feed
    • Prevention action log with clear success/failure messages
    • Threat memory state
    • MITRE ATT&CK coverage view
    • Attack distribution charts
  
  Runs the HIDS Core in a background thread and auto-refreshes.
=============================================================================
"""

import sys
import os
import time
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root is on sys.path so `hids` package imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hids.core import HIDSCore
from hids.config import ATTACKS, DASHBOARD_REFRESH

# ═══════════════════════════════════════════════════════════════════════════
#  Page Config
# ═══════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="HIDS — Adaptive Intrusion Detection & Prevention",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════════
#  CSS — Premium dark theme with glassmorphism
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
    /* ── Import premium font ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* ── Global ── */
    .stApp {
        background: linear-gradient(135deg, #0a0a1a 0%, #0d1117 40%, #161b22 100%);
        font-family: 'Inter', sans-serif;
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1117 0%, #161b22 100%) !important;
        border-right: 1px solid rgba(88, 166, 255, 0.15);
    }
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown h1,
    section[data-testid="stSidebar"] .stMarkdown h2,
    section[data-testid="stSidebar"] .stMarkdown h3 {
        color: #e6edf3 !important;
    }

    /* ── Headers ── */
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #58a6ff, #7ee8fa, #80ffdb);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
        letter-spacing: -0.5px;
    }
    .main-subtitle {
        color: #8b949e;
        font-size: 1rem;
        font-weight: 400;
        margin-bottom: 1.5rem;
    }

    /* ── KPI Cards ── */
    .kpi-card {
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.9), rgba(13, 17, 23, 0.95));
        border: 1px solid rgba(88, 166, 255, 0.2);
        border-radius: 16px;
        padding: 1.2rem 1.5rem;
        text-align: center;
        backdrop-filter: blur(10px);
        transition: all 0.3s ease;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }
    .kpi-card:hover {
        border-color: rgba(88, 166, 255, 0.5);
        box-shadow: 0 8px 32px rgba(88, 166, 255, 0.15);
        transform: translateY(-2px);
    }
    .kpi-value {
        font-size: 2.5rem;
        font-weight: 800;
        font-family: 'JetBrains Mono', monospace;
        line-height: 1.2;
    }
    .kpi-label {
        color: #8b949e;
        font-size: 0.85rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 0.3rem;
    }

    /* ── Event cards ── */
    .event-card {
        background: rgba(22, 27, 34, 0.8);
        border: 1px solid rgba(88, 166, 255, 0.12);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.8rem;
        backdrop-filter: blur(8px);
        transition: all 0.2s ease;
    }
    .event-card:hover {
        border-color: rgba(88, 166, 255, 0.35);
    }
    .event-card.prevented {
        border-left: 4px solid #3fb950;
    }
    .event-card.detected {
        border-left: 4px solid #d29922;
    }
    .event-card.failed {
        border-left: 4px solid #f85149;
    }

    .event-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.4rem;
    }
    .event-name {
        font-weight: 700;
        font-size: 1rem;
        color: #e6edf3;
    }
    .event-time {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: #8b949e;
    }
    .event-details {
        font-size: 0.85rem;
        color: #8b949e;
        margin-top: 0.2rem;
    }

    /* ── Badges ── */
    .badge {
        display: inline-block;
        padding: 0.15rem 0.6rem;
        border-radius: 20px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .badge-detect   { background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.3); }
    .badge-prevent  { background: rgba(63, 185, 80, 0.2);  color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.3);  }
    .badge-failed   { background: rgba(248, 81, 73, 0.2);  color: #f85149; border: 1px solid rgba(248, 81, 73, 0.3);  }

    .badge-low      { background: rgba(88, 166, 255, 0.15); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.25); }
    .badge-medium   { background: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.25); }
    .badge-high     { background: rgba(248, 81, 73, 0.15);  color: #f85149; border: 1px solid rgba(248, 81, 73, 0.25);  }
    .badge-critical { background: rgba(219, 51, 166, 0.15); color: #db33a6; border: 1px solid rgba(219, 51, 166, 0.35); }

    .badge-mitre {
        background: rgba(136, 132, 216, 0.15);
        color: #8884d8;
        border: 1px solid rgba(136, 132, 216, 0.25);
    }

    /* ── Prevention banner ── */
    .prevention-banner {
        background: linear-gradient(135deg, rgba(63, 185, 80, 0.15), rgba(63, 185, 80, 0.05));
        border: 1px solid rgba(63, 185, 80, 0.4);
        border-radius: 12px;
        padding: 0.8rem 1.2rem;
        margin-bottom: 0.5rem;
        display: flex;
        align-items: center;
        gap: 0.8rem;
    }
    .prevention-banner .icon {
        font-size: 1.5rem;
    }
    .prevention-banner .text {
        color: #3fb950;
        font-weight: 600;
        font-size: 0.95rem;
    }
    .prevention-banner .time {
        color: rgba(63, 185, 80, 0.7);
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
    }

    /* ── Section headers ── */
    .section-header {
        font-size: 1.3rem;
        font-weight: 700;
        color: #e6edf3;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid rgba(88, 166, 255, 0.15);
    }

    /* ── Status indicator ── */
    .status-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 8px;
        animation: pulse 2s infinite;
    }
    .status-dot.active { background: #3fb950; box-shadow: 0 0 8px rgba(63, 185, 80, 0.5); }
    .status-dot.inactive { background: #f85149; }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }

    /* ── Memory table ── */
    .memory-table {
        width: 100%;
        border-collapse: collapse;
    }
    .memory-table th {
        text-align: left;
        padding: 0.6rem 1rem;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #8b949e;
        border-bottom: 1px solid rgba(88, 166, 255, 0.15);
    }
    .memory-table td {
        padding: 0.6rem 1rem;
        font-size: 0.9rem;
        color: #e6edf3;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .memory-table tr:hover td {
        background: rgba(88, 166, 255, 0.05);
    }

    /* ── Hide streamlit defaults ── */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* ── Plotly chart backgrounds ── */
    .js-plotly-plot .plotly .modebar { display: none !important; }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
#  Initialize HIDS Core (singleton via session state)
# ═══════════════════════════════════════════════════════════════════════════
if "hids_core" not in st.session_state:
    st.session_state.hids_core = HIDSCore()
    st.session_state.hids_core.start()

core: HIDSCore = st.session_state.hids_core


# ═══════════════════════════════════════════════════════════════════════════
#  Helper functions
# ═══════════════════════════════════════════════════════════════════════════
def get_severity_badge(severity: str) -> str:
    cls = severity.lower()
    return f'<span class="badge badge-{cls}">{severity}</span>'

def get_action_badge(action: str) -> str:
    mapping = {
        "DETECT_ONLY": ("badge-detect", "🔍 DETECT ONLY"),
        "PREVENTED": ("badge-prevent", "🛡️ PREVENTED"),
        "FAILED_PREVENTION": ("badge-failed", "⚠️ FAILED"),
    }
    cls, text = mapping.get(action, ("badge-detect", action))
    return f'<span class="badge {cls}">{text}</span>'

def get_occurrence_text(occ: int) -> str:
    if occ == 1:
        return '<span style="color: #d29922; font-weight: 600;">1st — Learning</span>'
    else:
        return f'<span style="color: #3fb950; font-weight: 600;">#{occ} — Auto-Prevent</span>'


# ═══════════════════════════════════════════════════════════════════════════
#  Sidebar
# ═══════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🛡️ HIDS Control Panel")

    # System status
    running = core.is_running
    dot_class = "active" if running else "inactive"
    status_text = "MONITORING ACTIVE" if running else "STOPPED"
    st.markdown(
        f'<div style="margin: 1rem 0;"><span class="status-dot {dot_class}"></span>'
        f'<span style="color: #e6edf3; font-weight: 600;">{status_text}</span></div>',
        unsafe_allow_html=True
    )

    st.markdown("---")

    # Attack coverage
    st.markdown("### 📋 Monitored Attacks")
    for aid, info in ATTACKS.items():
        st.markdown(
            f'<div style="margin: 0.4rem 0; padding: 0.5rem; '
            f'background: rgba(22,27,34,0.8); border-radius: 8px; '
            f'border: 1px solid rgba(88,166,255,0.1);">'
            f'<div style="color: #e6edf3; font-weight: 600; font-size: 0.85rem;">{info["name"]}</div>'
            f'<div style="display: flex; gap: 0.4rem; margin-top: 0.3rem;">'
            f'<span class="badge badge-mitre">{info["mitre_id"]}</span>'
            f'{get_severity_badge(info["severity"])}'
            f'</div></div>',
            unsafe_allow_html=True
        )

    st.markdown("---")

    # Controls
    st.markdown("### ⚙️ Controls")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Reset Memory", use_container_width=True):
            core.memory.reset()
            st.toast("Threat memory cleared!", icon="🧹")
    with col2:
        if st.button("🗑️ Clear Logs", use_container_width=True):
            core.logger.clear()
            st.toast("Event logs cleared!", icon="🗑️")

    st.markdown("---")
    st.markdown(
        f'<div style="color: #484f58; font-size: 0.75rem; text-align: center;">'
        f'Auto-refresh: {DASHBOARD_REFRESH}s<br>'
        f'Last update: {datetime.now().strftime("%H:%M:%S")}</div>',
        unsafe_allow_html=True
    )


# ═══════════════════════════════════════════════════════════════════════════
#  Main Content
# ═══════════════════════════════════════════════════════════════════════════

# ── Title ───────────────────────────────────────────────────────────────
st.markdown('<div class="main-title">🛡️ HIDS — Adaptive Intrusion Detection & Prevention</div>', unsafe_allow_html=True)
st.markdown('<div class="main-subtitle">Host-Based Anomaly Detection with Threat Memory • Real-time Monitoring • MITRE ATT&CK Mapped</div>', unsafe_allow_html=True)

# ── Get data ────────────────────────────────────────────────────────────
stats = core.get_stats()
events = core.get_recent_events(100)
memory = core.get_threat_memory()

# ── KPI Row ─────────────────────────────────────────────────────────────
k1, k2, k3, k4 = st.columns(4)

with k1:
    st.markdown(
        f'<div class="kpi-card">'
        f'<div class="kpi-value" style="color: #58a6ff;">{stats["total_events"]}</div>'
        f'<div class="kpi-label">Total Events</div></div>',
        unsafe_allow_html=True
    )
with k2:
    st.markdown(
        f'<div class="kpi-card">'
        f'<div class="kpi-value" style="color: #d29922;">{stats["detections_only"]}</div>'
        f'<div class="kpi-label">Detections (Log Only)</div></div>',
        unsafe_allow_html=True
    )
with k3:
    st.markdown(
        f'<div class="kpi-card">'
        f'<div class="kpi-value" style="color: #3fb950;">{stats["preventions"]}</div>'
        f'<div class="kpi-label">Auto-Prevented</div></div>',
        unsafe_allow_html=True
    )
with k4:
    st.markdown(
        f'<div class="kpi-card">'
        f'<div class="kpi-value" style="color: #f85149;">{stats["failed_preventions"]}</div>'
        f'<div class="kpi-label">Failed Preventions</div></div>',
        unsafe_allow_html=True
    )

st.markdown("<br>", unsafe_allow_html=True)

# ── Prevention Banners (most recent) ───────────────────────────────────
recent_preventions = [e for e in events if e["action"] == "PREVENTED"][:3]
if recent_preventions:
    for prev in recent_preventions:
        st.markdown(
            f'<div class="prevention-banner">'
            f'<div class="icon">🛡️</div>'
            f'<div><div class="text">{prev["attack_name"]} prevented successfully at {prev["timestamp"].split(" ")[-1]}</div>'
            f'<div class="time">{prev["status"]}</div></div>'
            f'</div>',
            unsafe_allow_html=True
        )

# ── Two-column layout: Events + Charts ─────────────────────────────────
col_events, col_charts = st.columns([3, 2])

with col_events:
    st.markdown('<div class="section-header">📡 Live Detection Feed</div>', unsafe_allow_html=True)

    if not events:
        st.markdown(
            '<div style="text-align: center; padding: 3rem; color: #484f58;">'
            '<div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>'
            '<div style="font-size: 1.1rem;">No events detected yet</div>'
            '<div style="font-size: 0.85rem; margin-top: 0.5rem;">System is monitoring... waiting for threats</div>'
            '</div>',
            unsafe_allow_html=True
        )
    else:
        for evt in events[:20]:
            card_class = {
                "PREVENTED": "prevented",
                "DETECT_ONLY": "detected",
                "FAILED_PREVENTION": "failed",
            }.get(evt["action"], "detected")

            st.markdown(
                f'<div class="event-card {card_class}">'
                f'<div class="event-header">'
                f'<div class="event-name">{evt["attack_name"]}</div>'
                f'<div class="event-time">{evt["timestamp"]}</div>'
                f'</div>'
                f'<div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 0.4rem 0;">'
                f'{get_action_badge(evt["action"])}'
                f'{get_severity_badge(evt["severity"])}'
                f'<span class="badge badge-mitre">{evt["mitre_id"]} • {evt["mitre_tactic"]}</span>'
                f'{get_occurrence_text(evt["occurrence"])}'
                f'</div>'
                f'<div class="event-details">{evt["status"]}</div>'
                f'</div>',
                unsafe_allow_html=True
            )

with col_charts:
    st.markdown('<div class="section-header">📊 Analytics</div>', unsafe_allow_html=True)

    # ── Attack Distribution ─────────────────────────────────────────
    if stats["attack_counts"]:
        labels = [ATTACKS.get(k, {}).get("name", k) for k in stats["attack_counts"]]
        values = list(stats["attack_counts"].values())

        fig = go.Figure(data=[go.Pie(
            labels=labels, values=values,
            hole=0.55,
            marker=dict(
                colors=["#58a6ff", "#3fb950", "#d29922", "#f85149", "#db33a6"],
                line=dict(color="#0d1117", width=2)
            ),
            textfont=dict(color="#e6edf3", size=11),
            textinfo="label+percent",
        )])
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf3", family="Inter"),
            showlegend=False,
            margin=dict(t=30, b=10, l=10, r=10),
            height=280,
            title=dict(text="Attack Distribution", font=dict(size=14, color="#8b949e")),
        )
        st.plotly_chart(fig, use_container_width=True)

    # ── Severity Distribution ───────────────────────────────────────
    if stats["severity_counts"]:
        sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_colors = {"LOW": "#58a6ff", "MEDIUM": "#d29922", "HIGH": "#f85149", "CRITICAL": "#db33a6"}
        sev_labels = [s for s in sev_order if s in stats["severity_counts"]]
        sev_values = [stats["severity_counts"][s] for s in sev_labels]

        fig2 = go.Figure(data=[go.Bar(
            x=sev_labels, y=sev_values,
            marker_color=[sev_colors.get(s, "#58a6ff") for s in sev_labels],
            marker_line=dict(color="#0d1117", width=1),
            text=sev_values,
            textposition="outside",
            textfont=dict(color="#e6edf3"),
        )])
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf3", family="Inter"),
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            margin=dict(t=30, b=30, l=30, r=10),
            height=250,
            title=dict(text="Events by Severity", font=dict(size=14, color="#8b949e")),
        )
        st.plotly_chart(fig2, use_container_width=True)


# ── Threat Memory Table ─────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-header">🧠 Threat Memory</div>', unsafe_allow_html=True)

if memory:
    rows = ""
    for aid, mdata in memory.items():
        attack_info = ATTACKS.get(aid, {})
        name = attack_info.get("name", aid)
        count = mdata.get("count", 0)
        first = mdata.get("first_seen", "—")
        last = mdata.get("last_seen", "—")
        mode = "🟡 Learning" if count < 2 else "🟢 Auto-Prevent"
        rows += (
            f'<tr>'
            f'<td style="font-weight: 600;">{name}</td>'
            f'<td><span class="badge badge-mitre">{attack_info.get("mitre_id", "—")}</span></td>'
            f'<td style="font-family: JetBrains Mono; font-weight: 700; '
            f'color: {"#d29922" if count < 2 else "#3fb950"};">{count}</td>'
            f'<td>{mode}</td>'
            f'<td style="font-family: JetBrains Mono; font-size: 0.8rem; color: #8b949e;">{first}</td>'
            f'<td style="font-family: JetBrains Mono; font-size: 0.8rem; color: #8b949e;">{last}</td>'
            f'</tr>'
        )
    st.markdown(
        f'<table class="memory-table">'
        f'<thead><tr><th>Attack</th><th>MITRE</th><th>Count</th><th>Mode</th><th>First Seen</th><th>Last Seen</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>',
        unsafe_allow_html=True
    )
else:
    st.markdown(
        '<div style="text-align: center; padding: 2rem; color: #484f58;">'
        'No threats in memory — system is learning</div>',
        unsafe_allow_html=True
    )


# ── MITRE ATT&CK Coverage ──────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-header">🎯 MITRE ATT&CK Coverage</div>', unsafe_allow_html=True)

mitre_cols = st.columns(5)
for i, (aid, info) in enumerate(ATTACKS.items()):
    with mitre_cols[i % 5]:
        mem_count = memory.get(aid, {}).get("count", 0)
        border_color = "#3fb950" if mem_count >= 2 else ("#d29922" if mem_count == 1 else "rgba(88,166,255,0.2)")
        st.markdown(
            f'<div style="background: rgba(22,27,34,0.8); border: 1px solid {border_color}; '
            f'border-radius: 12px; padding: 1rem; text-align: center; margin-bottom: 0.5rem;">'
            f'<div style="font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px;">{info["mitre_tactic"]}</div>'
            f'<div style="font-size: 1.3rem; font-weight: 700; color: #58a6ff; margin: 0.3rem 0;">{info["mitre_id"]}</div>'
            f'<div style="font-size: 0.8rem; color: #e6edf3; font-weight: 500;">{info["name"]}</div>'
            f'<div style="margin-top: 0.4rem;">{get_severity_badge(info["severity"])}</div>'
            f'</div>',
            unsafe_allow_html=True
        )


# ═══════════════════════════════════════════════════════════════════════════
#  Auto-refresh
# ═══════════════════════════════════════════════════════════════════════════
time.sleep(DASHBOARD_REFRESH)
st.rerun()
