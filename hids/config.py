"""
=============================================================================
  HIDS Configuration Module
  -------------------------
  Central configuration for all detection thresholds, file paths,
  monitored directories, and MITRE ATT&CK technique mappings.
=============================================================================
"""

import os
import pwd

def get_target_home_and_user():
    """Resolve the effective target user and home directory."""
    # If run via sudo, target the original user, else current user
    username = os.environ.get("SUDO_USER") or os.environ.get("USER")
    try:
        if username:
            user_info = pwd.getpwnam(username)
            return user_info.pw_dir, username
    except KeyError:
        pass
    
    # Fallback to current effective user
    return os.path.expanduser("~"), os.environ.get("USER", "unknown")

TARGET_HOME_DIR, TARGET_USER = get_target_home_and_user()

# ── Base Paths ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR  = os.path.join(BASE_DIR, "logs")

# Ensure data and log directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ── Threat Memory ───────────────────────────────────────────────────────────
THREAT_MEMORY_FILE = os.path.join(DATA_DIR, "threat_memory.json")
EVENT_LOG_FILE     = os.path.join(DATA_DIR, "event_log.json")

# ── Detection Scan Interval (seconds) ──────────────────────────────────────
FAST_SCAN_INTERVAL = 0.5  # For process-based behavioral telemetry (psutil)
SLOW_SCAN_INTERVAL = 10.0 # For filesystem and persistence configuration checks

# ── Central Server Socket Communication ─────────────────────────────────────
HIDS_SOCKET_ENABLED = True
HIDS_SERVER_HOST = os.environ.get("HIDS_SERVER_HOST", "127.0.0.1")
HIDS_SERVER_PORT = int(os.environ.get("HIDS_SERVER_PORT", 9999))
HIDS_AGENT_ID = os.environ.get("HIDS_AGENT_ID", f"agent-{TARGET_USER}")
HIDS_SOCKET_RECONNECT_INTERVAL = 5  # seconds between reconnection attempts
HIDS_SOCKET_QUEUE_LIMIT = 1000      # maximum unsent events to hold in memory

# ── Attack Definitions ──────────────────────────────────────────────────────
# Each attack has:
#   - id:           unique string identifier
#   - name:         human-readable name
#   - mitre_id:     MITRE ATT&CK technique ID
#   - mitre_tactic: MITRE tactic category
#   - severity:     LOW / MEDIUM / HIGH / CRITICAL
#   - description:  what we're looking for
ATTACKS = {
    "mem_eater": {
        "id": "mem_eater",
        "name": "Parent-Child Memory Eater",
        "mitre_id": "T1496",
        "mitre_tactic": "Impact",
        "severity": "HIGH",
        "description": "Process running a suspicious script with child processes consuming excessive memory.",
    },
    "cron_persist": {
        "id": "cron_persist",
        "name": "Cron Persistence",
        "mitre_id": "T1053.003",
        "mitre_tactic": "Persistence",
        "severity": "HIGH",
        "description": "Cron job containing persist_payload.sh detected — attacker establishing persistence via crontab.",
    },
    "systemd_persist": {
        "id": "systemd_persist",
        "name": "Systemd User Service Persistence",
        "mitre_id": "T1543.002",
        "mitre_tactic": "Persistence",
        "severity": "CRITICAL",
        "description": "Systemd user service (demo-persist.service) created for persistence.",
    },
    "discovery_burst": {
        "id": "discovery_burst",
        "name": "Discovery Burst",
        "mitre_id": "T1082",
        "mitre_tactic": "Discovery",
        "severity": "MEDIUM",
        "description": "Rapid execution of reconnaissance commands (whoami, id, ps, netstat, uname, find, etc.).",
    },
    "staging_collection": {
        "id": "staging_collection",
        "name": "Staging / Collection",
        "mitre_id": "T1074.001",
        "mitre_tactic": "Collection",
        "severity": "HIGH",
        "description": "Rapid suspicious file creation in /tmp or home directory — data staging detected.",
    },
    "masquerade_process": {
        "id": "masquerade_process",
        "name": "Process Masquerading",
        "mitre_id": "T1036.005",
        "mitre_tactic": "Defense Evasion",
        "severity": "CRITICAL",
        "description": "Process running with a deceptive system-like name (e.g., kworker) from an unusual or user-writable directory.",
    },
    "shell_rc_persist": {
        "id": "shell_rc_persist",
        "name": "Shell RC Persistence",
        "mitre_id": "T1546.004",
        "mitre_tactic": "Persistence",
        "severity": "HIGH",
        "description": "Malicious entries detected in user shell configuration files (e.g., ~/.bashrc).",
    },
}

# ── Detection Thresholds ────────────────────────────────────────────────────
# Memory eater: script paths to watch
SUSPICIOUS_MEMORY_SCRIPTS = ["dump.py", "mem_eater.py"]

# Discovery burst: how many recon commands in DISCOVERY_WINDOW seconds triggers alert
DISCOVERY_COMMANDS = {"whoami", "id", "ps", "netstat", "uname", "find", "hostname",
                      "ifconfig", "ip", "cat", "ls", "w", "last", "df", "mount",
                      "lsblk", "lscpu", "lsmod", "env", "printenv", "ss"}
DISCOVERY_THRESHOLD = 4          # minimum recon commands within the window
DISCOVERY_WINDOW    = 10         # seconds

# Staging: directories to watch for rapid file creation
STAGING_WATCH_DIRS = ["/tmp", TARGET_HOME_DIR]
STAGING_THRESHOLD  = 5           # new files in STAGING_WINDOW seconds
STAGING_WINDOW     = 15          # seconds
# File extensions considered suspicious for staging
STAGING_SUSPICIOUS_EXT = {".tar", ".gz", ".zip", ".bz2", ".7z", ".dat",
                          ".dump", ".db", ".sql", ".csv", ".txt", ".log",
                          ".enc", ".bin", ".bak"}

# ── Cron / Systemd Persistence Markers ──────────────────────────────────────
CRON_PAYLOAD_MARKER       = "persist_payload.sh"
SYSTEMD_SERVICE_NAME      = "demo-persist.service"
SYSTEMD_USER_SERVICE_DIR  = os.path.join(TARGET_HOME_DIR, ".config/systemd/user")
SYSTEMD_SYSTEM_SERVICE_DIR = "/etc/systemd/system"

# ── Dashboard ───────────────────────────────────────────────────────────────
DASHBOARD_PORT     = 8501
DASHBOARD_REFRESH  = 3  # auto-refresh interval in seconds

# ── Hybrid Engine — False Positive Suppression ──────────────────────────────
# Process names that are ALWAYS safe (never alert on these)
KNOWN_SAFE_PROCESSES = {
    "chrome", "chrome_crashpad", "chromium", "firefox", "firefox-esr",
    "gnome-shell", "gnome-session", "gnome-terminal", "nautilus",
    "code", "cursor", "antigravity",
    "Xorg", "Xwayland", "gdm", "gdm-session", "gdm-wayland",
    "pulseaudio", "pipewire", "wireplumber",
    "dbus-daemon", "dbus-broker", "polkitd", "udisksd",
    "NetworkManager", "ModemManager", "wpa_supplicant",
    "snapd", "packagekitd", "fwupd", "colord",
    "evolution-data", "gvfsd", "tracker-miner",
    "gjs", "ibus-daemon", "ibus-engine", "xdg-desktop",
    "geoclue", "gsd-color", "gsd-power", "gsd-media-keys",
}

# Exe path prefixes that are always safe
SAFE_EXE_PREFIXES = (
    "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
    "/snap/", "/opt/google/chrome/", "/opt/cursor/",
)

# ── Hybrid Engine — Attack Thresholds ───────────────────────────────────────
# Memory abuse: RSS threshold in MB for Python processes
MEM_ABUSE_RSS_THRESHOLD = 50     # MB per Python child
MEM_ABUSE_CHILDREN_MIN  = 2      # minimum children to consider abuse

# Discovery burst
DISCOVERY_BURST_MIN_CMDS = 4     # distinct recon commands in window
DISCOVERY_BURST_WINDOW   = 15    # seconds

# Staging
STAGING_MIN_FILES = 5
STAGING_TIME_WINDOW = 15  # seconds

# Process Masquerading
MASQUERADE_NAMES = {
    "kworker", "systemd-update", "sshd-agent", "dbus-daemon", "pulseaudio",
    "bash", "sh", "python", "perl"
}

# Shell RC Persistence
SHELL_RC_FILES = [
    os.path.join(TARGET_HOME_DIR, ".bashrc"),
    os.path.join(TARGET_HOME_DIR, ".bash_aliases"),
    os.path.join(TARGET_HOME_DIR, ".zshrc"),
    os.path.join(TARGET_HOME_DIR, ".profile")
]
SHELL_RC_MARKERS = [
    "nc -e", "/dev/tcp", "curl | bash", "wget -qO-", "base64 -d", 
    "persist_payload.sh", "reverse_shell"
]
