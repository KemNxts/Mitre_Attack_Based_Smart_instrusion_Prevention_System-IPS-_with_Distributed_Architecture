# Two-Machine Deployment & Attack Model

## Overview
This document defines the strict, two-machine architecture required for deploying, testing, and demonstrating the Smart IPS/HIDS. It maps exactly how an external adversary (Kali Linux) executes the 7 canonical attacks and how the Target Host independently detects and mitigates the resulting biological OS behaviors without relying on simulated API payloads.

---

## Architecture Context

```text
       KALI LINUX                                    TARGET HOST (UBUNTU)
  (Attacker Machine)                               (Protected Environment)
                                            
 [ Adversary Toolkit ]                          [ Smart IPS & HIDS (run_hybrid.py) ]
  ├── SSH Client       ────── (Network) ─────▶   ├── Vulnerable Service / SSHd
  ├── Netcat (nc)                                ├── psutil Telemetry Poller
  └── Custom Scripts                             ├── Filesystem Monitors
                                                 └── HybridEngine Detectors
```

**Prerequisite for all 7 attacks:** The attacker must first obtain remote code execution (RCE) on the Target Host. In this laboratory environment, this is achieved either via **SSH access** using compromised credentials (e.g., brute-forcing the target) or by exploiting a vulnerable web application to pop a **reverse shell** back to the Kali machine.

---

## Attack Mapping Matrix

| Attack | Kali-side Action | Target-side Effect | Target Telemetry | Detection Point | Prevention |
|---|---|---|---|---|---|
| **Discovery Burst** | Attacker gets a remote shell and rapidly types recon commands (`whoami`, `ip a`, `uname`). | The attacker's shell process (`bash`) rapidly spawns multiple child processes for the commands. | `psutil` process polling. | `_detect_discovery_burst` correlates unique commands to the single shell PPID within a 15s window. | Terminates the parent shell process, severing the attacker's connection. |
| **Process Masquerading** | Attacker uploads a backdoor, copies `/bin/bash` to `/tmp/kworker`, and executes it in the background. | A process named `kworker` begins running, but its actual binary execution path is `/tmp/kworker`. | `psutil` process snapshot comparing `name` against `exe` and `cmdline`. | `_detect_masquerading` catches the deceptive name executing from a user-writable path (`/tmp`). | Kills the masquerading process and its children recursively. |
| **Staging / Collection** | Attacker runs a script to rapidly compress stolen data: `tar -czf /tmp/loot.tar.gz /etc/`. | Multiple `.tar.gz` or `.zip` files are rapidly created in the `/tmp` directory. | Filesystem polling of high-risk directories (`/tmp`, `/home`). | `_detect_staging` counts 5+ suspicious new archive files created within a 15s window. | Irreversibly deletes the malicious staged files. |
| **Shell RC Persistence** | Attacker echoes a reverse shell backdoor (`nc -e ...`) into the user's `~/.bashrc`. | The `.bashrc` file is appended with the malicious string. | Filesystem polling of shell configuration files (`.bashrc`, `.zshrc`). | `_detect_shell_rc_persistence` identifies known malicious markers (e.g., `nc -e`, `curl | bash`). | Safely parses and rewrites the `.bashrc`, removing only the backdoor line. |
| **Cron Persistence** | Attacker modifies the user's crontab using `echo "* * * * * /tmp/malicious.sh" | crontab -`. | The OS cron spool is updated with a job pointing to a suspicious directory. | OS command polling (`crontab -l`). | `_detect_cron_persistence` flags cron lines pointing to `/tmp` or `/home`. | Re-writes the crontab using `crontab -`, excluding the malicious entry. |
| **Systemd User Persistence** | Attacker creates a rogue `.service` file in `~/.config/systemd/user/` and enables it. | A `.service` file appears with an `ExecStart` path pointing to an attacker-controlled binary. | Filesystem scanning of systemd user directories. | `_detect_systemd_persistence` flags `ExecStart` directives targeting `/tmp` or user directories. | Stops/disables the service via `systemctl` and deletes the file. |
| **Parent-Child Memory Eater** | Attacker uploads and executes a resource exhaustion script (e.g., `dump.py`). | Python processes rapidly spawn children and collectively consume excessive RAM (RSS > 50MB). | `psutil` process polling tracking RSS and parent-child tree depth. | `_detect_memory_abuse` identifies high RSS usage and deep process trees originating from user directories. | Recursively kills the offending parent process and its entire child tree. |

---

## Defense Independence

The crucial distinction in this architecture is that **the Target Host has zero prior knowledge of the Kali attacker's intent.** 
- There are no APIs passing JSON payloads like `{"attack": "Cron Persistence"}`.
- The HIDS relies entirely on real biological OS indicators: process memory allocations, filesystem timestamps, configuration parsing, and PPID/PID hierarchies.
- The mitigation actions are genuine OS commands (`pkill`, `os.remove`, `crontab` rewriting) applied precisely to the source of the anomaly.

## Limitations & Realism Constraints
1. **Discovery Burst & Telemetry Gaps**: Because the current telemetry uses `psutil` polling every 2-3 seconds, an attacker who scripts the execution of 5 recon commands in 100 milliseconds will likely bypass detection, as the processes will start and die between polls. (This highlights the future need for event-driven telemetry like `auditd`).
2. **Path Assumptions**: Currently, some detectors assume the presence of `/home/khushal/` or `dump.py` specifically. To be a truly robust remote defender, these strings must be generalized to dynamic user directories.
