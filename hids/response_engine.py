"""
=============================================================================
  Response Engine  (Automatic Prevention)
  ----------------------------------------
  Executes prevention actions when Threat Memory indicates an attack has
  been seen before (occurrence >= 2).
  
  Each prevention function returns a result dict with success/failure info.
=============================================================================
"""

import os
import signal
import subprocess
import shutil

import psutil

from hids.config import (
    SUSPICIOUS_MEMORY_SCRIPTS,
    CRON_PAYLOAD_MARKER,
    SYSTEMD_SERVICE_NAME,
    SYSTEMD_USER_SERVICE_DIR,
    SYSTEMD_SYSTEM_SERVICE_DIR,
)


class ResponseEngine:
    """Executes automatic prevention actions for each attack type."""

    def prevent(self, attack_id: str, detection_data: dict) -> dict:
        """
        Dispatch to the correct prevention handler.
        Supports both legacy rule-based IDs and hybrid engine IDs.
        
        Returns dict with:
          - success (bool)
          - message (str)
          - action  (str) — what was done
        """
        handlers = {
            # Legacy IDs
            "mem_eater":          self._prevent_mem_eater,
            "cron_persist":       self._prevent_cron_persistence,
            "systemd_persist":    self._prevent_systemd_persistence,
            "discovery_burst":    self._prevent_discovery_burst,
            "staging_collection": self._prevent_staging,
            # Hybrid engine IDs
            "memory_abuse":       self._prevent_mem_eater,
            "masquerade_process": self._prevent_masquerade,
            "shell_rc_persist":   self._prevent_shell_rc,
        }
        handler = handlers.get(attack_id)
        if not handler:
            return {
                "success": False,
                "message": f"No prevention handler for {attack_id}",
                "action": "NONE",
            }
        try:
            return handler(detection_data)
        except Exception as e:
            return {
                "success": False,
                "message": f"Prevention failed with error: {e}",
                "action": "ERROR",
            }

    # ════════════════════════════════════════════════════════════════════
    #  PREVENTION 1 — Kill Memory Abuser
    # ════════════════════════════════════════════════════════════════════
    def _prevent_mem_eater(self, data: dict) -> dict:
        """Kill memory-abusing processes — by PID list or by script name."""
        killed = []
        try:
            # pkill by script paths
            for script in SUSPICIOUS_MEMORY_SCRIPTS:
                subprocess.run(
                    ["pkill", "-f", script],
                    capture_output=True, text=True, timeout=10
                )
            
            # Explicitly kill any PIDs from detection data
            for pid in data.get("pids", []):
                try:
                    p = psutil.Process(pid)
                    for child in p.children(recursive=True):
                        child.kill()
                        killed.append(child.pid)
                    p.kill()
                    killed.append(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to kill memory abuser: {e}",
                "action": "pkill + kill PIDs",
            }

        return {
            "success": True,
            "message": f"Killed memory-abusing processes: {killed}",
            "action": f"pkill -f {SUSPICIOUS_MEMORY_SCRIPTS} + killed children",
        }

    # ════════════════════════════════════════════════════════════════════
    #  PREVENTION 2 — Remove Cron Persistence
    # ════════════════════════════════════════════════════════════════════
    def _prevent_cron_persistence(self, data: dict) -> dict:
        """Remove cron entries containing persist_payload.sh."""
        try:
            # Get current crontab
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "message": "Could not read crontab",
                    "action": "crontab -l",
                }

            lines = result.stdout.splitlines()
            clean_lines = [
                line for line in lines
                if CRON_PAYLOAD_MARKER not in line
            ]
            removed = len(lines) - len(clean_lines)

            if removed == 0:
                return {
                    "success": True,
                    "message": "Cron entry already removed",
                    "action": "no action needed",
                }

            # Write cleaned crontab
            new_crontab = "\n".join(clean_lines) + "\n"
            proc = subprocess.run(
                ["crontab", "-"],
                input=new_crontab, capture_output=True, text=True, timeout=5
            )

            if proc.returncode == 0:
                return {
                    "success": True,
                    "message": f"Removed {removed} malicious cron entries containing '{CRON_PAYLOAD_MARKER}'",
                    "action": f"Filtered crontab, removed {removed} entries",
                }
            else:
                return {
                    "success": False,
                    "message": f"Failed to write cleaned crontab: {proc.stderr}",
                    "action": "crontab write failed",
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"Cron prevention error: {e}",
                "action": "error",
            }

    # ════════════════════════════════════════════════════════════════════
    #  PREVENTION 3 — Disable & Delete Systemd Service
    # ════════════════════════════════════════════════════════════════════
    def _prevent_systemd_persistence(self, data: dict) -> dict:
        """Stop, disable, and delete the rogue systemd service."""
        actions_taken = []
        errors = []

        # Try user service first
        for scope in ["--user", ""]:
            scope_args = [scope] if scope else []
            try:
                # Stop
                subprocess.run(
                    ["systemctl"] + scope_args + ["stop", SYSTEMD_SERVICE_NAME],
                    capture_output=True, timeout=10
                )
                actions_taken.append(f"systemctl {scope} stop {SYSTEMD_SERVICE_NAME}")

                # Disable
                subprocess.run(
                    ["systemctl"] + scope_args + ["disable", SYSTEMD_SERVICE_NAME],
                    capture_output=True, timeout=10
                )
                actions_taken.append(f"systemctl {scope} disable {SYSTEMD_SERVICE_NAME}")
            except Exception as e:
                errors.append(str(e))

        # Delete service file
        for sdir in [SYSTEMD_USER_SERVICE_DIR, SYSTEMD_SYSTEM_SERVICE_DIR]:
            spath = os.path.join(sdir, SYSTEMD_SERVICE_NAME)
            if os.path.exists(spath):
                try:
                    os.remove(spath)
                    actions_taken.append(f"Deleted {spath}")
                except OSError as e:
                    errors.append(f"Could not delete {spath}: {e}")

        # Reload daemon
        try:
            subprocess.run(
                ["systemctl", "--user", "daemon-reload"],
                capture_output=True, timeout=10
            )
            actions_taken.append("daemon-reload (user)")
        except Exception:
            pass

        success = len(actions_taken) > 0
        return {
            "success": success,
            "message": "; ".join(actions_taken) + (f" | Errors: {'; '.join(errors)}" if errors else ""),
            "action": "Stop + Disable + Delete systemd service",
        }

    # ════════════════════════════════════════════════════════════════════
    #  PREVENTION 4 — Kill Discovery Burst Parent
    # ════════════════════════════════════════════════════════════════════
    def _prevent_discovery_burst(self, data: dict) -> dict:
        """Kill the parent process responsible for the recon burst."""
        ppid = data.get("parent_pid")
        if not ppid:
            return {
                "success": False,
                "message": "No parent PID available for discovery burst",
                "action": "NONE",
            }

        try:
            parent = psutil.Process(ppid)
            parent_name = parent.name()
            # Kill children first
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            parent.kill()
            return {
                "success": True,
                "message": f"Killed parent process {parent_name} (PID {ppid}) and its children",
                "action": f"kill PID {ppid} ({parent_name})",
            }
        except psutil.NoSuchProcess:
            return {
                "success": True,
                "message": f"Parent PID {ppid} already terminated",
                "action": "already dead",
            }
        except psutil.AccessDenied:
            # Fallback to kill command
            try:
                os.kill(ppid, signal.SIGKILL)
                return {
                    "success": True,
                    "message": f"Force-killed PID {ppid} via SIGKILL",
                    "action": f"SIGKILL PID {ppid}",
                }
            except Exception as e:
                return {
                    "success": False,
                    "message": f"Access denied killing PID {ppid}: {e}",
                    "action": "failed — access denied",
                }

    # ════════════════════════════════════════════════════════════════════
    #  PREVENTION 5 — Delete Staged Files + Kill Process
    # ════════════════════════════════════════════════════════════════════
    def _prevent_staging(self, data: dict) -> dict:
        """Delete staged files and kill processes writing to them."""
        staged_files = data.get("staged_files", [])
        deleted = []
        failed = []

        for fpath in staged_files:
            try:
                # Try to find and kill the process holding this file
                for proc in psutil.process_iter(["pid", "open_files"]):
                    try:
                        open_files = proc.info.get("open_files") or []
                        for of in open_files:
                            if of.path == fpath:
                                proc.kill()
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Delete the file
                if os.path.isfile(fpath):
                    os.remove(fpath)
                    deleted.append(fpath)
                elif os.path.isdir(fpath):
                    shutil.rmtree(fpath, ignore_errors=True)
                    deleted.append(fpath)
            except Exception as e:
                failed.append(f"{fpath}: {e}")

        success = len(deleted) > 0 or len(failed) == 0
        return {
            "success": success,
            "message": f"Deleted {len(deleted)} staged files" + (f", {len(failed)} failed" if failed else ""),
            "action": f"Deleted files: {deleted[:5]}{'...' if len(deleted) > 5 else ''}",
        }

    # ════════════════════════════════════════════════════════════════════
    #  PREVENTION 6 — Kill Masquerading Process
    # ════════════════════════════════════════════════════════════════════
    def _prevent_masquerade(self, data: dict) -> dict:
        """Kill the masquerading process."""
        pids = data.get("pids", [])
        if not pids:
            return {
                "success": False,
                "message": "No PIDs provided for masquerading process",
                "action": "NONE",
            }
            
        killed = []
        for pid in pids:
            try:
                p = psutil.Process(pid)
                # Kill children first
                for child in p.children(recursive=True):
                    try:
                        child.kill()
                        killed.append(child.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                p.kill()
                killed.append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        # Fallback to kill command just in case
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
                if pid not in killed:
                    killed.append(pid)
            except Exception:
                pass
                
        success = len(killed) > 0
        return {
            "success": success,
            "message": f"Killed masquerading processes: {killed}" if success else "Failed to kill masquerading processes",
            "action": f"SIGKILL PIDs: {pids}",
        }

    # ════════════════════════════════════════════════════════════════════
    #  PREVENTION 7 — Clean Shell RC Persistence
    # ════════════════════════════════════════════════════════════════════
    def _prevent_shell_rc(self, data: dict) -> dict:
        """Remove malicious lines from shell RC files."""
        affected_files = data.get("affected_files", [])
        bad_lines = data.get("bad_lines", [])
        
        if not affected_files or not bad_lines:
            return {
                "success": False,
                "message": "No files or lines provided to clean",
                "action": "NONE",
            }
            
        cleaned = []
        errors = []
        
        for filepath in affected_files:
            if not os.path.isfile(filepath):
                continue
                
            try:
                # Read current content
                with open(filepath, 'r', errors='ignore') as f:
                    lines = f.readlines()
                    
                # Filter out bad lines
                new_lines = []
                for line in lines:
                    line_clean = line.strip()
                    if not any(bad in line_clean for bad in bad_lines) and \
                       not any(marker in line_clean for marker in data.get("markers", [])):
                        new_lines.append(line)
                        
                # Write back if changed
                if len(new_lines) < len(lines):
                    with open(filepath, 'w') as f:
                        f.writelines(new_lines)
                    cleaned.append(filepath)
            except Exception as e:
                errors.append(f"{filepath}: {e}")
                
        success = len(cleaned) > 0 or len(errors) == 0
        return {
            "success": success,
            "message": f"Cleaned {len(cleaned)} shell RC files" + (f", {len(errors)} errors" if errors else ""),
            "action": f"Removed malicious entries from {cleaned}",
        }
