import sys, os, time
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from hids.communication.socket_client import SocketClient

client = SocketClient()
client.start()
print("📡 Client started, sending event while server is offline...")
client.queue_event({
    "agent_id": "test-agent",
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "attack_name": "Queued Offline Attack",
    "action": "DETECT_ONLY"
})
time.sleep(2)
print("📦 Queue size:", client.queue.qsize())
print("🚀 Starting server now...")
import subprocess
server_proc = subprocess.Popen(["venv/bin/python", "socket_server.py"])
time.sleep(6)
print("📦 Queue size after reconnect:", client.queue.qsize())
client.stop()
server_proc.terminate()
