#!/usr/bin/env python3
"""
=============================================================================
  Central Socket Server
  ---------------------
  Standalone TCP server that receives JSON telemetry events from multiple
  HIDS agents. Validates event schema and appends them to a central log file.
=============================================================================
"""

import socketserver
import json
import os
import threading

# Configuration
HOST = os.environ.get("HIDS_SERVER_HOST", "0.0.0.0")
PORT = int(os.environ.get("HIDS_SERVER_PORT", 9999))
CENTRAL_LOG_FILE = os.path.join(os.path.dirname(__file__), "central_events.jsonl")

# Ensure central log file can be written
os.makedirs(os.path.dirname(CENTRAL_LOG_FILE) or ".", exist_ok=True)

class HidsEventRequestHandler(socketserver.StreamRequestHandler):
    """
    Handles incoming TCP connections from HIDS agents.
    Expects newline-delimited JSON payloads.
    """
    
    def handle(self):
        client_ip = self.client_address[0]
        print(f"[SERVER] Connection established from {client_ip}")
        
        try:
            # Read line by line to handle multiple queued events per connection
            while True:
                # Read with a strict size limit (e.g. 10KB per event max) to prevent memory exhaustion
                line = self.rfile.readline(10240)
                if not line:
                    break
                
                payload = line.decode('utf-8').strip()
                if not payload:
                    continue
                
                self._process_event(payload, client_ip)
                
        except Exception as e:
            print(f"[SERVER] Error handling connection from {client_ip}: {e}")
            
        print(f"[SERVER] Connection closed from {client_ip}")

    def _process_event(self, payload: str, client_ip: str):
        try:
            event = json.loads(payload)
            
            # 1. Validation (must contain required fields)
            required_fields = ["agent_id", "timestamp", "attack_name", "action"]
            if not all(k in event for k in required_fields):
                print(f"[SERVER] [WARN] Malformed event rejected from {client_ip}")
                return
                
            # 2. Add server-side receipt metadata
            event["_server_receipt_ip"] = client_ip
            
            # 3. Write to central storage
            with open(CENTRAL_LOG_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")
                
            print(f"[SERVER] [{event['agent_id']}] {event['action']}: {event['attack_name']}")
            
        except json.JSONDecodeError:
            print(f"[SERVER] [WARN] Invalid JSON received from {client_ip}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # Allow port reuse to prevent "Address already in use" on quick restarts
    allow_reuse_address = True

if __name__ == "__main__":
    print(f"🚀 Central HIDS Socket Server listening on {HOST}:{PORT}")
    print(f"📁 Central Log File: {CENTRAL_LOG_FILE}")
    
    server = ThreadedTCPServer((HOST, PORT), HidsEventRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        server.server_close()
