#!/usr/bin/env python3
"""
Test script to validate the socket client and offline queuing behavior.
Does NOT generate real security events.
"""

import sys
import os
import time

# Add root to path so we can import hids
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from hids.communication.socket_client import SocketClient

def main():
    print("🚀 Initializing SocketClient...")
    client = SocketClient()
    client.start()
    
    # 1. Send normal event
    print("📡 Sending Test Event 1 (Normal)...")
    client.queue_event({
        "agent_id": "test-agent",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "attack_name": "Test Attack Alpha",
        "action": "DETECT_ONLY"
    })
    
    # Wait for queue to drain
    time.sleep(2)
    
    # 2. Send Malformed Event (missing fields)
    print("📡 Sending Test Event 2 (Malformed)...")
    client.queue_event({
        "invalid_field": "This should be rejected by server"
    })
    
    time.sleep(2)
    
    print("\n🛑 Shutting down test client...")
    client.stop()

if __name__ == "__main__":
    main()
