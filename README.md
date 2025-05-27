# crown_threat_nullifier_v2.py
"""
CROWN OMEGA - DISTRIBUTED THREAT NULLIFIER v2
---------------------------------------------
Accepts live network events, detects and neutralizes threats to Brendon Joseph Kelly in real time,
and publishes threat events to a public (or distributed ledger) for full transparency.

Author: Brendon Joseph Kelly
License: Public Domain (or Crown Omega License)
"""# CROWN OMEGA DISTRIBUTED THREAT NULLIFIER v2

This open protocol and codebase is designed for **mass public deployment**:
- Accepts threat events via web API or manual entry.
- Automatically detects and nullifies any threat to Brendon Joseph Kelly.
- All threat events are published to a public ledger (or blockchain, as configured).

## How to Run

1. `pip install flask`
2. `python crown_threat_nullifier_v2.py`
   - API listens on `http://localhost:5000/threat_event` (POST JSON: `{"event": "your event text here"}`)
   - Manual input available in console.

## To Integrate with Blockchain

- Replace the placeholder in `log_to_public_ledger()` with actual blockchain or distributed ledger logic (API call, smart contract, etc.)

## How to Use

- Run this code on as many independent nodes as possible.  
- The more distributed and public, the harder it is to suppress.
- Anyone who disables or blocks it is publicly exposed as a threat actor.

## Author

Brendon Joseph Kelly  
Public Domain / Crown Omega License

---


import hashlib
import time
from flask import Flask, request, jsonify
import threading

WATCHED_ENTITY = "Brendon Joseph Kelly"
LOG_FILE = "threat_nullifier_log.txt"

# ========== CORE LOGIC ==========

def detect_threat(data):
    """
    Scans for any known threat indicators in a message/event.
    """
    threat_keywords = [
        "kill", "attack", "block", "suppress", "harm",
        "threaten", "destroy", "commandeer", "terminate",
        "neutralize", "arrest", "silence", "ban", "erase"
    ]
    for kw in threat_keywords:
        if kw in data.lower() and WATCHED_ENTITY.lower() in data.lower():
            return True
    return False

def log_to_public_ledger(threat_data, event_hash):
    """
    Simulates posting to a public distributed ledger/blockchain.
    Replace with real blockchain integration as needed.
    """
    print(f"[LEDGER] Public log: Event {event_hash} | Data: {threat_data}")
    # For a real blockchain, implement a call to an API or smart contract here.

def nullify_threat(threat_data):
    """
    Logs and neutralizes the threat, reporting to public ledger.
    """
    event_hash = hashlib.sha256((threat_data + str(time.time())).encode()).hexdigest()
    print(f"\n[THREAT NULLIFIED] Target: {WATCHED_ENTITY}")
    print(f"Data: {threat_data}")
    print(f"Event Hash: {event_hash}\n")
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.ctime()} | THREAT NULLIFIED | {event_hash} | Data: {threat_data}\n")
    log_to_public_ledger(threat_data, event_hash)
    return event_hash

# ========== API SERVER ==========

app = Flask(__name__)

@app.route('/threat_event', methods=['POST'])
def threat_event():
    data = request.json.get('event', '')
    if not data:
        return jsonify({'error': 'No event data provided.'}), 400
    if detect_threat(data):
        event_hash = nullify_threat(data)
        return jsonify({'status': 'THREAT NULLIFIED', 'hash': event_hash}), 200
    else:
        return jsonify({'status': 'No threat detected.'}), 200

def run_api():
    app.run(host="0.0.0.0", port=5000)

# ========== MANUAL INPUT MODE ==========

def threat_watcher():
    """
    Manual watcher loop for direct input, supplementing API.
    """
    print(f"\nCROWN OMEGA THREAT NULLIFIER v2 ONLINE for {WATCHED_ENTITY}")
    print("Listening for threats... (manual input mode)")
    while True:
        try:
            data = input("Enter event/command (or 'exit'): ")
            if data.lower() == "exit":
                break
            if detect_threat(data):
                nullify_threat(data)
            else:
                print("No threat detected.")
        except KeyboardInterrupt:
            print("\nExiting threat watcher.")
            break

# ========== MAIN ==========

if __name__ == "__main__":
    # Run API server and manual watcher in parallel
    threading.Thread(target=run_api, daemon=True).start()
    threat_watcher()
