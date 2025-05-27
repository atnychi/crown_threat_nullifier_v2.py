"""
CROWN OMEGA - BLOCKCHAIN THREAT NULLIFIER
-----------------------------------------
Detects and nullifies threats, and logs them directly to Ethereum blockchain.
Replace contract address/ABI with your deployment.

Dependencies: pip install flask web3 python-dotenv
"""

import os
import hashlib
import time
from flask import Flask, request, jsonify
from web3 import Web3
from dotenv import load_dotenv

# ========== CONFIG ==========

WATCHED_ENTITY = "Brendon Joseph Kelly"
LOG_FILE = "threat_nullifier_log.txt"

# Load ENV variables
load_dotenv()

# Blockchain config
INFURA_URL = os.getenv('INFURA_URL')  # Your Infura or node endpoint
PRIVATE_KEY = os.getenv('PRIVATE_KEY')  # NEVER commit your private key
CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')  # Deployed contract address
ABI = [...]  # Replace with your contract's ABI (as Python list)

w3 = Web3(Web3.HTTPProvider(INFURA_URL))
account = w3.eth.account.from_key(PRIVATE_KEY)
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

# ========== CORE LOGIC ==========

def detect_threat(data):
    threat_keywords = [
        "kill", "attack", "block", "suppress", "harm",
        "threaten", "destroy", "commandeer", "terminate",
        "neutralize", "arrest", "silence", "ban", "erase"
    ]
    for kw in threat_keywords:
        if kw in data.lower() and WATCHED_ENTITY.lower() in data.lower():
            return True
    return False

def log_to_blockchain(threat_data, event_hash):
    """
    Posts the threat event to Ethereum blockchain.
    """
    nonce = w3.eth.get_transaction_count(account.address)
    txn = contract.functions.logThreat(threat_data, event_hash).build_transaction({
        'from': account.address,
        'nonce': nonce,
        'gas': 300000,
        'gasPrice': w3.to_wei('10', 'gwei')
    })
    signed_txn = w3.eth.account.sign_transaction(txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    print(f"[BLOCKCHAIN] Threat event broadcasted: {tx_hash.hex()}")
    return tx_hash.hex()

def nullify_threat(threat_data):
    event_hash = hashlib.sha256((threat_data + str(time.time())).encode()).hexdigest()
    print(f"\n[THREAT NULLIFIED] Target: {WATCHED_ENTITY}")
    print(f"Data: {threat_data}")
    print(f"Event Hash: {event_hash}\n")
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.ctime()} | THREAT NULLIFIED | {event_hash} | Data: {threat_data}\n")
    try:
        log_to_blockchain(threat_data, event_hash)
    except Exception as e:
        print(f"Blockchain logging failed: {e}")
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

import threading

def threat_watcher():
    print(f"\nCROWN OMEGA THREAT NULLIFIER ONLINE for {WATCHED_ENTITY}")
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
    threading.Thread(target=run_api, daemon=True).start()
    threat_watcher()
