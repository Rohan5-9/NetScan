from flask import Flask, render_template, jsonify
from flask_cors import CORS
from scapy.all import sniff
import pandas as pd
import pickle
import threading

app = Flask(__name__)
CORS(app)

# Load model
with open("iot_ids_model.pkl", "rb") as f:
    bundle = pickle.load(f)

model = bundle["model"]
features = bundle["features"]

latest_status = "Starting..."
attack_counter = 0

# Feature extraction
def extract_features(packet):
    length = len(packet)

    is_mqtt = 1 if packet.haslayer("TCP") and (packet.dport == 1883 or packet.sport == 1883) else 0
    is_attack_proto = 1 if packet.haslayer("ICMP") or packet.haslayer("ICMPv6") else 0

    time_delta = 0

    if length < 100:
        length_bucket = 0
    elif length < 500:
        length_bucket = 1
    elif length < 1000:
        length_bucket = 2
    else:
        length_bucket = 3

    return [length, time_delta, is_mqtt, is_attack_proto, length_bucket]

# Packet processing
def process_packet(packet):
    global latest_status, attack_counter

    try:
        if len(packet) < 60:
            return

        data = extract_features(packet)
        df = pd.DataFrame([data], columns=features)

        pred = model.predict(df)

        if pred[0] == 1:
            attack_counter += 1
        else:
            attack_counter = max(0, attack_counter - 1)

        if attack_counter > 2:
            latest_status = "🚨 ATTACK DETECTED"
        else:
            latest_status = "Normal Traffic"

    except:
        pass

# Start sniffing
def start_sniffing():
    sniff(filter="tcp port 1883 or icmp or icmp6", prn=process_packet, store=0)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/stats")
def stats():
    return jsonify({
        "status": latest_status,
        "attacks": attack_counter
    })

if __name__ == "__main__":
    import os

    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)