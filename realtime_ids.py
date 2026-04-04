import pickle
import pandas as pd
from scapy.all import sniff

# 🔹 Load trained model
with open("iot_ids_model.pkl", "rb") as f:
    bundle = pickle.load(f)

model = bundle["model"]
features = bundle["features"]

# 🔹 Counter for attack detection
attack_counter = 0

# 🔹 Feature extraction
def extract_features(packet):
    length = len(packet)

    # MQTT detection (port 1883)
    is_mqtt = 1 if packet.haslayer("TCP") and (packet.dport == 1883 or packet.sport == 1883) else 0

    # ICMP + ICMPv6 detection
    is_attack_proto = 1 if packet.haslayer("ICMP") or packet.haslayer("ICMPv6") else 0

    # Keep consistent with training
    time_delta = 0

    # Length bucket
    if length < 100:
        length_bucket = 0
    elif length < 500:
        length_bucket = 1
    elif length < 1000:
        length_bucket = 2
    else:
        length_bucket = 3

    return [length, time_delta, is_mqtt, is_attack_proto, length_bucket]

# 🔹 Packet processing
def process_packet(packet):
    global attack_counter

    try:
        # Ignore small noise packets
        if len(packet) < 60:
            return

        data = extract_features(packet)
        df = pd.DataFrame([data], columns=features)

        pred = model.predict(df)

        # 🔥 Improved counter logic (VERY IMPORTANT)
        if pred[0] == 1:
            attack_counter += 1
        else:
            attack_counter = max(0, attack_counter - 1)

        # 🔥 Lower threshold for better sensitivity
        if attack_counter > 2:
            print("🚨 ATTACK DETECTED")
        else:
            print("Normal Traffic")

        # 🔍 Debug (optional — remove for final demo)
        print(f"[DEBUG] pred={pred[0]} counter={attack_counter}")

    except:
        pass

# 🔹 Start IDS
print("🚀 Starting Real-Time IDS...")

sniff(
    filter="tcp port 1883 or icmp or icmp6",
    prn=process_packet,
    store=0
)