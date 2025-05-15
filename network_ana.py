from scapy.all import sniff
from collections import defaultdict
import time
import pandas as pd
import numpy as np
import joblib

# Load the trained model
model = joblib.load('network_traffic_model.joblib')
print("✅ Model loaded: network_traffic_model.joblib")

flows = defaultdict(list)
last_processed = time.time()

def process_flows():
    global flows
    print("\n[O] Processing flows...\n")
    
    for flow_id, packets in flows.items():
        src, dst, sport, dport, proto = flow_id
        times = [t for t, _ in packets]
        sizes = [s for _, s in packets]
        
        # Calculate flow features
        duration = max(times) - min(times) if len(times) > 1 else 0
        pkt_count = len(packets)
        mean_pkt_size = sum(sizes) / pkt_count if pkt_count > 0 else 0
        
        # Approximate features to match the trained model's features
        total_fwd_packets = pkt_count  
        total_len_fwd = sum(sizes)     
        total_len_bwd = 0              
        fwd_pkt_len_mean = mean_pkt_size
        bwd_pkt_len_mean = 0           
        flow_iat_mean = (duration / (pkt_count - 1)) if pkt_count > 1 else 0
        fwd_iat_mean = flow_iat_mean   
        bwd_iat_mean = 0               

        # Create feature dictionary
        flow_features = {
            'Flow Duration': duration * 1_000_000,  #
            'Total Fwd Packets': total_fwd_packets,
            'Total Length of Fwd Packets': total_len_fwd,
            'Total Length of Bwd Packets': total_len_bwd,
            'Fwd Packet Length Mean': fwd_pkt_len_mean,
            'Bwd Packet Length Mean': bwd_pkt_len_mean,
            'Flow IAT Mean': flow_iat_mean * 1_000_000,  
            'Fwd IAT Mean': fwd_iat_mean * 1_000_000,    
            'Bwd IAT Mean': bwd_iat_mean * 1_000_000     
        }

        # Convert features to DataFrame for model prediction
        feature_df = pd.DataFrame([flow_features])
        
        # Predict using the loaded model
        try:
            prediction = model.predict(feature_df)[0]
            prediction_proba = model.predict_proba(feature_df)[0]
            label = "Malicious" if prediction == 1 else "Benign"
            confidence = prediction_proba[prediction]
            
            # Print flow details and prediction
            print(f"[*] Flow: {src}:{sport} -> {dst}:{dport} ({proto})")
            print(f"   Features: {flow_features}")
            print(f"   Prediction: {label} (Confidence: {confidence:.2f})")
            print("-" * 50)
        except Exception as e:
            print(f"[X] Error predicting for flow {flow_id}: {e}")

    # Clear flows after processing
    flows.clear()

def packet_callback(packet):
    global last_processed

    if packet.haslayer('IP') and (packet.haslayer('TCP') or packet.haslayer('UDP')):
        ip = packet['IP']
        proto = 'TCP' if packet.haslayer('TCP') else 'UDP'
        sport = packet[proto].sport
        dport = packet[proto].dport
        key = (ip.src, ip.dst, sport, dport, proto)

        flows[key].append((packet.time, len(packet)))
        # print(flows)  # Optional: comment out to reduce verbosity

    if time.time() - last_processed > 5:
        process_flows()
        last_processed = time.time()

print("[*] Starting packet capture on wlan0...")
sniff(iface="wlan0", prn=packet_callback, store=0)