# Real-Time Network Traffic Anomaly Detection

This project provides a real-time network monitoring system to detect malicious traffic, such as DDoS attacks, using a machine learning model. It captures network packets, processes them into flows, extracts features, and classifies flows as benign or malicious using a pre-trained RandomForestClassifier trained on the CICIDS2017 DDoS dataset.

## Features
- Captures TCP/UDP packets using Scapy.
- Processes flows every 60 seconds, extracting features like flow duration and packet count.
- Classifies flows as benign or malicious with confidence scores.
- Supports testing in a controlled environment with simulated malicious traffic (e.g., UDP floods, SYN floods).

## Prerequisites
- **Operating System**: Linux (e.g., Ubuntu, Kali Linux) recommended for packet capture.
- **Python**: Version 3.6 or higher.
- **Network Interface**: A network interface (e.g., `wlan0` or `eth0`) in promiscuous mode.
- **Virtual Environment** (optional): For isolating dependencies.
- **Test Environment**: A virtual network (e.g., VirtualBox, GNS3) with victim, attacker, and monitor nodes.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/network-traffic-anomaly-detection.git
   cd network-traffic-anomaly-detection
   ```

2. **Install Dependencies**:
   ```bash
   pip install scapy pandas numpy joblib scikit-learn
   ```

3. **Ensure Model File**:
   - Place the trained model (`network_traffic_model.joblib`) in the project directory.
   - If training your own model, use the CICIDS2017 DDoS dataset and the provided training script (see [Training](#training)).

4. **Set Up Network Interface**:
   - Identify your network interface:
     ```bash
     ip link
     ```
   - Enable promiscuous mode (replace `eth0` with your interface):
     ```bash
     sudo ifconfig eth0 promisc
     ```

## Usage
1. **Run the Monitoring Script**:
   - Start capturing packets and classifying flows:
     ```bash
     sudo python3 network_monitor.py
     ```
   - The script captures packets on `wlan0` (edit the script to change the interface), processes flows every 60 seconds, and prints predictions (e.g., "Benign" or "Malicious").

2. **Example Output**:
   ```
   📡 Starting packet capture on wlan0...
   ⏱️ Processing flows...
   🧠 Flow: 192.168.1.20:12345 -> 192.168.1.10:443 (UDP)
      Features: {'Flow Duration': 5000000.0, 'Total Fwd Packets': 10000, ...}
      Prediction: Malicious (Confidence: 0.95)
   ```

3. **Stop the Script**:
   - Press `Ctrl+C` to stop packet capture.
