import time
import pandas as pd
import pyshark
import joblib
import numpy as np
import xgboost as xgb
import logging

# Configuration parameters
INTERFACE = "Wi-Fi"  # Change based on your system
CAPTURE_DURATION = 10  # Capture traffic for 10 seconds per batch
TSHARK_PATH = "D:\\nakul\\wireshark\\tshark.exe"  # Update with your correct tshark path
MODEL_PATH = "models/xgboost_model.json"
FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", 
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max", 
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std", 
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", 
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", 
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", 
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", 
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Fwd URG Flags", 
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", 
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", 
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", 
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count", 
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size", 
    "Fwd Header Length.1", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", 
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", 
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", 
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_model(model_path):
    """Load the trained model."""
    try:
        model = xgb.Booster()
        model.load_model(model_path)
        logging.info("Model loaded successfully.")
        return model
    except Exception as e:
        logging.error(f"Error loading model: {e}")
        exit(1)

def extract_features(packet):
    """Extracts features from a captured packet and ensures all required features exist."""
    try:
        features = {
            "Destination Port": int(packet["TCP"].dstport) if "TCP" in packet else 0,
            "Flow Duration": int(packet.sniff_time.timestamp() * 1000000),
            "Total Fwd Packets": 1 if "IP" in packet else 0,
            "Total Backward Packets": 0,  # This requires tracking bidirectional flows

            # Features that are hard to extract from pyshark: Default to 0
            "Total Length of Fwd Packets": 0,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": 0,
            "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 0,
            "Fwd Packet Length Std": 0,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0,
            "Bwd Packet Length Std": 0,
            "Flow Bytes/s": float(packet.length) / CAPTURE_DURATION,
            "Flow Packets/s": 0,
            "Flow IAT Mean": 0,
            "Flow IAT Std": 0,
            "Flow IAT Max": 0,
            "Flow IAT Min": 0,
            "Fwd IAT Total": 0,
            "Fwd IAT Mean": 0,
            "Fwd IAT Std": 0,
            "Fwd IAT Max": 0,
            "Fwd IAT Min": 0,
            "Bwd IAT Total": 0,
            "Bwd IAT Mean": 0,
            "Bwd IAT Std": 0,
            "Bwd IAT Max": 0,
            "Bwd IAT Min": 0,
            "Fwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Fwd Header Length": 0,
            "Bwd Header Length": 0,
            "Fwd Packets/s": 0,
            "Bwd Packets/s": 0,
            "Min Packet Length": 0,
            "Max Packet Length": 0,
            "Packet Length Mean": 0,
            "Packet Length Std": 0,
            "Packet Length Variance": 0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": 0,
            "Average Packet Size": 0,
            "Avg Fwd Segment Size": 0,
            "Avg Bwd Segment Size": 0,
            "Fwd Header Length.1": 0,
            "Subflow Fwd Packets": 0,
            "Subflow Fwd Bytes": 0,
            "Subflow Bwd Packets": 0,
            "Subflow Bwd Bytes": 0,
            "Init_Win_bytes_forward": 0,
            "Init_Win_bytes_backward": 0,
            "act_data_pkt_fwd": 0,
            "min_seg_size_forward": 0,
            "Active Mean": 0,
            "Active Std": 0,
            "Active Max": 0,
            "Active Min": 0,
            "Idle Mean": 0,
            "Idle Std": 0,
            "Idle Max": 0,
            "Idle Min": 0,
        }
        logging.debug(f"Extracted features: {features}")
        return features
    except Exception as e:
        logging.error(f"Feature extraction error: {e}")
        return None

def analyze_batch(model, batch_data):
    """Analyze a batch of captured packets using the trained model."""
    if batch_data:
        # Create a DataFrame from the captured batch data
        df = pd.DataFrame(batch_data)
        df = df.fillna(0)  # Handle missing values
        df = df[FEATURE_COLUMNS]  # Ensure correct feature order
        
        # Convert DataFrame to DMatrix for XGBoost
        dtest = xgb.DMatrix(df)
        predictions = model.predict(dtest)
        
        # Check predictions for potential threats
        for i, pred in enumerate(predictions):
            if np.any(pred != 0):
                logging.warning(f"[ALERT] Potential Threat Detected! Packet {i} classified as {pred}")
                logging.info(f"Packet Details: {batch_data[i]}")

def capture_and_analyze():
    """Captures network traffic in real-time, extracts features, and analyzes them using the trained model."""
    model = load_model(MODEL_PATH)
    logging.info("Starting real-time traffic analysis in batches...")
    while True:
        try:
            # Initialize live capture on the specified interface
            capture = pyshark.LiveCapture(interface=INTERFACE, tshark_path=TSHARK_PATH)
            start_time = time.time()
            batch_data = []
            
            # Capture packets continuously
            for packet in capture.sniff_continuously(packet_count=100):
                features = extract_features(packet)
                if features:
                    batch_data.append(features)
                
                # Stop capturing after the specified duration
                if time.time() - start_time > CAPTURE_DURATION:
                    break
            
            # Analyze the captured batch
            analyze_batch(model, batch_data)
            
            # Wait before capturing the next batch
            time.sleep(5)
        except Exception as e:
            logging.error(f"Error during capture and analysis: {e}")

if __name__ == "__main__":
    capture_and_analyze()
