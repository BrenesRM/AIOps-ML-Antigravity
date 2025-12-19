import pandas as pd
import requests
import time
import random
import logging
import os

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Event-Sender")

API_URL = "http://localhost:8000/event"
DATA_PATH = "data/network_traffic_data.csv"

def send_events():
    if not os.path.exists(DATA_PATH):
        logger.error(f"Data file not found at {DATA_PATH}. Please ensure Phase 1 data is in place.")
        return

    logger.info(f"Reading telemetry data from {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)

    # Simulate realistic delay between events
    logger.info("Starting AIOps Event Simulation. Press Ctrl+C to stop.")
    
    try:
        while True:
            # Pick a random row from the dataset
            sample = df.sample(n=1).iloc[0].to_dict()
            
            # 1. Randomize values slightly for variation (AIOps realism)
            # Add/subtract up to 10% from byte counts
            sample['bytes_sent'] = int(sample['bytes_sent'] * random.uniform(0.9, 1.1))
            sample['bytes_recv'] = int(sample['bytes_recv'] * random.uniform(0.9, 1.1))
            
            # Occasionally change the dest_port to simulate a port scan or new service
            if random.random() < 0.05:
                sample['dest_port'] = random.randint(1024, 65535)
                logger.info(f"Simulating unexpected port access: {sample['dest_port']}")

            # 2. Add current timestamp
            sample['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S")

            # 3. Send to API
            try:
                # Clean up NaN values for JSON serialization
                payload = {k: (v if pd.notnull(v) else None) for k, v in sample.items()}
                
                response = requests.post(API_URL, json=payload, timeout=5)
                
                if response.status_code == 200:
                    result = response.json()
                    status_icon = "🟢" if result['status'] == 'normal' else "🔴"
                    logger.info(f"{status_icon} Result: {result['status'].upper()} | Score: {result['anomaly_score']:.4f} | {payload['source_ip']} -> {payload['dest_ip']}")
                else:
                    logger.error(f"API Error ({response.status_code}): {response.text}")

            except requests.exceptions.ConnectionError:
                logger.error("Failed to connect to API. Is it running at http://localhost:8000?")
            except Exception as e:
                logger.error(f"Unexpected error: {e}")

            # Wait between 1 to 5 seconds
            time.sleep(random.uniform(1, 5))

    except KeyboardInterrupt:
        logger.info("Simulation stopped by user.")

if __name__ == "__main__":
    send_events()
