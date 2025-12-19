import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os

# Create directories if they don't exist
os.makedirs('ml/models', exist_ok=True)

def train_model(data_path='data/network_traffic_data.csv'):
    print(f"Loading data from {data_path}...")
    df = pd.read_csv(data_path)
    
    # 1. Data Cleaning
    # Remove any rows with missing values that are critical
    df = df.dropna(subset=['source_ip', 'dest_ip', 'dest_port', 'protocol'])
    
    # 2. Feature Engineering
    print("Performing feature engineering...")
    
    # Fill missing values for dns_query
    df['dns_query'] = df['dns_query'].fillna('none')
    
    # Encode categorical features
    # Using LabelEncoder for simplicity in this Phase
    le_protocol = LabelEncoder()
    df['protocol_enc'] = le_protocol.fit_transform(df['protocol'])
    
    # Scale numeric features
    scaler = StandardScaler()
    numeric_features = ['dest_port', 'bytes_sent', 'bytes_recv']
    df[numeric_features] = scaler.fit_transform(df[numeric_features])
    
    # Feature selection: Why these?
    # - dest_port: Common indicator of service type and potential port scanning
    # - bytes_sent/recv: Volume anomalies often indicate data exfiltration or DoS
    # - protocol_enc: Different protocols have different baseline behaviors
    features = numeric_features + ['protocol_enc']
    X = df[features]
    
    # 3. Model Training
    print("Training Isolation Forest model...")
    # contamination='auto' lets the model decide the proportion of outliers
    model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
    model.fit(X)
    
    # 4. Evaluation (Simple check)
    # 1 for inliers, -1 for outliers
    predictions = model.predict(X)
    anomaly_count = (predictions == -1).sum()
    print(f"Detected {anomaly_count} anomalies out of {len(df)} records.")
    
    # 5. Save Artifacts
    print("Saving model and preprocessing artifacts...")
    model_artifacts = {
        'model': model,
        'scaler': scaler,
        'le_protocol': le_protocol,
        'features': features
    }
    
    joblib.dump(model_artifacts, 'ml/models/anomaly_model.joblib')
    print("Phase 1 complete. Model saved to ml/models/anomaly_model.joblib")

if __name__ == "__main__":
    train_model()
