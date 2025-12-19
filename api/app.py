import os
import joblib
import pandas as pd
import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("api/api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AIOps-API")

app = FastAPI(title="AIOps Network Anomaly Detection API")

# Model Path
MODEL_PATH = "ml/models/anomaly_model.joblib"

# Load Model Artifacts
model_artifacts = None
if os.path.exists(MODEL_PATH):
    try:
        model_artifacts = joblib.load(MODEL_PATH)
        logger.info(f"Model loaded successfully from {MODEL_PATH}")
    except Exception as e:
        logger.error(f"Error loading model: {e}")
else:
    logger.warning(f"Model file not found at {MODEL_PATH}. Inference will not be available until the model is provided.")

# Input Schema (Matches CSV Schema)
class NetworkEvent(BaseModel):
    timestamp: str
    process_path: str
    process_hash: str
    source_ip: str
    dest_ip: str
    dest_domain: Optional[str] = None
    dest_port: int
    bytes_sent: int
    bytes_recv: int
    protocol: str
    dns_query: Optional[str] = None
    parent_process: Optional[str] = None
    user_context: Optional[str] = None

@app.get("/")
async def root():
    return {"message": "AIOps Network Anomaly Detection API is live"}

@app.post("/event")
async def predict_event(event: NetworkEvent):
    if not model_artifacts:
        raise HTTPException(status_code=503, detail="Model is not loaded. Please upload anomaly_model.joblib to ml/models/")

    # 1. Transform input to DataFrame
    event_data = event.dict()
    df_input = pd.DataFrame([event_data])

    try:
        # 2. Preprocessing (Must match training code)
        # Handle protocol encoding
        le = model_artifacts['le_protocol']
        # If protocol is unseen, we might need handling, but for this project we assume known protocols
        try:
            df_input['protocol_enc'] = le.transform(df_input['protocol'])
        except ValueError:
            # Simple fallback for unknown protocol
            df_input['protocol_enc'] = -1 

        # Scale numeric features
        scaler = model_artifacts['scaler']
        numeric_features = ['dest_port', 'bytes_sent', 'bytes_recv']
        df_input[numeric_features] = scaler.transform(df_input[numeric_features])

        # 3. Inference
        model = model_artifacts['model']
        features = model_artifacts['features']
        X = df_input[features]
        
        prediction = model.predict(X)[0] # 1 for inlier, -1 for outlier
        score = model.decision_function(X)[0]

        # 4. Trigger Alerts
        status = "normal" if prediction == 1 else "anomaly"
        if status == "anomaly":
            logger.warning(f"ALERT: Anomaly detected! Source: {event.source_ip} -> Dest: {event.dest_ip}:{event.dest_port} | Score: {score}")
        else:
            logger.info(f"Event processed: Status: {status} | Score: {score}")

        return {
            "status": status,
            "anomaly_score": score,
            "timestamp": datetime.now().isoformat(),
            "event_summary": f"{event.source_ip} -> {event.dest_ip}:{event.dest_port}"
        }

    except Exception as e:
        logger.error(f"Inference error: {e}")
        raise HTTPException(status_code=500, detail="An error occurred during inference.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
