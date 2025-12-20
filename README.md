# AIOps Network Anomaly Detection

This project implements a complete AIOps lifecycle for detecting network traffic anomalies. It uses an unsupervised **Isolation Forest** model to identify suspicious behavior in real-time telemetry.

![Project Overview](./Path.png)

## 🚀 Project Overview

The system is designed to provide security teams with automated insights into network traffic, identifying "unknown unknown" anomalies that traditional rule-based systems might miss.

### 🏗️ Architecture
- **Training:** Google Colab-friendly Jupyter Notebook for high-performance training without local GPU requirements.
- **Inference Server:** FastAPI REST API providing real-time scoring.
- **Agent Simulation:** Python-based telemetry generator to simulate live network data streams.
- **Deployment:** Fully containerized via Docker for portable and consistent execution.

---

## 📂 Folder Structure
```text
KodiakAI/MachineLearning/
├── api/                    # FastAPI application and dependencies
├── data/                   # Raw network telemetry (CSV)
├── ml/
│   ├── models/             # Exported model artifacts (.joblib)
│   └── notebooks/          # Colab training notebook
├── scripts/                # Mock event generator
├── tests/                  # Automated test suite
├── Dockerfile              # API container definition
└── docker-compose.yml      # Orchestration definition
```

---

## 🛠️ Getting Started

### 1. Phase 1: Model Training
1. Open the [training_notebook.ipynb](./ml/notebooks/training_notebook.ipynb) in **Google Colab**.
2. Upload `data/network_traffic_data.csv` when prompted.
3. Run all cells to train the model and download `anomaly_model.joblib`.
4. Place the downloaded model in the `./ml/models/` directory.

### 2. Phase 2 & 4: Deployment
You can run the API locally or via Docker.

**Using Docker (Recommended):**
```bash
docker compose up --build -d
```
The API will be available at `http://localhost:8000`.

### 3. Phase 3: Live Simulation
Start the mock telemetry agent to stream events to the API:
```bash
# Ensure you have requirements installed
pip install pandas requests
python scripts/mock_event_sender.py
```

---

## 🧪 Testing
The project includes a `pytest` suite to verify the API and inference logic.

**Local Test Execution:**
1. Ensure the API is running (Locally or in Docker).
2. Install test dependencies:
   ```bash
   pip install pytest requests
   ```
3. Run the tests:
   ```bash
   python -m pytest tests/test_api.py
   ```

---

## 📊 Test Results & Findings
The system has been verified through automated testing and live telemetry simulation.

- **Automated Tests**: All 4 core test cases passed (Root accessibility, Normal inference, Schema validation, Logic verification).
- **Simulation**: Confirmed stable throughput and accurate anomaly logging during randomized traffic bursts.
- **Model Performance**: Isolation Forest inference latency is sub-millisecond, suitable for high-frequency AIOps environments.

For more details, see [TEST_RESULTS.md](./TEST_RESULTS.md).

---

## 🛡️ Security & AIOps Features
- **Pydantic Validation:** Strict enforcement of the network telemetry schema.
- **Structured Logging:** Anomalies are logged with feature scores for auditability.
- **Behavioral Detection:** Uses unsupervised learning to detect shifts in traffic patterns (e.g., unusual ports or byte volumes).

---

**Developed for KodiakAI - AIOps Security Suite**
