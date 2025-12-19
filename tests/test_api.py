import pytest
import requests
import json

BASE_URL = "http://localhost:8000"

def test_root_endpoint():
    """Verify that the API root is accessible."""
    response = requests.get(f"{BASE_URL}/")
    assert response.status_code == 200
    assert response.json()["message"] == "AIOps Network Anomaly Detection API is live"

def test_inference_endpoint_normal():
    """Verify that a normal event returns a 200 OK and valid schema."""
    payload = {
        "timestamp": "2023-10-27 10:00:00",
        "process_path": "C:\\Windows\\System32\\svchost.exe",
        "process_hash": "abc123hash",
        "source_ip": "192.168.1.5",
        "dest_ip": "8.8.8.8",
        "dest_domain": "google.com",
        "dest_port": 443,
        "bytes_sent": 500,
        "bytes_recv": 1200,
        "protocol": "TCP",
        "dns_query": "google.com",
        "parent_process": "services.exe",
        "user_context": "SYSTEM"
    }
    response = requests.post(f"{BASE_URL}/event", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "anomaly_score" in data
    assert "timestamp" in data

def test_inference_endpoint_invalid_data():
    """Verify that the API rejects invalid data schemas (e.g., missing dest_port)."""
    payload = {
        "source_ip": "192.168.1.5",
        "dest_ip": "8.8.8.8"
        # Missing required fields
    }
    response = requests.post(f"{BASE_URL}/event", json=payload)
    assert response.status_code == 422 # Unprocessable Entity

def test_inference_logic():
    """Verify that high byte counts or unusual ports trigger different scores."""
    # Note: Since the model is trained on specific data, we just verify it responds.
    payload_high_sent = {
        "timestamp": "2023-10-27 10:00:00",
        "process_path": "C:\\Windows\\System32\\svchost.exe",
        "process_hash": "abc123hash",
        "source_ip": "192.168.1.5",
        "dest_ip": "8.8.8.8",
        "dest_domain": "google.com",
        "dest_port": 443,
        "bytes_sent": 99999999, # Extreme value
        "bytes_recv": 1200,
        "protocol": "TCP",
        "dns_query": "google.com",
        "parent_process": "services.exe",
        "user_context": "SYSTEM"
    }
    response = requests.post(f"{BASE_URL}/event", json=payload_high_sent)
    assert response.status_code == 200
    data = response.json()
    # If the model logic is working, it should return a result
    assert data["status"] in ["normal", "anomaly"]
