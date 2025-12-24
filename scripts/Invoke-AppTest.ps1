$ErrorActionPreference = "Stop"
$ProjectRoot = "C:\VSCODE\AIOps-ML-Antigravity"

Write-Host "--- AIOps App & ML Test Suite ---" -ForegroundColor Cyan

# 1. Environment Check
Write-Host "[1/6] Checking Python environment..." -ForegroundColor Yellow
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed or not in PATH."
}

# 2. Model Check/Train
Write-Host "[2/6] Verifying ML model..." -ForegroundColor Yellow
$ModelPath = "$ProjectRoot\ml\models\anomaly_model.joblib"
if (-not (Test-Path $ModelPath)) {
    Write-Host "Model not found. Training now..." -ForegroundColor Gray
    python "$ProjectRoot\ml\train.py"
}
else {
    Write-Host "Model found." -ForegroundColor Green
}

# 3. Start API Server
Write-Host "[3/6] Starting FastAPI server..." -ForegroundColor Yellow
$ApiProcess = Start-Process python -ArgumentList "-m uvicorn api.app:app --host localhost --port 8000" -WorkingDirectory $ProjectRoot -PassThru -NoNewWindow
Start-Sleep -Seconds 5

# 4. Run Pytest
Write-Host "[4/6] Running automated tests (pytest)..." -ForegroundColor Yellow
python -m pytest "$ProjectRoot\tests\test_api.py"
$PytestExit = $LASTEXITCODE

# 5. Run Mock Simulation
Write-Host "[5/6] Running short live simulation..." -ForegroundColor Yellow
$SimProcess = Start-Process python -ArgumentList "$ProjectRoot\scripts\mock_event_sender.py" -WorkingDirectory $ProjectRoot -PassThru -NoNewWindow
Start-Sleep -Seconds 10
Stop-Process -Id $SimProcess.Id -Force -ErrorAction SilentlyContinue

# 6. Cleanup
Write-Host "[6/6] Shutting down FastAPI server..." -ForegroundColor Yellow
Stop-Process -Id $ApiProcess.Id -Force -ErrorAction SilentlyContinue

Write-Host "Test complete." -ForegroundColor Cyan
exit $PytestExit
