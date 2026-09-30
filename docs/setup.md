# Setup & Installation Guide (docs/setup.md)

UniGuard AI is designed to run 100% locally and offline without external internet dependencies after initial package installation.

## Prerequisites
- **Python:** 3.11+ (Tested on Python 3.14 on Windows 64-bit)
- **Node.js:** 18+ (Tested on Node v24.15.0 with npm 11.12.1)
- **Git** (optional)

---

## 1. Backend Setup

### Create and Activate Virtual Environment
```powershell
# In project root:
py -3.14 -m venv .venv

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# On Linux/macOS:
source .venv/bin/activate
```

### Install Pinned Python Dependencies
```powershell
pip install -r backend/requirements.txt
```

### Generate Sample Datasets & Train Initial Models
```powershell
# Generate all 8 synthetic datasets in data/sample/
python -m backend.app.generator.traffic_generator

# Train Random Forest and Isolation Forest models with temporal context tracking
python -c "from backend.app.engine.ml_detector import ml_detector; ml_detector.train()"
```

---

## 2. Frontend Setup (Official Production Build)

The official application serves the compiled React application directly from FastAPI at `http://127.0.0.1:8000`.

```powershell
cd frontend
npm install
npm run build
cd ..
```

---

## 3. Launching the Application

### Single Official Production Web Application
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser. Both the React UI, the REST API endpoints, and the real-time WebSocket are fully operational on this single port.

---

## 4. Running Automated Tests

To run the complete test suite:
```powershell
# From workspace root:
.\.venv\Scripts\pytest.exe -v
```
All **16 unit and integration tests** will execute covering parsing, feature extraction, all 6 threat detection rules, botnet false-positive protection, ML inference, scenario whitelisting, file upload security, and SPA routing.
