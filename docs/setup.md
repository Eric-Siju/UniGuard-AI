# Setup & Installation Guide (docs/setup.md)

UniGuard AI is designed to run 100% locally and offline without external internet dependencies after initial package installation.

## Prerequisites
- **Python:** 3.11+ (Tested on Python 3.14 on Windows 64-bit)
- **Node.js:** 18+ (Tested on Node v24.15.0 with npm 11.12.1)
- **Git** (optional)

---

## 1. Backend Setup

### Create and Activate Virtual Environment
```bash
# In project root:
py -3.14 -m venv .venv

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# On Linux/macOS:
source .venv/bin/activate
```

### Install Python Dependencies
```bash
pip install fastapi "uvicorn[standard]" pydantic sqlalchemy scapy pandas numpy scikit-learn python-multipart websockets pytest httpx psutil jinja2
```

### Generate Sample Datasets & Train Initial Models
```bash
# Generate all 8 synthetic datasets in data/sample/
python -m backend.app.generator.traffic_generator

# Train Random Forest and Isolation Forest models
python -c "from backend.app.engine.ml_detector import ml_detector; ml_detector.train()"
```

### Run Backend Server
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
The backend API is now running at `http://127.0.0.1:8000`.

---

## 2. Frontend Setup

### Install Node Dependencies
```bash
cd frontend
npm install
```

### Run Frontend Dev Server
```bash
npm run dev
```
The frontend application is now running at `http://localhost:3000`.

---

## 3. Running Automated Tests

To run the complete test suite:
```bash
# From workspace root:
$env:PYTHONPATH="."
.\.venv\Scripts\pytest.exe backend/tests/test_pipeline.py -v
```
All 11 tests will execute covering parsing, feature extraction, all 6 rules, ML inference, and REST endpoints.
