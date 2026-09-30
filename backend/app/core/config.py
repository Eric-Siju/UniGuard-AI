"""
Core Configuration for UniGuard AI
Passive Unidirectional Cyber Threat Detection System
"""

from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BASE_DIR.parent
DATA_DIR = PROJECT_ROOT / "data" / "sample"
SAVED_MODELS_DIR = BASE_DIR / "saved_models"
REPORTS_DIR = BASE_DIR / "reports"
UPLOAD_DIR = BASE_DIR / "uploads"

DATA_DIR.mkdir(parents=True, exist_ok=True)
SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = BASE_DIR / "uniguard.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

class Settings(BaseModel):
    APP_NAME: str = "UniGuard AI"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Passive Unidirectional Cyber Threat Detection for Air-Gapped and Diode Networks"
    
    # Strictly Passive Monitored Network Guarantees
    PASSIVE_MODE: bool = True
    READ_ONLY_MONITORING: bool = True
    ACTIVE_RESPONSE_ENABLED: bool = False
    ALLOW_PACKET_INJECTION: bool = False
    ALLOW_PAYLOAD_DECRYPTION: bool = False
    
    DATABASE_URL: str = DATABASE_URL
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_EXTENSIONS: list[str] = [".pcap", ".pcapng", ".cap", ".csv"]
    
    # Multi-signal thresholds (configurable via settings API)
    DDOS_PACKET_RATE_THRESHOLD: float = 250.0  # pkts/sec
    DDOS_SYN_RATIO_THRESHOLD: float = 0.80
    PORT_SCAN_PORT_THRESHOLD: int = 15
    PORT_SCAN_FAN_OUT_THRESHOLD: int = 10
    BOTNET_INTERVAL_JITTER_MAX: float = 0.20  # seconds std dev
    BOTNET_MIN_BEACONS: int = 4
    DNS_ENTROPY_THRESHOLD: float = 3.5
    DNS_LENGTH_THRESHOLD: int = 28
    EXFILTRATION_BYTES_THRESHOLD: int = 4_000_000  # 4MB
    EXFILTRATION_RATIO_THRESHOLD: float = 10.0
    
    # Streaming simulation settings
    DEFAULT_STREAM_INTERVAL: float = 0.6  # sec
    DEFAULT_BATCH_SIZE: int = 4
    DEFAULT_SPEED_MULTIPLIER: float = 1.0

settings = Settings()
