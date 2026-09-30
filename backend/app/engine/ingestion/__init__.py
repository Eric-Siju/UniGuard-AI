"""
Ingestion package for UniGuard AI
"""
from backend.app.engine.ingestion.base import BaseIngestionAdapter
from backend.app.engine.ingestion.zeek import ZeekJsonAdapter
from backend.app.engine.ingestion.suricata import SuricataEveAdapter
from backend.app.engine.ingestion.manager import ingestion_manager

__all__ = [
    "BaseIngestionAdapter",
    "ZeekJsonAdapter",
    "SuricataEveAdapter",
    "ingestion_manager"
]
