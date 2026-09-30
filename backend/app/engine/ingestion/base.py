"""
Base Ingestion Adapter Interface for UniGuard AI
"""

from typing import Dict, Any, List, Tuple
from abc import ABC, abstractmethod

class BaseIngestionAdapter(ABC):
    source_type: str = "GENERIC"
    
    def __init__(self):
        self.records_received = 0
        self.records_parsed = 0
        self.records_rejected = 0
        self.parsing_errors: List[str] = []

    @abstractmethod
    def parse_content(self, text_or_bytes: str) -> List[Dict[str, Any]]:
        """Parses raw text/json log lines into UniGuard normalized flow dictionaries."""
        pass

    def get_stats(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "records_received": self.records_received,
            "records_parsed": self.records_parsed,
            "records_rejected": self.records_rejected,
            "error_count": len(self.parsing_errors),
            "recent_errors": self.parsing_errors[-5:]
        }
