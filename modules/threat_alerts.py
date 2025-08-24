import hashlib
import time
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, Dict, List, Counter
from collections import defaultdict, deque

from .threat_types import ThreatType, ServiceType

@dataclass
class ThreatAlert:
    """Uproszczony alert bezpieczeństwa"""
    timestamp: datetime
    threat_type: ThreatType
    source_ip: str
    target_ip: str
    target_port: Optional[int]
    service: ServiceType
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    packet_count: int = 1
    data_volume: int = 0
    confidence: float = 1.0
    
    def __hash__(self):
        return hash((self.threat_type, self.source_ip, self.target_ip, self.target_port))
    
    def get_alert_id(self) -> str:
        """Unikalny identyfikator alertu"""
        data = f"{self.threat_type.value}{self.source_ip}{self.target_ip}{self.target_port}"
        return hashlib.md5(data.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "id": self.get_alert_id(),
            "timestamp": self.timestamp.isoformat(),
            "threat_type": self.threat_type.value,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "service": self.service.service_name,
            "severity": self.severity,
            "description": self.description,
            "packet_count": self.packet_count,
            "data_volume": self.data_volume,
            "confidence": self.confidence
        }


class AlertManager:
    """Uproszczony manager alertów z lepszym filtrowaniem"""
    
    def __init__(self, logger):
        self.logger = logger
        self.active_alerts = {}
        self.alert_history = deque(maxlen=1000)  # Zmniejszona historia
        self.last_alert_time = {}
        self.alert_counts = Counter()
        
        # Konfiguracja suppression (w sekundach)
        self.suppression_times = {
            ThreatType.PORT_SCAN: 300,      # 5 minut
            ThreatType.SYN_FLOOD: 60,       # 1 minuta
            ThreatType.UDP_FLOOD: 60,       # 1 minuta
            ThreatType.DOS_ATTACK: 120,     # 2 minuty
            ThreatType.DDOS_ATTACK: 180,    # 3 minuty
            ThreatType.BRUTE_FORCE: 600,    # 10 minut
        }
    
    def should_suppress_alert(self, alert: ThreatAlert) -> bool:
        """Inteligentne filtrowanie duplikatów"""
        alert_key = f"{alert.threat_type.value}:{alert.source_ip}:{alert.target_ip}"
        
        if alert_key not in self.last_alert_time:
            return False
        
        time_since_last = (datetime.now() - self.last_alert_time[alert_key]).total_seconds()
        suppression_time = self.suppression_times.get(alert.threat_type, 300)
        
        return time_since_last < suppression_time
    
    def add_alert(self, alert: ThreatAlert) -> bool:
        """Dodaje alert z filtrowaniem"""
        if self.should_suppress_alert(alert):
            return False
        
        alert_key = f"{alert.threat_type.value}:{alert.source_ip}:{alert.target_ip}"
        self.last_alert_time[alert_key] = datetime.now()
        self.alert_counts[alert_key] += 1
        
        # Dodaj do historii
        self.alert_history.append(alert)
        
        # Loguj alert
        self._log_alert(alert)
        return True
    
    def _log_alert(self, alert: ThreatAlert):
        """Loguje alert w czytelnym formacie"""
        severity_symbols = {
            "LOW": "🟡",
            "MEDIUM": "🟠", 
            "HIGH": "🔴",
            "CRITICAL": "🚨"
        }
        
        symbol = severity_symbols.get(alert.severity, "⚠️")
        
        log_msg = (
            f"{symbol} {alert.threat_type.value} | "
            f"{alert.source_ip} → {alert.target_ip}:{alert.target_port} | "
            f"{alert.service.service_name} | "
            f"Severity: {alert.severity} | "
            f"Confidence: {alert.confidence:.2f} | "
            f"{alert.description}"
        )
        
        # Import logger tutaj żeby uniknąć circular imports
        try:
            from modules.logger import security_logger
            security_logger.warning(log_msg)
        except ImportError:
            print(log_msg)
    
    def get_recent_alerts(self, minutes: int = 60) -> List[ThreatAlert]:
        """Zwraca ostatnie alerty"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [alert for alert in self.alert_history if alert.timestamp > cutoff_time]
    
    def get_stats(self) -> dict:
        """Zwraca statystyki alertów"""
        recent_alerts = self.get_recent_alerts(60)
        
        return {
            "total_alerts": len(self.alert_history),
            "recent_alerts": len(recent_alerts),
            "alert_types": {
                threat_type.value: len([a for a in recent_alerts if a.threat_type == threat_type])
                for threat_type in ThreatType
            },
            "severity_breakdown": {
                severity: len([a for a in recent_alerts if a.severity == severity])
                for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            }
        }