import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Set, Optional

from .threat_types import ThreatType, ServiceType
from .threat_alerts import ThreatAlert, AlertManager
from .ip_behavior import IPBehavior

class EnhancedThreatDetector:
    """Uproszczony i wydajniejszy detektor zagrożeń"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.alert_manager = AlertManager(logger)
        
        # Główne struktury danych
        self.ip_behaviors: Dict[str, IPBehavior] = {}
        self.blocked_ips: Set[str] = set()
        
        # Tracking DDoS attacks
        self.target_attackers: Dict[str, Set[str]] = defaultdict(set)
        
        # Whitelist for local networks
        self.local_networks = [
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('127.0.0.0/8')
        ]
        
        # Configuration thresholds - simplified
        self.thresholds = {
            'port_scan_threshold': getattr(config, 'port_scan_threshold', 15),
            'dos_packet_threshold': getattr(config, 'dos_packet_threshold', 50),
            'ddos_source_threshold': getattr(config, 'ddos_source_threshold', 5),
            'brute_force_threshold': getattr(config, 'brute_force_threshold', 10),
            'syn_flood_threshold': getattr(config, 'syn_flood_threshold', 50)
        }
    
    def is_local_ip(self, ip_str: str) -> bool:
        """Sprawdza czy IP jest lokalny"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in self.local_networks)
        except:
            return False
    
    def analyze_packet(self, src_ip: str, dst_ip: str, dst_port: int, 
                      protocol: str, packet_size: int, tcp_flags: str = "") -> List[ThreatAlert]:
        """Główna funkcja analizy pakietu - uproszczona"""
        
        # Skip internal/local traffic
        if self.is_local_ip(src_ip) and self.is_local_ip(dst_ip):
            return []
        
        # Skip already blocked IPs to save resources
        if src_ip in self.blocked_ips:
            return []
        
        alerts = []
        
        # Update IP behavior
        if src_ip not in self.ip_behaviors:
            self.ip_behaviors[src_ip] = IPBehavior(src_ip)
        
        behavior = self.ip_behaviors[src_ip]
        behavior.update(dst_port, protocol, packet_size, tcp_flags)
        
        # Track potential DDoS targets
        target_key = f"{dst_ip}:{dst_port}"
        self.target_attackers[target_key].add(src_ip)
        
        # Service identification
        service = ServiceType.get_service_by_port(dst_port)
        
        # Main threat detection
        alerts.extend(self._detect_port_scan(behavior, src_ip, dst_ip, dst_port, service))
        alerts.extend(self._detect_dos_attack(behavior, src_ip, dst_ip, dst_port, service))
        alerts.extend(self._detect_syn_flood(behavior, src_ip, dst_ip, dst_port, service, tcp_flags))
        alerts.extend(self._detect_ddos_attack(target_key, dst_ip, dst_port, service))
        alerts.extend(self._detect_brute_force(behavior, src_ip, dst_ip, dst_port, service))
        
        # Add alerts to manager
        for alert in alerts:
            self.alert_manager.add_alert(alert)
        
        # Check if IP should be blocked
        should_block, block_reason = behavior.should_block()
        if should_block and src_ip not in self.blocked_ips:
            self.blocked_ips.add(src_ip)
            self._create_blocking_alert(src_ip, dst_ip, dst_port, service, block_reason)
        
        return alerts
    
    def _detect_port_scan(self, behavior: IPBehavior, src_ip: str, dst_ip: str, 
                         dst_port: int, service: ServiceType) -> List[ThreatAlert]:
        """Wykrywa skanowanie portów"""
        unique_ports, ports_list, scan_pattern = behavior.get_recent_unique_ports(60)
        
        if unique_ports < self.thresholds['port_scan_threshold']:
            return []
        
        # Określ severity na podstawie wzorca i liczby portów
        if scan_pattern == "sequential" or unique_ports > 50:
            severity = "HIGH"
            confidence = 0.9
        elif scan_pattern == "common_ports" or unique_ports > 30:
            severity = "MEDIUM"
            confidence = 0.7
        else:
            severity = "LOW"
            confidence = 0.5
        
        alert = ThreatAlert(
            timestamp=datetime.now(),
            threat_type=ThreatType.PORT_SCAN,
            source_ip=src_ip,
            target_ip=dst_ip,
            target_port=dst_port,
            service=service,
            severity=severity,
            description=f"Port scan: {unique_ports} ports, pattern: {scan_pattern}",
            packet_count=behavior.packet_count,
            data_volume=behavior.bytes_sent,
            confidence=confidence
        )
        
        return [alert]
    
    def _detect_dos_attack(self, behavior: IPBehavior, src_ip: str, dst_ip: str,
                          dst_port: int, service: ServiceType) -> List[ThreatAlert]:
        """Wykrywa atak DoS"""
        packet_rate = behavior.get_packet_rate(10)
        
        if packet_rate < self.thresholds['dos_packet_threshold']:
            return []
        
        # Określ severity na podstawie intensywności
        if packet_rate > 200:
            severity = "CRITICAL"
            confidence = 0.95
        elif packet_rate > 100:
            severity = "HIGH" 
            confidence = 0.8
        else:
            severity = "MEDIUM"
            confidence = 0.6
        
        alert = ThreatAlert(
            timestamp=datetime.now(),
            threat_type=ThreatType.DOS_ATTACK,
            source_ip=src_ip,
            target_ip=dst_ip,
            target_port=dst_port,
            service=service,
            severity=severity,
            description=f"DoS attack: {packet_rate:.1f} packets/second",
            packet_count=behavior.packet_count,
            data_volume=behavior.bytes_sent,
            confidence=confidence
        )
        
        return [alert]
    
    def _detect_syn_flood(self, behavior: IPBehavior, src_ip: str, dst_ip: str,
                         dst_port: int, service: ServiceType, tcp_flags: str) -> List[ThreatAlert]:
        """Wykrywa atak SYN flood"""
        is_syn_flood, syn_confidence = behavior.is_syn_flood_pattern()
        
        if not is_syn_flood or syn_confidence < 0.5:
            return []
        
        severity = "CRITICAL" if syn_confidence > 0.8 else "HIGH"
        
        alert = ThreatAlert(
            timestamp=datetime.now(),
            threat_type=ThreatType.SYN_FLOOD,
            source_ip=src_ip,
            target_ip=dst_ip,
            target_port=dst_port,
            service=service,
            severity=severity,
            description=f"SYN flood: {behavior.syn_packets} SYN packets",
            packet_count=behavior.syn_packets,
            data_volume=behavior.bytes_sent,
            confidence=syn_confidence
        )
        
        return [alert]
    
    def _detect_ddos_attack(self, target_key: str, dst_ip: str, dst_port: int,
                           service: ServiceType) -> List[ThreatAlert]:
        """Wykrywa atak DDoS"""
        attacker_count = len(self.target_attackers[target_key])
        
        if attacker_count < self.thresholds['ddos_source_threshold']:
            return []
        
        # Oblicz łączną częstotliwość ataków
        total_packet_rate = 0
        for attacker_ip in self.target_attackers[target_key]:
            if attacker_ip in self.ip_behaviors:
                total_packet_rate += self.ip_behaviors[attacker_ip].get_packet_rate()
        
        if total_packet_rate < self.thresholds['dos_packet_threshold']:
            return []
        
        # Określ severity
        if attacker_count > 20 or total_packet_rate > 500:
            severity = "CRITICAL"
            confidence = 0.95
        elif attacker_count > 10 or total_packet_rate > 200:
            severity = "HIGH"
            confidence = 0.8
        else:
            severity = "MEDIUM"
            confidence = 0.6
        
        alert = ThreatAlert(
            timestamp=datetime.now(),
            threat_type=ThreatType.DDOS_ATTACK,
            source_ip=f"Multiple({attacker_count})",
            target_ip=dst_ip,
            target_port=dst_port,
            service=service,
            severity=severity,
            description=f"DDoS: {attacker_count} sources, {total_packet_rate:.1f} pps total",
            packet_count=sum(self.ip_behaviors.get(ip, IPBehavior("")).packet_count 
                           for ip in self.target_attackers[target_key]),
            confidence=confidence
        )
        
        return [alert]
    
    def _detect_brute_force(self, behavior: IPBehavior, src_ip: str, dst_ip: str,
                           dst_port: int, service: ServiceType) -> List[ThreatAlert]:
        """Wykrywa atak brute force na usługi wymagające autoryzacji"""
        # Sprawdź tylko dla usług wymagających logowania
        if not service.is_critical_service():
            return []
        
        if behavior.connection_attempts < self.thresholds['brute_force_threshold']:
            return []
        
        failure_rate = behavior.failed_connections / max(behavior.connection_attempts, 1)
        if failure_rate < 0.5:  # Mniej niż 50% niepowodzeń
            return []
        
        # Określ severity na podstawie liczby prób i wskaźnika błędów
        if behavior.failed_connections > 50 and failure_rate > 0.8:
            severity = "HIGH"
            confidence = 0.9
        elif behavior.failed_connections > 20 and failure_rate > 0.7:
            severity = "MEDIUM"
            confidence = 0.7
        else:
            severity = "LOW"
            confidence = 0.5
        
        alert = ThreatAlert(
            timestamp=datetime.now(),
            threat_type=ThreatType.BRUTE_FORCE,
            source_ip=src_ip,
            target_ip=dst_ip,
            target_port=dst_port,
            service=service,
            severity=severity,
            description=f"Brute force: {behavior.failed_connections} failed attempts ({failure_rate:.1%})",
            packet_count=behavior.connection_attempts,
            confidence=confidence
        )
        
        return [alert]
    
    def _create_blocking_alert(self, src_ip: str, dst_ip: str, dst_port: int,
                              service: ServiceType, reason: str):
        """Tworzy alert o zablokowaniu IP"""
        alert = ThreatAlert(
            timestamp=datetime.now(),
            threat_type=ThreatType.SUSPICIOUS_ACTIVITY,
            source_ip=src_ip,
            target_ip=dst_ip,
            target_port=dst_port,
            service=service,
            severity="CRITICAL",
            description=f"IP BLOCKED: {reason}",
            confidence=1.0
        )
        
        self.alert_manager.add_alert(alert)
        
        # Integracja z ACL Manager
        try:
            from modules.acl import ACLManager
            acl = ACLManager()
            acl.block_ip(src_ip, f"Security Monitor: {reason}")
        except ImportError:
            pass  # ACL Manager niedostępny
    
    def cleanup_old_data(self, hours: int = 2):
        """Czyści stare dane - zoptymalizowane"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Usuń stare zachowania IP
        to_remove = []
        for ip, behavior in self.ip_behaviors.items():
            if behavior.last_activity < cutoff_time:
                to_remove.append(ip)
        
        for ip in to_remove:
            del self.ip_behaviors[ip]
            self.blocked_ips.discard(ip)
        
        # Wyczyść cele DDoS
        for target_key in list(self.target_attackers.keys()):
            # Usuń nieaktywnych atakujących
            active_attackers = {ip for ip in self.target_attackers[target_key] 
                              if ip in self.ip_behaviors}
            if active_attackers:
                self.target_attackers[target_key] = active_attackers
            else:
                del self.target_attackers[target_key]
    
    def get_recent_alerts(self, minutes: int = 60) -> List[ThreatAlert]:
        """Zwraca ostatnie alerty"""
        return self.alert_manager.get_recent_alerts(minutes)
    
    def get_threat_summary(self) -> dict:
        """Zwraca zwięzłe podsumowanie zagrożeń"""
        recent_alerts = self.get_recent_alerts(60)
        
        # Top 5 atakujących
        top_attackers = sorted(
            [(ip, behavior) for ip, behavior in self.ip_behaviors.items()],
            key=lambda x: x[1].packet_count,
            reverse=True
        )[:5]
        
        # Top 5 celów DDoS
        top_ddos_targets = sorted(
            [(target, attackers) for target, attackers in self.target_attackers.items()],
            key=lambda x: len(x[1]),
            reverse=True
        )[:5]
        
        return {
            "monitored_ips": len(self.ip_behaviors),
            "blocked_ips": len(self.blocked_ips),
            "recent_alerts": len(recent_alerts),
            "alert_stats": self.alert_manager.get_stats(),
            "top_attackers": [
                {
                    "ip": ip,
                    "packets": behavior.packet_count,
                    "ports": len(behavior.unique_ports_accessed),
                    "rate": behavior.get_packet_rate()
                }
                for ip, behavior in top_attackers
            ],
            "ddos_targets": [
                {
                    "target": target,
                    "attackers": len(attackers)
                }
                for target, attackers in top_ddos_targets if len(attackers) >= 3
            ]
        }