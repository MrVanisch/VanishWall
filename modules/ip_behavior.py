import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import deque, Counter
from typing import Set, Tuple, List
from statistics import mean

from .threat_types import AttackPattern

@dataclass
class IPBehavior:
    """Uproszczona analiza zachowania IP z lepszą wydajnością"""
    ip: str
    packet_count: int = 0
    bytes_sent: int = 0
    unique_ports_accessed: Set[int] = field(default_factory=set)
    protocols_used: Counter = field(default_factory=Counter)
    first_seen: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    
    # Okna czasowe - zmniejszone dla lepszej wydajności
    recent_ports: deque = field(default_factory=lambda: deque(maxlen=50))
    recent_packets: deque = field(default_factory=lambda: deque(maxlen=100))
    
    # TCP flags i połączenia
    syn_packets: int = 0
    connection_attempts: int = 0
    failed_connections: int = 0
    
    def update(self, dst_port: int, protocol: str, packet_size: int, 
               tcp_flags: str = "", success: bool = True):
        """Aktualizuje zachowanie IP"""
        current_time = datetime.now()
        
        # Podstawowe statystyki
        self.packet_count += 1
        self.bytes_sent += packet_size
        self.unique_ports_accessed.add(dst_port)
        self.protocols_used[protocol] += 1
        self.last_activity = current_time
        
        # TCP specific
        if protocol == "TCP":
            if "S" in tcp_flags and "A" not in tcp_flags:  # SYN bez ACK
                self.syn_packets += 1
                self.connection_attempts += 1
        
        if not success:
            self.failed_connections += 1
        
        # Dodaj do okien czasowych
        self.recent_ports.append((current_time, dst_port))
        self.recent_packets.append((current_time, packet_size, protocol))

    def get_recent_unique_ports(self, window_seconds: int = 60) -> Tuple[int, List[int], str]:
        """Zwraca liczbę unikalnych portów i wzorzec skanowania"""
        cutoff_time = datetime.now() - timedelta(seconds=window_seconds)
        recent_ports = []
        
        for timestamp, port in self.recent_ports:
            if timestamp > cutoff_time:
                recent_ports.append(port)
        
        unique_ports = list(set(recent_ports))
        unique_count = len(unique_ports)
        pattern = AttackPattern.detect_scan_pattern(unique_ports)
        
        return unique_count, unique_ports, pattern

    def get_packet_rate(self, window_seconds: int = 10) -> float:
        """Oblicza częstotliwość pakietów"""
        cutoff_time = datetime.now() - timedelta(seconds=window_seconds)
        recent_count = sum(1 for timestamp, _, _ in self.recent_packets 
                          if timestamp > cutoff_time)
        return recent_count / window_seconds if window_seconds > 0 else 0

    def is_syn_flood_pattern(self, window_seconds: int = 30) -> Tuple[bool, float]:
        """Wykrywa wzorzec SYN flood - uproszczone"""
        if self.syn_packets < 10:  # Minimum threshold
            return False, 0.0
        
        # Sprawdź częstotliwość SYN
        cutoff_time = datetime.now() - timedelta(seconds=window_seconds)
        recent_syn_count = 0
        
        for timestamp, _, protocol in self.recent_packets:
            if timestamp > cutoff_time and protocol == "TCP":
                recent_syn_count += 1
        
        syn_rate = recent_syn_count / window_seconds if window_seconds > 0 else 0
        
        # SYN flood jeśli więcej niż 10 SYN/s
        is_flood = syn_rate > 10
        confidence = min(syn_rate / 50, 1.0)  # Max confidence at 50 SYN/s
        
        return is_flood, confidence

    def get_protocol_diversity(self) -> float:
        """Oblicza różnorodność protokołów (0-1)"""
        if not self.protocols_used:
            return 0.0
        
        total = sum(self.protocols_used.values())
        # Shannon entropy - simplified
        entropy = 0
        for count in self.protocols_used.values():
            p = count / total
            if p > 0:
                entropy -= p * (p.bit_length() - 1)  # Simplified log calculation
        
        # Normalize to 0-1 range
        max_entropy = len(self.protocols_used).bit_length() - 1
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def is_suspicious_behavior(self) -> Tuple[bool, str, float]:
        """Wykrywa podejrzane zachowanie - główna funkcja detekcji"""
        suspicious_factors = []
        total_confidence = 0.0
        
        # 1. Port scanning
        unique_ports, ports_list, scan_pattern = self.get_recent_unique_ports(60)
        if unique_ports >= 10:
            confidence = min(unique_ports / 50, 1.0)
            if scan_pattern == AttackPattern.SEQUENTIAL_SCAN:
                confidence += 0.2
            elif scan_pattern == AttackPattern.COMMON_PORTS_SCAN:
                confidence += 0.3
            
            suspicious_factors.append(f"Port scan: {unique_ports} ports ({scan_pattern})")
            total_confidence += confidence
        
        # 2. High packet rate
        packet_rate = self.get_packet_rate(10)
        if packet_rate > 20:  # More than 20 packets/second
            confidence = min(packet_rate / 100, 1.0)
            suspicious_factors.append(f"High rate: {packet_rate:.1f} pps")
            total_confidence += confidence
        
        # 3. SYN flood
        is_syn_flood, syn_confidence = self.is_syn_flood_pattern()
        if is_syn_flood:
            suspicious_factors.append(f"SYN flood: {self.syn_packets} SYN packets")
            total_confidence += syn_confidence
        
        # 4. Protocol diversity (could indicate scanning)
        protocol_diversity = self.get_protocol_diversity()
        if protocol_diversity > 0.8 and len(self.protocols_used) > 2:
            suspicious_factors.append(f"Protocol diversity: {protocol_diversity:.2f}")
            total_confidence += 0.3
        
        # 5. High failure rate
        if self.connection_attempts > 5:
            failure_rate = self.failed_connections / self.connection_attempts
            if failure_rate > 0.7:
                suspicious_factors.append(f"High failure rate: {failure_rate:.1%}")
                total_confidence += failure_rate * 0.5
        
        is_suspicious = total_confidence > 0.5
        description = "; ".join(suspicious_factors) if suspicious_factors else "Normal behavior"
        final_confidence = min(total_confidence, 1.0)
        
        return is_suspicious, description, final_confidence

    def should_block(self) -> Tuple[bool, str]:
        """Decyduje czy IP powinien zostać zablokowany"""
        is_suspicious, description, confidence = self.is_suspicious_behavior()
        
        # Blokuj jeśli wysoka pewność lub ekstremalne zachowanie
        should_block = (
            confidence > 0.7 or  # High confidence
            self.get_packet_rate() > 100 or  # Very high rate
            len(self.unique_ports_accessed) > 50 or  # Excessive port scanning
            self.syn_packets > 100  # SYN flood
        )
        
        block_reason = ""
        if should_block:
            if confidence > 0.7:
                block_reason = f"High threat confidence: {confidence:.2f}"
            elif self.get_packet_rate() > 100:
                block_reason = f"Excessive packet rate: {self.get_packet_rate():.1f} pps"
            elif len(self.unique_ports_accessed) > 50:
                block_reason = f"Port scan: {len(self.unique_ports_accessed)} ports"
            elif self.syn_packets > 100:
                block_reason = f"SYN flood: {self.syn_packets} packets"
        
        return should_block, block_reason