from scapy.all import sniff, IP, UDP, get_if_list
import time
import threading
import queue
from collections import defaultdict, deque
from statistics import mean, stdev, median
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, Set, Tuple
import socket
import struct
import hashlib
import weakref
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger
from config import CONFIG

# Konfiguracja
UDP_LIMIT = CONFIG.get("UDP_LIMIT", 100)
CHECK_INTERVAL = CONFIG.get("CHECK_INTERVAL_UDP", 1)
MAX_HISTORY_SIZE = CONFIG.get("MAX_HISTORY_SIZE", 10)
PACKET_QUEUE_SIZE = CONFIG.get("PACKET_QUEUE_SIZE", 2000)
WORKER_THREADS = CONFIG.get("UDP_WORKER_THREADS", 3)
ANOMALY_THRESHOLD_MULTIPLIER = CONFIG.get("ANOMALY_THRESHOLD_MULTIPLIER", 2)

# Nowe agresywne parametry
BURST_DETECTION_WINDOW = 2  # okno 2 sekundy na burst
BURST_THRESHOLD = 50        # 50 pakietów w 2 sekundy = blokada
PATTERN_ANALYSIS_ENABLED = True
GEOLOCATION_BLOCKING = True
PORT_SCAN_DETECTION = True

@dataclass
class PacketFingerprint:
    """Zaawansowany fingerprint pakietu do wykrywania wzorców"""
    src_ip: str
    dst_port: int
    packet_size: int
    payload_hash: str
    timestamp: float
    ttl: int = 0
    flags: str = ""

@dataclass
class IPThreatProfile:
    """Profil zagrożenia IP z wieloma metrykami"""
    ip: str
    packet_count: int = 0
    last_seen: float = 0
    first_seen: float = 0
    burst_count: int = 0
    unique_ports: Set[int] = field(default_factory=set)
    packet_sizes: deque = field(default_factory=lambda: deque(maxlen=50))
    payload_hashes: Set[str] = field(default_factory=set)
    history: deque = field(default_factory=lambda: deque(maxlen=MAX_HISTORY_SIZE))
    threat_score: float = 0.0
    is_suspicious: bool = False
    geolocation: str = ""
    
    def calculate_threat_score(self) -> float:
        """Oblicza threat score na podstawie różnych czynników"""
        score = 0.0
        
        # Wysoka częstotliwość pakietów
        if self.packet_count > UDP_LIMIT:
            score += min(self.packet_count / UDP_LIMIT * 100, 500)
        
        # Port scanning (wiele unikalnych portów)
        if len(self.unique_ports) > 10:
            score += len(self.unique_ports) * 10
        
        # Burst detection
        if self.burst_count > 3:
            score += self.burst_count * 50
        
        # Jednakowe payload (amplification attacks)
        if len(self.payload_hashes) <= 3 and self.packet_count > 20:
            score += 200
        
        # Podejrzane rozmiary pakietów (bardzo małe lub bardzo duże)
        if self.packet_sizes:
            avg_size = mean(self.packet_sizes)
            if avg_size < 50 or avg_size > 1400:
                score += 100
        
        # Podejrzane geolokalizacje
        suspicious_countries = ['CN', 'RU', 'KP', 'IR']
        if self.geolocation in suspicious_countries:
            score += 150
        
        self.threat_score = score
        return score

class AdvancedUDPFloodDetector:
    """Zaawansowany detektor UDP flood z multiple detection methods"""
    
    def __init__(self, acl_manager: ACLManager):
        self.acl = acl_manager
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue(maxsize=PACKET_QUEUE_SIZE)
        
        # Thread-safe struktury danych
        self._lock = threading.RLock()
        self.threat_profiles: Dict[str, IPThreatProfile] = {}
        
        # Burst detection
        self.burst_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Pattern analysis
        self.known_attack_patterns: Set[str] = set()
        self.legitimate_patterns: Set[str] = set()
        
        # Rate limiting per IP
        self.rate_limiters: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Emergency blocking
        self.emergency_blocked: Set[str] = set()
        self.whitelist: Set[str] = {'127.0.0.1', '::1'}
        
        # Wątki
        self.worker_threads = []
        self.monitor_thread = None
        self.burst_monitor_thread = None
        self.pattern_analyzer_thread = None
        self.cleanup_thread = None
        self.sniffer_thread = None
        
        # Statystyki
        self.processed_packets = 0
        self.blocked_ips = set()
        self.legitimate_ips = set()
        
        # Callback
        self.custom_analysis_callback: Optional[Callable] = None
        
        system_logger.info("🛡️ AdvancedUDPFloodDetector zainicjowany")
        self._load_known_patterns()

    def _load_known_patterns(self):
        """Ładuje znane wzorce ataków"""
        # Znane wzorce ataków UDP flood
        self.known_attack_patterns.update([
            "amplification_dns", "amplification_ntp", "amplification_snmp",
            "memcached_amplification", "chargen_amplification"
        ])
        
        # Wzorce legitymnego ruchu
        self.legitimate_patterns.update([
            "dns_query", "ntp_sync", "dhcp_request"
        ])

    def _get_packet_pattern(self, packet_info: PacketFingerprint) -> str:
        """Identyfikuje wzorzec pakietu"""
        # DNS amplification
        if packet_info.dst_port == 53 and packet_info.packet_size > 500:
            return "amplification_dns"
        
        # NTP amplification
        if packet_info.dst_port == 123 and packet_info.packet_size > 400:
            return "amplification_ntp"
        
        # SNMP amplification
        if packet_info.dst_port == 161 and packet_info.packet_size > 300:
            return "amplification_snmp"
        
        # Memcached amplification
        if packet_info.dst_port == 11211:
            return "memcached_amplification"
        
        # Chargen amplification
        if packet_info.dst_port == 19:
            return "chargen_amplification"
        
        # Small packet flood
        if packet_info.packet_size < 64:
            return "small_packet_flood"
        
        # Fragmented flood
        if packet_info.packet_size > 1400:
            return "fragmented_flood"
        
        return "unknown"

    def _is_geolocation_suspicious(self, ip: str) -> Tuple[bool, str]:
        """Sprawdza czy IP pochodzi z podejrzanej lokalizacji"""
        # Simplified geolocation check - w produkcji użyj prawdziwej bazy GeoIP
        suspicious_ranges = [
            ('1.2.3.0', '1.2.3.255'),  # Przykład
            ('5.2.64.0', '5.2.79.255'),  # Znane zakresy botnetów
        ]
        
        # Tu dodaj prawdziwą implementację GeoIP
        return False, "XX"

    def _packet_processor_worker(self, worker_id: int):
        """Zaawansowany worker do przetwarzania pakietów"""
        debug_logger.debug(f"🔧 Advanced Worker {worker_id} rozpoczął pracę")
        
        while not self.stop_event.is_set():
            try:
                packet_info = self.packet_queue.get(timeout=1)
                self._advanced_packet_analysis(packet_info, worker_id)
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                system_logger.error(f"❌ Błąd w advanced worker {worker_id}: {e}", exc_info=True)

    def _advanced_packet_analysis(self, packet_info: PacketFingerprint, worker_id: int):
        """Zaawansowana analiza pakietu z multiple checks"""
        try:
            # Whitelist check
            if packet_info.src_ip in self.whitelist:
                return
            
            # Emergency block check
            if packet_info.src_ip in self.emergency_blocked:
                return
            
            current_time = time.time()
            
            with self._lock:
                # Pobierz/utwórz profil IP
                if packet_info.src_ip not in self.threat_profiles:
                    self.threat_profiles[packet_info.src_ip] = IPThreatProfile(
                        ip=packet_info.src_ip,
                        first_seen=current_time
                    )
                
                profile = self.threat_profiles[packet_info.src_ip]
                profile.packet_count += 1
                profile.last_seen = current_time
                profile.unique_ports.add(packet_info.dst_port)
                profile.packet_sizes.append(packet_info.packet_size)
                profile.payload_hashes.add(packet_info.payload_hash)
                
                # Geolocation check
                if not profile.geolocation:
                    is_suspicious, geo = self._is_geolocation_suspicious(packet_info.src_ip)
                    profile.geolocation = geo
                    if is_suspicious:
                        profile.is_suspicious = True
                
                self.processed_packets += 1
                
                # IMMEDIATE BLOCKING CONDITIONS
                
                # 1. Rate limiting - bardzo agresywne
                rate_window = self.rate_limiters[packet_info.src_ip]
                rate_window.append(current_time)
                
                # Usuń stare wpisy (ostatnie 5 sekund)
                while rate_window and rate_window[0] < current_time - 5:
                    rate_window.popleft()
                
                # Jeśli więcej niż 30 pakietów w 5 sekund - BLOKUJ
                if len(rate_window) > 30:
                    self._immediate_block(packet_info.src_ip, "Rate limit exceeded (30 pkt/5s)", profile)
                    return
                
                # 2. Burst detection - bardzo szybka blokada
                burst_window = self.burst_tracker[packet_info.src_ip]
                burst_window.append(current_time)
                
                # Usuń stare burst wpisy (ostatnie 2 sekundy)
                while burst_window and burst_window[0] < current_time - BURST_DETECTION_WINDOW:
                    burst_window.popleft()
                
                # Jeśli burst threshold przekroczony
                if len(burst_window) > BURST_THRESHOLD:
                    profile.burst_count += 1
                    self._immediate_block(packet_info.src_ip, f"Burst detected ({len(burst_window)} pkt/2s)", profile)
                    return
                
                # 3. Pattern analysis
                pattern = self._get_packet_pattern(packet_info)
                if pattern in self.known_attack_patterns:
                    self._immediate_block(packet_info.src_ip, f"Attack pattern: {pattern}", profile)
                    return
                
                # 4. Port scanning detection
                if len(profile.unique_ports) > 20:  # Więcej niż 20 portów
                    self._immediate_block(packet_info.src_ip, f"Port scanning ({len(profile.unique_ports)} ports)", profile)
                    return
                
                # 5. Amplification detection
                if (packet_info.packet_size > 1000 and 
                    packet_info.dst_port in [53, 123, 161, 1900, 11211]):
                    self._immediate_block(packet_info.src_ip, f"Amplification attack on port {packet_info.dst_port}", profile)
                    return
                
                # 6. Threat score calculation
                threat_score = profile.calculate_threat_score()
                if threat_score > 300:  # Niski próg = agresywna blokada
                    self._immediate_block(packet_info.src_ip, f"High threat score: {threat_score:.1f}", profile)
                    return
                
                # Custom analysis callback
                if self.custom_analysis_callback:
                    should_block = self.custom_analysis_callback(packet_info)
                    if should_block:
                        self._immediate_block(packet_info.src_ip, "Custom analysis detection", profile)
                        return
                
                debug_logger.debug(f"📦 Worker {worker_id}: UDP od {packet_info.src_ip}:{packet_info.dst_port} "
                                 f"(łącznie: {profile.packet_count}, threat: {threat_score:.1f})")
                
        except Exception as e:
            system_logger.error(f"❌ Błąd advanced analysis dla {packet_info.src_ip}: {e}")

    def _immediate_block(self, ip: str, reason: str, profile: IPThreatProfile):
        """Natychmiastowa blokada IP"""
        if self.acl.is_blocked(ip) or ip in self.blocked_ips:
            return
        
        try:
            # Emergency block - dodatkowa warstwa
            self.emergency_blocked.add(ip)
            
            self.acl.block_ip(ip, reason=reason)
            self.blocked_ips.add(ip)
            
            severity = "CRITICAL" if profile.threat_score > 500 else "HIGH"
            
            msg = f"🚨 IMMEDIATE UDP BLOCK: {ip} - {reason} (threat: {profile.threat_score:.1f}, severity: {severity})"
            print(msg)
            system_logger.warning(msg)
            security_logger.critical(f"🛑 Natychmiastowa blokada UDP – IP: {ip}, {reason}, "
                                   f"packets: {profile.packet_count}, ports: {len(profile.unique_ports)}, "
                                   f"threat_score: {profile.threat_score:.1f}")
            
        except Exception as e:
            system_logger.error(f"❌ Błąd immediate block IP {ip}: {e}")

    def _monitor_traffic(self):
        """Monitor ruchu z zaawansowaną analizą trendów"""
        debug_logger.debug("📊 Advanced monitor ruchu rozpoczął pracę")
        
        while not self.stop_event.is_set():
            try:
                time.sleep(CHECK_INTERVAL)
                self._advanced_traffic_analysis()
                
            except Exception as e:
                system_logger.error(f"❌ Błąd w advanced monitor: {e}", exc_info=True)

    def _advanced_traffic_analysis(self):
        """Zaawansowana analiza wzorców ruchu"""
        current_time = time.time()
        
        with self._lock:
            # Analiza wszystkich profili IP
            for ip, profile in list(self.threat_profiles.items()):
                if ip in self.blocked_ips or ip in self.emergency_blocked:
                    continue
                
                # Skip if no recent activity
                if current_time - profile.last_seen > CHECK_INTERVAL * 3:
                    continue
                
                # Aktualizuj historię
                profile.history.append(profile.packet_count)
                
                # Zaawansowana analiza statystyczna
                if len(profile.history) >= 3:
                    recent_avg = mean(list(profile.history)[-3:])  # Ostatnie 3 pomiary
                    overall_avg = mean(profile.history)
                    
                    # Trend analysis - nagły wzrost
                    if recent_avg > overall_avg * 3 and recent_avg > UDP_LIMIT:
                        self._immediate_block(ip, f"Traffic trend anomaly (recent: {recent_avg:.1f}, avg: {overall_avg:.1f})", profile)
                        continue
                
                # Consistency analysis - zbyt regularne pakiety (boty)
                if len(profile.history) >= 5:
                    std_dev = stdev(profile.history)
                    if std_dev < 2 and mean(profile.history) > 20:  # Bardzo regularne
                        self._immediate_block(ip, f"Bot-like behavior (std_dev: {std_dev:.1f})", profile)
                        continue
                
                # Reset counters
                profile.packet_count = 0

    def _burst_monitor(self):
        """Dedykowany monitor burst detection"""
        debug_logger.debug("💥 Burst monitor rozpoczął pracę")
        
        while not self.stop_event.is_set():
            try:
                time.sleep(0.5)  # Bardzo częste sprawdzanie
                current_time = time.time()
                
                with self._lock:
                    for ip, burst_times in list(self.burst_tracker.items()):
                        if ip in self.blocked_ips:
                            continue
                        
                        # Clean old entries
                        while burst_times and burst_times[0] < current_time - BURST_DETECTION_WINDOW:
                            burst_times.popleft()
                        
                        # Check for micro-bursts (bardzo krótkie, intensywne ataki)
                        if len(burst_times) > 20:  # 20 pakietów w 0.5s
                            recent_packets = [t for t in burst_times if t > current_time - 0.5]
                            if len(recent_packets) > 20:
                                if ip in self.threat_profiles:
                                    self._immediate_block(ip, f"Micro-burst detected ({len(recent_packets)} pkt/0.5s)", 
                                                        self.threat_profiles[ip])
                
            except Exception as e:
                system_logger.error(f"❌ Błąd w burst monitor: {e}", exc_info=True)

    def _cleanup_old_data(self):
        """Zaawansowane czyszczenie z inteligentnym GC"""
        debug_logger.debug("🧹 Advanced cleanup rozpoczął pracę")
        
        while not self.stop_event.is_set():
            try:
                time.sleep(CHECK_INTERVAL * 2)
                current_time = time.time()
                cleanup_threshold = CHECK_INTERVAL * 10
                
                with self._lock:
                    # Cleanup threat profiles
                    old_ips = [
                        ip for ip, profile in self.threat_profiles.items()
                        if current_time - profile.last_seen > cleanup_threshold
                        and ip not in self.blocked_ips
                    ]
                    
                    for ip in old_ips:
                        del self.threat_profiles[ip]
                        self.burst_tracker.pop(ip, None)
                        self.rate_limiters.pop(ip, None)
                        self.emergency_blocked.discard(ip)
                    
                    # Cleanup blocked IPs that should be unblocked
                    expired_blocks = []
                    for ip in list(self.emergency_blocked):
                        if not self.acl.is_blocked(ip):
                            expired_blocks.append(ip)
                    
                    for ip in expired_blocks:
                        self.emergency_blocked.discard(ip)
                        self.blocked_ips.discard(ip)
                
                if old_ips:
                    debug_logger.debug(f"🧹 Wyczyszczono dane dla {len(old_ips)} nieaktywnych IP, "
                                     f"odblokowano {len(expired_blocks)} IP")
                    
            except Exception as e:
                system_logger.error(f"❌ Błąd w advanced cleanup: {e}", exc_info=True)

    def _packet_callback(self, packet):
        """Zaawansowany callback z pre-filtering"""
        if self.stop_event.is_set():
            return
        
        try:
            if packet.haslayer(IP) and packet.haslayer(UDP):
                src_ip = packet[IP].src
                
                # Quick emergency block check
                if src_ip in self.emergency_blocked:
                    return  # Drop packet immediately
                
                # Create advanced fingerprint
                payload = bytes(packet[UDP].payload) if packet[UDP].payload else b''
                payload_hash = hashlib.md5(payload[:100]).hexdigest()  # First 100 bytes
                
                packet_info = PacketFingerprint(
                    src_ip=src_ip,
                    dst_port=packet[UDP].dport,
                    packet_size=len(packet),
                    payload_hash=payload_hash,
                    timestamp=time.time(),
                    ttl=packet[IP].ttl,
                    flags=str(packet[IP].flags)
                )
                
                # Non-blocking put with overflow handling
                try:
                    self.packet_queue.put_nowait(packet_info)
                except queue.Full:
                    # Emergency: if queue full, block highest threat IPs immediately
                    debug_logger.warning("⚠️ Queue overflow - applying emergency blocks")
                    self._emergency_queue_overflow_handler()
                    
        except Exception as e:
            debug_logger.error(f"❌ Błąd w advanced packet_callback: {e}")

    def _emergency_queue_overflow_handler(self):
        """Emergency handler gdy kolejka się przepełnia"""
        try:
            with self._lock:
                # Znajdź IP z najwyższym threat score
                threat_ips = [(ip, profile.calculate_threat_score()) 
                             for ip, profile in self.threat_profiles.items()
                             if ip not in self.blocked_ips]
                
                threat_ips.sort(key=lambda x: x[1], reverse=True)
                
                # Zablokuj top 10 najbardziej podejrzanych IP
                for ip, score in threat_ips[:10]:
                    if score > 100:  # Only if significant threat
                        self._immediate_block(ip, f"Emergency queue overflow (score: {score:.1f})", 
                                            self.threat_profiles[ip])
                
        except Exception as e:
            system_logger.error(f"❌ Błąd emergency overflow handler: {e}")

    def start(self):
        """Uruchamia zaawansowany detektor"""
        if not self.stop_event.is_set():
            system_logger.warning("⚠️ Advanced detektor już działa")
            return
        
        print("🛡️ Uruchamianie zaawansowanej ochrony UDP flood...")
        system_logger.info("🛡️ Advanced UDP flood detection started")
        
        self.stop_event.clear()
        self.processed_packets = 0
        self.blocked_ips.clear()
        self.emergency_blocked.clear()
        
        try:
            # Worker threads (więcej)
            for i in range(WORKER_THREADS):
                worker = threading.Thread(
                    target=self._packet_processor_worker,
                    args=(i,),
                    name=f"AdvUDPWorker-{i}",
                    daemon=True
                )
                worker.start()
                self.worker_threads.append(worker)
            
            # Advanced monitor
            self.monitor_thread = threading.Thread(
                target=self._monitor_traffic,
                name="AdvUDPMonitor",
                daemon=True
            )
            self.monitor_thread.start()
            
            # Burst monitor
            self.burst_monitor_thread = threading.Thread(
                target=self._burst_monitor,
                name="UDPBurstMonitor",
                daemon=True
            )
            self.burst_monitor_thread.start()
            
            # Cleanup
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_old_data,
                name="AdvUDPCleanup",
                daemon=True
            )
            self.cleanup_thread.start()
            
            # Sniffer
            self.sniffer_thread = threading.Thread(
                target=self._run_sniffer,
                name="AdvUDPSniffer",
                daemon=True
            )
            self.sniffer_thread.start()
            
            system_logger.info(f"🚀 Advanced UDP Detector: {WORKER_THREADS} workers, burst monitor, pattern analyzer")
            
        except Exception as e:
            system_logger.error(f"❌ Błąd uruchamiania advanced detektora: {e}", exc_info=True)
            self.stop()

    def _run_sniffer(self):
        """Uruchamia sniffer z zaawansowanym filtrowaniem"""
        try:
            debug_logger.debug("🔍 Advanced sniffer rozpoczął nasłuchiwanie")
            
            # Bardziej precyzyjny filtr
            advanced_filter = "udp and not port 67 and not port 68"  # Exclude DHCP
            
            sniff(
                filter=advanced_filter,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except Exception as e:
            system_logger.error("❌ Błąd advanced sniffera UDP", exc_info=True)
        finally:
            debug_logger.debug("📴 Advanced sniffer zakończony")

    def stop(self):
        """Zatrzymuje zaawansowany detektor"""
        print("🛑 Zatrzymywanie zaawansowanej ochrony UDP flood...")
        system_logger.info("🛑 Zatrzymywanie advanced UDP flood detection")
        
        self.stop_event.set()
        
        try:
            # Quick cleanup
            try:
                while not self.packet_queue.empty():
                    self.packet_queue.get_nowait()
            except queue.Empty:
                pass
            
            # Join threads
            all_threads = [
                *self.worker_threads,
                self.monitor_thread,
                self.burst_monitor_thread,
                self.cleanup_thread,
                self.sniffer_thread
            ]
            
            for thread in all_threads:
                if thread and thread.is_alive():
                    thread.join(timeout=3)
            
            # Final stats
            with self._lock:
                active_profiles = len(self.threat_profiles)
                blocked_count = len(self.blocked_ips)
                emergency_blocked_count = len(self.emergency_blocked)
            
            system_logger.info(f"📊 Advanced detektor zatrzymany. Przetworzono: {self.processed_packets} "
                             f"pakietów, aktywnych profili: {active_profiles}, "
                             f"zablokowanych: {blocked_count}, emergency blocks: {emergency_blocked_count}")
            
            # Cleanup
            self.worker_threads.clear()
            self.monitor_thread = None
            self.burst_monitor_thread = None
            self.cleanup_thread = None
            self.sniffer_thread = None
            
        except Exception as e:
            system_logger.error("❌ Błąd zatrzymywania advanced detektora", exc_info=True)

    def get_stats(self) -> dict:
        """Zwraca zaawansowane statystyki"""
        with self._lock:
            threat_scores = [p.calculate_threat_score() for p in self.threat_profiles.values()]
            avg_threat = mean(threat_scores) if threat_scores else 0
            
            return {
                "processed_packets": self.processed_packets,
                "active_profiles": len(self.threat_profiles),
                "blocked_ips": len(self.blocked_ips),
                "emergency_blocked": len(self.emergency_blocked),
                "queue_size": self.packet_queue.qsize(),
                "is_running": not self.stop_event.is_set(),
                "average_threat_score": round(avg_threat, 2),
                "high_threat_ips": len([p for p in self.threat_profiles.values() if p.calculate_threat_score() > 200]),
                "total_unique_ports": sum(len(p.unique_ports) for p in self.threat_profiles.values()),
                "known_attack_patterns": len(self.known_attack_patterns)
            }

    def add_to_whitelist(self, ip: str):
        """Dodaje IP do whitelisty"""
        self.whitelist.add(ip)
        system_logger.info(f"✅ Dodano {ip} do whitelisty UDP")

    def remove_from_whitelist(self, ip: str):
        """Usuwa IP z whitelisty"""
        self.whitelist.discard(ip)
        system_logger.info(f"❌ Usunięto {ip} z whitelisty UDP")

# Globalna instancja
acl = ACLManager(block_time=10)
detector = AdvancedUDPFloodDetector(acl)

# Funkcje kompatybilności
def start_udp_flood():
    detector.start()

def stop_udp_flood():
    detector.stop()

def analyze_udp_packet(packet):
    detector._packet_callback(packet)

def set_custom_detector_callback(callback):
    detector.set_custom_analysis(callback)

def get_detector_stats():
    return detector.get_stats()

def add_ip_to_whitelist(ip: str):
    detector.add_to_whitelist(ip)

def remove_ip_from_whitelist(ip: str):
    detector.remove_from_whitelist(ip)