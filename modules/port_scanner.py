import time
import threading
from collections import defaultdict, deque
from scapy.all import sniff, TCP, IP
import config
from modules.logger import security_logger, system_logger, debug_logger
from modules.acl import ACLManager
import os

class PortScannerDetector:
    def __init__(self):
        self.config = config.CONFIG
        self.acl_manager = ACLManager()
        self.running = False
        self.sniffer_thread = None
        
        # Konfiguracja wykrywania port scanu
        self.scan_threshold = self.config.get("PORTSCAN_THRESHOLD", 10)  # liczba portów
        self.time_window = self.config.get("PORTSCAN_TIME_WINDOW", 30)    # okno czasowe w sekundach
        self.block_time = self.config.get("PORTSCAN_BLOCK_TIME", 600)    # czas blokady w sekundach
        self.suspicious_ports = set(self.config.get("PORTSCAN_SUSPICIOUS_PORTS", 
                                                   [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]))
        
        # Struktury danych do śledzenia połączeń
        self.ip_port_history = defaultdict(lambda: deque())  # IP -> deque of (timestamp, port)
        self.scan_attempts = defaultdict(int)                # IP -> liczba prób skanowania
        self.blocked_scanners = set()                        # zbiór zablokowanych IP
        
        # Lock dla thread safety
        self.lock = threading.Lock()
        
        system_logger.info("🔍 Port Scanner Detector zainicjalizowany")

    def _is_syn_scan(self, packet):
        """Sprawdza czy pakiet to część SYN scan"""
        if TCP in packet:
            tcp_layer = packet[TCP]
            # SYN flag bez ACK (nowe połączenie)
            return tcp_layer.flags == 2  # SYN flag
        return False

    def _is_suspicious_port_access(self, port):
        """Sprawdza czy port jest podejrzany dla skanowania"""
        return port in self.suspicious_ports

    def _clean_old_entries(self, ip):
        """Usuwa stare wpisy spoza okna czasowego"""
        current_time = time.time()
        history = self.ip_port_history[ip]
        
        while history and (current_time - history[0][0]) > self.time_window:
            history.popleft()

    def _analyze_packet(self, packet):
        """Analizuje pakiet pod kątem wykrywania port scanu"""
        try:
            if IP not in packet or TCP not in packet:
                return
            
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            current_time = time.time()
            
            # Pomijaj wewnętrzny ruch (localhost, sieci prywatne)
            if src_ip.startswith(('127.', '10.', '192.168.')) or src_ip.startswith('172.'):
                if src_ip.startswith('172.'):
                    # Sprawdź czy to rzeczywiście sieć prywatna 172.16-31.x.x
                    octets = src_ip.split('.')
                    if len(octets) >= 2:
                        second_octet = int(octets[1])
                        if not (16 <= second_octet <= 31):
                            pass  # nie jest siecią prywatną, kontynuuj analizę
                        else:
                            return
                else:
                    return
            
            # Sprawdź czy to SYN scan
            if not self._is_syn_scan(packet):
                return
            
            with self.lock:
                # Usuń stare wpisy
                self._clean_old_entries(src_ip)
                
                # Dodaj nowy wpis
                self.ip_port_history[src_ip].append((current_time, dst_port))
                
                # Pobierz unikalne porty w oknie czasowym
                unique_ports = set(port for _, port in self.ip_port_history[src_ip])
                suspicious_ports_hit = sum(1 for port in unique_ports if self._is_suspicious_port_access(port))
                
                debug_logger.debug(f"🔍 PortScan: {src_ip} -> port {dst_port}, unique_ports: {len(unique_ports)}, suspicious: {suspicious_ports_hit}")
                
                # Wykryj port scan
                if len(unique_ports) >= self.scan_threshold or suspicious_ports_hit >= 5:
                    if src_ip not in self.blocked_scanners:
                        self._handle_port_scan_detection(src_ip, unique_ports, suspicious_ports_hit)
                        
        except Exception as e:
            debug_logger.error(f"Błąd podczas analizy pakietu port scan: {e}", exc_info=True)

    def _handle_port_scan_detection(self, src_ip, unique_ports, suspicious_ports_hit):
        """Obsługuje wykrycie port scanu"""
        self.scan_attempts[src_ip] += 1
        scan_count = self.scan_attempts[src_ip]
        
        ports_list = list(unique_ports)[:10]  # Pokaż maksymalnie 10 portów
        
        reason = f"Port scan detected - {len(unique_ports)} ports scanned, {suspicious_ports_hit} suspicious"
        details = f"Scanned ports: {ports_list}, attempts: {scan_count}"
        
        security_logger.error(f"🚨 WYKRYTO PORT SCAN z IP: {src_ip} | Porty: {len(unique_ports)} | Podejrzane: {suspicious_ports_hit} | Próba #{scan_count}")
        security_logger.error(f"🚨 Szczegóły port scan {src_ip}: {details}")
        
        # Blokuj IP przez ACL
        self.acl_manager.block_ip(src_ip, reason)
        self.blocked_scanners.add(src_ip)
        
        # Ustaw timer na odblokowanie z naszej listy
        threading.Timer(self.block_time, self._unblock_scanner, [src_ip]).start()
        
        # Wyczyść historię dla tego IP
        self.ip_port_history[src_ip].clear()

    def _unblock_scanner(self, src_ip):
        """Usuwa IP z listy zablokowanych scannerów"""
        with self.lock:
            self.blocked_scanners.discard(src_ip)
        system_logger.info(f"🔍 Port scanner {src_ip} usunięty z listy zablokowanych")

    def _packet_handler(self, packet):
        """Handler pakietów dla sniffer"""
        try:
            self._analyze_packet(packet)
        except Exception as e:
            debug_logger.error(f"Błąd w packet_handler port scan: {e}", exc_info=True)

    def start_detection(self):
        """Uruchamia wykrywanie port scanu"""
        if self.running:
            system_logger.warning("🔍 Port Scanner Detector już działa!")
            return
        
        self.running = True
        system_logger.info("🔍 Uruchamianie Port Scanner Detector...")
        
        try:
            # Uruchom sniffer w osobnym wątku
            self.sniffer_thread = threading.Thread(
                target=self._run_sniffer,
                daemon=True
            )
            self.sniffer_thread.start()
            
            system_logger.info("✅ Port Scanner Detector uruchomiony pomyślnie")
            
        except Exception as e:
            system_logger.error(f"❌ Błąd uruchamiania Port Scanner Detector: {e}")
            self.running = False

    def _run_sniffer(self):
        """Uruchamia sniffer pakietów"""
        try:
            # Filtr dla pakietów TCP SYN
            sniff(
                filter="tcp[tcpflags] & tcp-syn != 0",
                prn=self._packet_handler,
                stop_filter=lambda x: not self.running,
                store=0  # Nie przechowuj pakietów w pamięci
            )
        except Exception as e:
            system_logger.error(f"Błąd w sniffer port scan: {e}", exc_info=True)
            self.running = False

    def stop_detection(self):
        """Zatrzymuje wykrywanie port scanu"""
        if not self.running:
            system_logger.warning("🔍 Port Scanner Detector nie działa!")
            return
        
        system_logger.info("🔍 Zatrzymywanie Port Scanner Detector...")
        self.running = False
        
        # Poczekaj na zakończenie wątku sniffera
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=5)
        
        # Wyczyść struktury danych
        with self.lock:
            self.ip_port_history.clear()
            self.scan_attempts.clear()
            self.blocked_scanners.clear()
        
        system_logger.info("✅ Port Scanner Detector zatrzymany")

    def restart_detection(self):
        """Restartuje wykrywanie port scanu"""
        system_logger.info("🔄 Restartowanie Port Scanner Detector...")
        self.stop_detection()
        time.sleep(2)
        self.start_detection()

    def get_stats(self):
        """Zwraca statystyki modułu"""
        with self.lock:
            return {
                "running": self.running,
                "monitored_ips": len(self.ip_port_history),
                "blocked_scanners": len(self.blocked_scanners),
                "total_scan_attempts": sum(self.scan_attempts.values()),
                "config": {
                    "scan_threshold": self.scan_threshold,
                    "time_window": self.time_window,
                    "block_time": self.block_time,
                    "suspicious_ports_count": len(self.suspicious_ports)
                }
            }

# Instancja globalna
_port_scanner_detector = None

def get_port_scanner_detector():
    """Zwraca globalną instancję detektora"""
    global _port_scanner_detector
    if _port_scanner_detector is None:
        _port_scanner_detector = PortScannerDetector()
    return _port_scanner_detector

# Funkcje wymagane przez główną aplikację
def start_port_scanner():
    """Uruchamia ochronę przed port scanem"""
    detector = get_port_scanner_detector()
    detector.start_detection()

def stop_port_scanner():
    """Zatrzymuje ochronę przed port scanem"""
    detector = get_port_scanner_detector()
    detector.stop_detection()

def restart_port_scanner():
    """Restartuje ochronę przed port scanem"""
    detector = get_port_scanner_detector()
    detector.restart_detection()

def get_port_scanner():
    """Zwraca statystyki ochrony przed port scanem"""
    detector = get_port_scanner_detector()
    return detector.get_stats()

if __name__ == "__main__":
    # Test uruchomienia modułu
    print("🔍 Testowanie Port Scanner Detector...")
    detector = PortScannerDetector()
    
    try:
        detector.start_detection()
        print("✅ Moduł uruchomiony, naciśnij Ctrl+C aby zatrzymać...")
        
        while True:
            time.sleep(10)
            stats = detector.get_stats()
            print(f"📊 Stats: {stats}")
            
    except KeyboardInterrupt:
        print("\n🛑 Zatrzymywanie...")
        detector.stop_detection()
        print("✅ Zatrzymano")