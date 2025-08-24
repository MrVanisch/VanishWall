import time
import threading
import os
from datetime import datetime, timedelta
from collections import deque
from typing import Optional, Dict
from statistics import mean

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer
except ImportError:
    raise ImportError("Wymagana biblioteka Scapy. Zainstaluj: pip install scapy")

from .threat_detector import EnhancedThreatDetector
from .threat_types import ServiceType

class NetworkMonitorConfig:
    """Uproszczona konfiguracja"""
    
    def __init__(self):
        try:
            import config
            import importlib
            importlib.reload(config)
            self._config = getattr(config, 'CONFIG', {})
        except Exception:
            self._config = {}
    
    # Progi detekcji - realistyczne wartości
    @property
    def port_scan_threshold(self) -> int:
        return self._config.get("PORT_SCAN_THRESHOLD", 15)
    
    @property
    def dos_packet_threshold(self) -> int:
        return self._config.get("DOS_PACKET_THRESHOLD", 50)
    
    @property
    def ddos_source_threshold(self) -> int:
        return self._config.get("DDOS_SOURCE_THRESHOLD", 5)
    
    @property
    def brute_force_threshold(self) -> int:
        return self._config.get("BRUTE_FORCE_THRESHOLD", 10)
    
    @property
    def syn_flood_threshold(self) -> int:
        return self._config.get("SYN_FLOOD_THRESHOLD", 50)
    
    @property
    def check_interval(self) -> int:
        return self._config.get("CHECK_INTERVAL_TRAFFIC", 30)


class SimpleLogger:
    """Uproszczony logger"""
    
    def __init__(self):
        os.makedirs("logs", exist_ok=True)
        self.log_file = "logs/security_monitor.log"
    
    def info(self, message: str):
        self._log("INFO", message)
    
    def warning(self, message: str):
        self._log("WARNING", message)
        print(f"⚠️  {message}")
    
    def error(self, message: str):
        self._log("ERROR", message)
        print(f"❌ {message}")
    
    def _log(self, level: str, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - {level} - {message}\n"
        
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception:
            pass  # Ignore logging errors


class AdvancedNetworkMonitor:
    """Uproszczony i wydajny monitor sieci"""
    
    def __init__(self):
        self.config = NetworkMonitorConfig()
        self.logger = SimpleLogger()
        self.threat_detector = EnhancedThreatDetector(self.config, self.logger)
        
        # Statystyki
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = datetime.now()
        self.packets_per_second = deque(maxlen=60)
        self.service_stats: Dict[ServiceType, int] = {}
        
        # Kontrola wątków
        self._monitoring_active = False
        self._sniffer: Optional[AsyncSniffer] = None
        self._stats_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        # Metryki wydajności
        self.last_stats_time = datetime.now()
        self.last_packet_count = 0
    
    def _extract_tcp_flags(self, packet) -> str:
        """Wyciąga flagi TCP"""
        if not packet.haslayer(TCP):
            return ""
        
        tcp = packet[TCP]
        flags = ""
        if tcp.flags.F: flags += "F"
        if tcp.flags.S: flags += "S"
        if tcp.flags.R: flags += "R"
        if tcp.flags.P: flags += "P"
        if tcp.flags.A: flags += "A"
        if tcp.flags.U: flags += "U"
        
        return flags
    
    def _analyze_packet(self, packet):
        """Główna funkcja analizy pakietu"""
        with self._lock:
            if not self._monitoring_active:
                return
            
            try:
                if not packet.haslayer(IP):
                    return
                
                # Podstawowe informacje
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                packet_size = len(packet)
                protocol = "Other"
                dst_port = 0
                tcp_flags = ""
                
                # Analiza protokołu
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    dst_port = packet[TCP].dport
                    tcp_flags = self._extract_tcp_flags(packet)
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                    dst_port = 0
                
                # Aktualizuj statystyki
                self.total_packets += 1
                self.total_bytes += packet_size
                
                # Aktualizuj statystyki usług
                service = ServiceType.get_service_by_port(dst_port)
                self.service_stats[service] = self.service_stats.get(service, 0) + 1
                
                # Detekcja zagrożeń
                self.threat_detector.analyze_packet(
                    src_ip, dst_ip, dst_port, protocol, packet_size, tcp_flags
                )
                
            except Exception as e:
                self.logger.error(f"Błąd analizy pakietu: {e}")
    
    def _stats_worker(self):
        """Wątek statystyk"""
        while self._monitoring_active:
            try:
                time.sleep(self.config.check_interval)
                
                with self._lock:
                    if not self._monitoring_active:
                        break
                    
                    # Oblicz PPS
                    current_time = datetime.now()
                    time_diff = (current_time - self.last_stats_time).total_seconds()
                    packet_diff = self.total_packets - self.last_packet_count
                    
                    pps = packet_diff / time_diff if time_diff > 0 else 0
                    self.packets_per_second.append(pps)
                    
                    self.last_stats_time = current_time
                    self.last_packet_count = self.total_packets
                    
                    self._print_stats()
                    
            except Exception as e:
                self.logger.error(f"Błąd w wątku statystyk: {e}")
                break
    
    def _cleanup_worker(self):
        """Wątek czyszczący stare dane"""
        while self._monitoring_active:
            try:
                time.sleep(300)  # Co 5 minut
                
                with self._lock:
                    if not self._monitoring_active:
                        break
                    
                    self.threat_detector.cleanup_old_data()
                    
            except Exception as e:
                self.logger.error(f"Błąd czyszczenia: {e}")
                break
    
    def _print_stats(self):
        """Wyświetla statystyki"""
        uptime = datetime.now() - self.start_time
        avg_pps = mean(self.packets_per_second) if self.packets_per_second else 0
        total_mb = self.total_bytes / (1024 * 1024)
        
        threat_summary = self.threat_detector.get_threat_summary()
        recent_alerts = self.threat_detector.get_recent_alerts(10)
        critical_alerts = [a for a in recent_alerts if a.severity == "CRITICAL"]
        
        print("\n" + "="*60)
        print(f"🛡️  NETWORK SECURITY MONITOR")
        print(f"⏱️  Uptime: {uptime}")
        print(f"📦 Packets: {self.total_packets:,} ({avg_pps:.1f} pps)")
        print(f"💾 Data: {total_mb:.2f} MB")
        print(f"🔍 Monitored IPs: {threat_summary['monitored_ips']}")
        print(f"🚫 Blocked IPs: {threat_summary['blocked_ips']}")
        
        # Top services
        if self.service_stats:
            print("\n🔧 TOP SERVICES:")
            sorted_services = sorted(self.service_stats.items(), 
                                   key=lambda x: x[1], reverse=True)[:5]
            for service, count in sorted_services:
                print(f"  • {service.service_name}: {count:,} packets")
        
        # Alerts
        if critical_alerts:
            print(f"\n🚨 CRITICAL ALERTS (last 10 min): {len(critical_alerts)}")
            for alert in critical_alerts[-3:]:
                print(f"  • {alert.threat_type.value}: {alert.source_ip} → {alert.target_ip}")
        else:
            print(f"\n✅ Recent alerts: {len(recent_alerts)} (0 critical)")
        
        # Top attackers
        if threat_summary['top_attackers']:
            print("\n🎯 TOP ATTACKERS:")
            for attacker in threat_summary['top_attackers'][:3]:
                print(f"  • {attacker['ip']}: {attacker['packets']} packets, "
                      f"{attacker['ports']} ports, {attacker['rate']:.1f} pps")
        
        print("="*60)
    
    @property
    def is_monitoring(self) -> bool:
        with self._lock:
            return self._monitoring_active
    
    def start(self) -> bool:
        """Uruchamia monitoring"""
        with self._lock:
            if self._monitoring_active:
                self.logger.warning("Monitor już działa!")
                return False
            
            try:
                self.logger.info("🚀 Uruchamianie Network Security Monitor...")
                
                # Reset statystyk
                self.total_packets = 0
                self.total_bytes = 0
                self.start_time = datetime.now()
                self.last_stats_time = datetime.now()
                self.last_packet_count = 0
                self.packets_per_second.clear()
                self.service_stats.clear()
                
                # Utworzenie sniffera
                self._sniffer = AsyncSniffer(
                    filter="ip",
                    prn=self._analyze_packet,
                    store=False
                )
                
                self._monitoring_active = True
                
                # Uruchomienie wątków
                self._stats_thread = threading.Thread(
                    target=self._stats_worker,
                    daemon=True
                )
                self._stats_thread.start()
                
                self._cleanup_thread = threading.Thread(
                    target=self._cleanup_worker,
                    daemon=True
                )
                self._cleanup_thread.start()
                
                # Uruchomienie sniffera
                self._sniffer.start()
                
                self.logger.info("✅ Monitor uruchomiony pomyślnie")
                print("🛡️  Network Security Monitor uruchomiony!")
                print("📊 Statystyki będą wyświetlane co " + 
                      f"{self.config.check_interval} sekund")
                print("⚡ Naciśnij Ctrl+C aby zatrzymać")
                
                return True
                
            except Exception as e:
                self.logger.error(f"Błąd uruchamiania: {e}")
                self._cleanup()
                return False
    
    def stop(self) -> bool:
        """Zatrzymuje monitoring"""
        with self._lock:
            if not self._monitoring_active:
                self.logger.warning("Monitor nie działa!")
                return False
            
            try:
                self.logger.info("🛑 Zatrzymywanie monitora...")
                self._monitoring_active = False
                
                self._cleanup()
                
                self.logger.info("✅ Monitor zatrzymany")
                print("✅ Network Security Monitor zatrzymany")
                return True
                
            except Exception as e:
                self.logger.error(f"Błąd zatrzymywania: {e}")
                return False
    
    def _cleanup(self):
        """Czyści zasoby"""
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        
        # Czekaj na wątki
        for thread in [self._stats_thread, self._cleanup_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=3)
        
        self._stats_thread = None
        self._cleanup_thread = None
    
    def get_status(self) -> dict:
        """Zwraca status monitora"""
        with self._lock:
            uptime_seconds = (datetime.now() - self.start_time).total_seconds()
            avg_pps = mean(self.packets_per_second) if self.packets_per_second else 0
            threat_summary = self.threat_detector.get_threat_summary()
            
            return {
                "monitoring_active": self._monitoring_active,
                "uptime_seconds": uptime_seconds,
                "total_packets": self.total_packets,
                "total_mb": self.total_bytes / (1024 * 1024),
                "packets_per_second": avg_pps,
                "monitored_ips": threat_summary["monitored_ips"],
                "blocked_ips": threat_summary["blocked_ips"],
                "recent_alerts": threat_summary["recent_alerts"],
                "threat_summary": threat_summary
            }


# Singleton instance
_monitor_instance: Optional[AdvancedNetworkMonitor] = None

def get_monitor() -> AdvancedNetworkMonitor:
    """Zwraca instancję monitora"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = AdvancedNetworkMonitor()
    return _monitor_instance

# API compatibility functions
def start_traffic_monitor():
    """Uruchamia monitor"""
    return get_monitor().start()

def stop_traffic_monitor():
    """Zatrzymuje monitor"""
    return get_monitor().stop()

def restart_traffic_monitor():
    """Restartuje monitor"""
    monitor = get_monitor()
    if monitor.is_monitoring:
        monitor.stop()
    time.sleep(2)
    return monitor.start()

def get_monitor_status():
    """Zwraca status monitora"""
    return get_monitor().get_status()

if __name__ == "__main__":
    print("🚀 Advanced Network Security Monitor")
    print("🔍 Wykrywa: Port scans, DoS/DDoS, SYN floods, Brute force")
    print("⚡ Naciśnij Ctrl+C aby zatrzymać")
    
    monitor = get_monitor()
    
    if monitor.start():
        try:
            while monitor.is_monitoring:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n👋 Zatrzymywanie...")
        finally:
            monitor.stop()
            status = monitor.get_status()
            print("\n📊 Końcowe statystyki:")
            print(f"   Pakiety: {status['total_packets']:,}")
            print(f"   Dane: {status['total_mb']:.2f} MB")
            print(f"   Alerty: {status['recent_alerts']}")
            print("✅ Zatrzymano")
    else:
        print("❌ Nie udało się uruchomić monitora")
        exit(1)