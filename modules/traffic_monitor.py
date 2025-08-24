# ULEPSZONA WERSJA MOCK MONITORA - kompatybilna z nowym API
import time
import threading
import random
from datetime import datetime

# Mock class dla kompatybilności z API
class MockMonitor:
    def __init__(self):
        self.is_monitoring = False
        self._stats = {
            "total_packets": 0,
            "total_mb": 0,
            "uptime_seconds": 0,
            "packets_per_second": 0,
            "monitored_ips": 0,
            "blocked_ips": 0,
            "recent_alerts": 0,
            "monitoring_active": False,
            "active_services": 0
        }
        self.start_time = datetime.now()
        self._thread = None
        self._running = False
        
        # Dane dla wykresów
        self._alert_types = ["HTTP Traffic", "HTTPS Traffic", "SSH Access", "DNS Query", "FTP Access"]
        self._service_types = ["HTTP", "HTTPS", "SSH", "DNS", "FTP", "MySQL", "PostgreSQL"]
        
        print("🎯 Enhanced MockMonitor initialized")
    
    def start(self):
        print("🚀 MockMonitor - URUCHAMIANIE...")
        self.is_monitoring = True
        self._stats["monitoring_active"] = True
        self.start_time = datetime.now()
        self._running = True
        
        # Uruchom symulację w osobnym wątku
        self._thread = threading.Thread(target=self._simulate_traffic, daemon=True)
        self._thread.start()
        
        print("✅ MockMonitor uruchomiony! Symulacja ruchu rozpoczęta.")
        return True
    
    def stop(self):
        print("🛑 MockMonitor - ZATRZYMYWANIE...")
        self.is_monitoring = False
        self._stats["monitoring_active"] = False
        self._running = False
        
        # Reset stats when stopped
        if not self.is_monitoring:
            self._stats.update({
                "total_packets": 0,
                "total_mb": 0,
                "uptime_seconds": 0,
                "packets_per_second": 0,
                "monitored_ips": 0,
                "recent_alerts": 0,
                "active_services": 0
            })
        
        print("✅ MockMonitor zatrzymany!")
        return True
    
    def _simulate_traffic(self):
        """Symuluje ruch sieciowy dla demonstracji"""
        print("🔄 Symulacja ruchu rozpoczęta...")
        packet_count = 0
        
        while self._running:
            try:
                # Symuluj pakiety - zwiększaj stopniowo
                new_packets = random.randint(20, 80)
                packet_count += new_packets
                
                # Zwiększaj aktywność z czasem
                time_running = (datetime.now() - self.start_time).total_seconds()
                multiplier = min(1 + (time_running / 300), 3)  # Max 3x po 5 minutach
                
                self._stats.update({
                    "total_packets": int(packet_count * multiplier),
                    "total_mb": round((packet_count * multiplier) * 0.0015, 2),
                    "packets_per_second": round((new_packets * multiplier) / 5, 1),
                    "monitored_ips": random.randint(2, 8),
                    "active_services": random.randint(3, 7),
                    "recent_alerts": random.randint(0, 5) if packet_count > 100 else 0
                })
                
                if packet_count % 100 == 0:
                    print(f"📊 Symulacja: {self._stats['total_packets']} pakietów, "
                          f"{self._stats['total_mb']}MB, "
                          f"{self._stats['monitored_ips']} IP, " 
                          f"{self._stats['recent_alerts']} alertów")
                
                time.sleep(5)  # Aktualizacja co 5 sekund
                
            except Exception as e:
                print(f"❌ Błąd w symulacji: {e}")
                break
        
        print("🔄 Symulacja ruchu zakończona")
    
    def get_status(self):
        # Aktualizuj uptime
        if self.is_monitoring:
            self._stats["uptime_seconds"] = (datetime.now() - self.start_time).total_seconds()
        else:
            self._stats["uptime_seconds"] = 0
        
        print(f"📊 get_status() - monitoring: {self.is_monitoring}, packets: {self._stats['total_packets']}")
        return self._stats
    
    def get_security_summary(self):
        """GŁÓWNA FUNKCJA - zwraca dane w formacie oczekiwanym przez API"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.is_monitoring else 0
        
        if self.is_monitoring:
            # Monitor aktywny - realistyczne dane
            alert_count = self._stats["recent_alerts"]
            
            # Dynamiczny rozkład alertów
            alert_breakdown = {}
            if alert_count > 0:
                # Rozłóż alerty na różne typy
                remaining_alerts = alert_count
                for alert_type in self._alert_types:
                    if remaining_alerts <= 0:
                        break
                    
                    # Przydziel losową liczbę alertów (ale nie więcej niż zostało)
                    count = random.randint(0, min(remaining_alerts, 3))
                    if count > 0:
                        alert_breakdown[alert_type] = count
                        remaining_alerts -= count
                
                # Jeśli zostały alerty, dodaj do pierwszego typu
                if remaining_alerts > 0 and alert_breakdown:
                    first_type = list(alert_breakdown.keys())[0]
                    alert_breakdown[first_type] += remaining_alerts
            
            # Dynamiczne top services
            total_packets = self._stats["total_packets"]
            active_services_count = self._stats["active_services"]
            top_services = []
            
            if total_packets > 0 and active_services_count > 0:
                # Generuj services na podstawie aktualnej liczby
                service_names = self._service_types[:active_services_count]
                remaining_packets = total_packets
                
                for i, service in enumerate(service_names):
                    if i == len(service_names) - 1:
                        # Ostatnia usługa dostaje resztę pakietów
                        packets = remaining_packets
                    else:
                        # Losowy podział pakietów
                        max_packets = remaining_packets // 2
                        packets = random.randint(1, max(1, max_packets))
                        remaining_packets -= packets
                    
                    mb = round(packets * 0.0015, 2)
                    top_services.append({
                        "service": service,
                        "packets": packets,
                        "mb": mb
                    })
                
                # Sortuj malejąco
                top_services.sort(key=lambda x: x["packets"], reverse=True)
            
            summary = {
                "monitoring_active": True,
                "uptime_seconds": uptime,
                "total_packets": self._stats["total_packets"],
                "total_mb": self._stats["total_mb"],
                "packets_per_second": self._stats["packets_per_second"],
                "active_services": self._stats["active_services"],
                "monitored_ips": self._stats["monitored_ips"],
                "recent_alerts": alert_count,
                "critical_alerts": 0,
                
                # Dane dla wykresów
                "alert_breakdown": alert_breakdown,
                "top_services": top_services,
                
                # Threat intelligence
                "threat_intelligence": {
                    "monitored_ips": self._stats["monitored_ips"],
                    "blocked_ips": 0,
                    "recent_alerts": alert_count,
                    "top_attackers": [],
                    "ddos_targets": []
                }
            }
        else:
            # Monitor nieaktywny - zerowe dane
            summary = {
                "monitoring_active": False,
                "uptime_seconds": 0,
                "total_packets": 0,
                "total_mb": 0,
                "packets_per_second": 0,
                "active_services": 0,
                "monitored_ips": 0,
                "recent_alerts": 0,
                "critical_alerts": 0,
                "alert_breakdown": {},
                "top_services": [],
                "threat_intelligence": {
                    "monitored_ips": 0,
                    "blocked_ips": 0,
                    "recent_alerts": 0,
                    "top_attackers": [],
                    "ddos_targets": []
                }
            }
        
        print(f"🔍 get_security_summary() returning: active={summary['monitoring_active']}, "
              f"packets={summary['total_packets']}, alerts={summary['recent_alerts']}")
        return summary

# Global instance
_monitor = MockMonitor()

# API Functions z DEBUGOWANIEM
def start_traffic_monitor():
    print("🎬 start_traffic_monitor() called")
    result = _monitor.start()
    print(f"🎬 start_traffic_monitor() result: {result}")
    return result

def stop_traffic_monitor():
    print("🎬 stop_traffic_monitor() called")
    result = _monitor.stop()
    print(f"🎬 stop_traffic_monitor() result: {result}")
    return result

def restart_traffic_monitor():
    print("🎬 restart_traffic_monitor() called")
    _monitor.stop()
    time.sleep(1)
    result = _monitor.start()
    print(f"🎬 restart_traffic_monitor() result: {result}")
    return result

def get_security_monitor():
    """KOMPATYBILNOŚĆ - główna funkcja używana przez API"""
    print("🔍 get_security_monitor() called")
    return _monitor

def get_traffic_monitor():
    return _monitor

def get_monitor():
    return _monitor

def get_monitor_status():
    print("🔍 get_monitor_status() called")
    return _monitor.get_status()

def get_traffic_stats():
    return _monitor.get_status()

def is_monitoring_active():
    result = _monitor.is_monitoring
    print(f"🔍 is_monitoring_active() called, result: {result}")
    return result

# Network traffic compatibility
network_traffic_data = {
    "packets": 0,
    "bytes": 0,
    "start_time": time.time()
}

def start_network_traffic_monitor():
    global network_traffic_data
    network_traffic_data["start_time"] = time.time()
    return start_traffic_monitor()

def stop_network_traffic_monitor():
    return stop_traffic_monitor()

def get_traffic_config():
    return {
        "check_interval": 30,
        "port_scan_threshold": 15,
        "dos_packet_threshold": 50,
        "ddos_source_threshold": 5,
        "brute_force_threshold": 10,
        "syn_flood_threshold": 50
    }

def get_security_alerts(minutes=60):
    """Zwraca przykładowe alerty gdy monitor jest aktywny"""
    if _monitor.is_monitoring and _monitor._stats["recent_alerts"] > 0:
        alerts = []
        alert_count = _monitor._stats["recent_alerts"]
        
        for i in range(min(alert_count, 5)):  # Max 5 alertów
            alert_type = random.choice(["HTTP Traffic", "HTTPS Traffic", "SSH Access", "DNS Query"])
            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "threat_type": alert_type,
                "description": f"{alert_type} detected from 192.168.1.{100+i}",
                "severity": random.choice(["LOW", "MEDIUM"]),
                "source_ip": f"192.168.1.{100+i}",
                "target_port": random.choice([80, 443, 22, 53])
            })
        
        print(f"🚨 get_security_alerts() returning {len(alerts)} alerts")
        return alerts
    
    print("🚨 get_security_alerts() returning 0 alerts")
    return []

def get_threat_intelligence():
    active = _monitor.is_monitoring
    alert_count = _monitor._stats["recent_alerts"] if active else 0
    
    data = {
        "monitored_ips": _monitor._stats["monitored_ips"] if active else 0,
        "blocked_ips": 0,
        "recent_alerts": alert_count,
        "top_attackers": [],
        "ddos_targets": [],
        "alert_stats": {
            "total_alerts": alert_count,
            "recent_alerts": alert_count,
            "alert_types": {
                "HTTP Traffic": random.randint(0, alert_count),
                "HTTPS Traffic": random.randint(0, alert_count//2)
            } if alert_count > 0 else {},
            "severity_breakdown": {
                "LOW": alert_count if alert_count > 0 else 0,
                "MEDIUM": 0, 
                "HIGH": 0,
                "CRITICAL": 0
            }
        }
    }
    print(f"🔍 get_threat_intelligence() returning: {data}")
    return data

def get_blocked_ips():
    return []

def get_monitor_health():
    active = _monitor.is_monitoring
    uptime = (datetime.now() - _monitor.start_time).total_seconds() if active else 0
    
    health = {
        "status": "healthy" if active else "stopped",
        "uptime_hours": uptime / 3600,
        "packets_processed": _monitor._stats["total_packets"] if active else 0,
        "data_processed_mb": _monitor._stats["total_mb"] if active else 0,
        "performance": {
            "packets_per_second": _monitor._stats["packets_per_second"] if active else 0,
            "memory_usage": "normal",
            "cpu_usage": "normal"
        },
        "threats_detected": {
            "monitored_ips": _monitor._stats["monitored_ips"] if active else 0,
            "blocked_ips": 0,
            "recent_alerts": _monitor._stats["recent_alerts"] if active else 0
        }
    }
    print(f"🔍 get_monitor_health() returning: {health}")
    return health

# Mock threat detector dla kompatybilności
class MockThreatDetector:
    def __init__(self):
        self.blocked_ips = set()
    
    def get_recent_alerts(self, minutes=60):
        return get_security_alerts(minutes)
    
    def get_threat_summary(self):
        return get_threat_intelligence()

# Dodaj threat_detector do monitora
_monitor.threat_detector = MockThreatDetector()

print("✅ Enhanced Mock Traffic Monitor załadowany")
print("🎯 Funkcje:")
print("   - Dynamiczne generowanie danych")
print("   - Kompatybilne z nowym API") 
print("   - Realistyczne rozkłady alertów i usług")
print("🔍 Wszystkie wywołania funkcji są logowane w konsoli")

# Test przy starcie
print("🧪 Testowanie podstawowych funkcji...")
print(f"   - is_monitoring_active(): {is_monitoring_active()}")
print(f"   - get_monitor_status(): {get_monitor_status()}")
print("🧪 Test zakończony")
print("="*60)