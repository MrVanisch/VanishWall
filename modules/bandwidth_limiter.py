from scapy.all import sniff, IP
import time
import threading
from modules.acl import ACLManager
from modules.logger import system_logger  # Używamy poprawnego loggera

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=10)

# Limit ruchu
BANDWIDTH_LIMIT = 50 * 1024 * 1024  # 50 MB w bajtach
CHECK_INTERVAL = 10 # Sprawdzanie co 10 sekund

# Monitorowanie ruchu
traffic = {}
monitoring_active = False
sniffer = None
monitor_thread = None

def analyze_packet(packet):
    """Analizuje pakiety i zlicza bajty przesłane przez IP"""
    if not monitoring_active:
        return
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        packet_size = len(packet)
        traffic[ip_src] = traffic.get(ip_src, 0) + packet_size


def monitor_traffic():
    """Sprawdza ruch co określony czas i blokuje IP, jeśli przekroczy limit"""
    global monitoring_active
    while monitoring_active:
        time.sleep(CHECK_INTERVAL)
        
        for ip, bytes_sent in list(traffic.items()):
            if bytes_sent > BANDWIDTH_LIMIT and not acl.is_blocked(ip):
                print(f"\U0001F6D1 WYKRYTO ATAK: {ip} - {bytes_sent / (1024 * 1024):.2f} MB / {CHECK_INTERVAL} s")
                system_logger.warning(f"WYKRYTO ATAK: {ip} - {bytes_sent / (1024 * 1024):.2f} MB / {CHECK_INTERVAL} s")
                acl.block_ip(ip, reason="Zbyt duże zużycie pasma")
        
        traffic.clear()


def start_bandwidth_limiter():
    """Uruchamia monitorowanie ruchu i ograniczanie przepustowości"""
    global monitoring_active, sniffer, monitor_thread
    
    if monitoring_active:
        print("⚠️ Monitorowanie już działa!")
        return
    
    print("🛡️ Bandwidth limiter uruchomiony...")
    system_logger.info("Monitorowanie ruchu zostało uruchomione.")
    monitoring_active = True
    
    monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
    monitor_thread.start()
    
    sniffer = sniff(filter="ip", prn=analyze_packet, store=False, stop_filter=lambda x: not monitoring_active)


def stop_bandwidth_limiter():
    """Zatrzymuje monitorowanie ruchu"""
    global monitoring_active, sniffer, monitor_thread
    
    if not monitoring_active:
        print("⚠️ bandwidth_limiter zostało zatrzymane")
        return
    
    print("🛑 bandwidth_limiter zostało zatrzymane.")
    system_logger.info("Monitorowanie ruchu zostało zatrzymane.")
    monitoring_active = False
    
    if monitor_thread and monitor_thread.is_alive():
        monitor_thread.join(timeout=2)
    
    sniffer = None
    monitor_thread = None
    print("✅ bandwidth_limiter zostało zatrzymane.")


def restart_bandwidth_limiter():
    """Restartuje monitorowanie ruchu"""
    print("🔄 Restartowanie monitorowania ruchu...")
    stop_bandwidth_limiter()
    time.sleep(1)
    start_bandwidth_limiter()
    print("✅ Restart monitorowania ruchu zakończony.")


if __name__ == "__main__":
    start_bandwidth_limiter()
