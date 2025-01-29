from scapy.all import sniff, IP
import time
import threading
from modules.acl import ACLManager
from modules.logger import system_logger  # Używamy poprawnego loggera

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=10)

# Limit ruchu
BANDWIDTH_LIMIT = 50 * 1024 * 1024  # 50 MB w bajtach
CHECK_INTERVAL = 10  # Sprawdzanie co 10 sekund

# Monitorowanie ruchu
traffic = {}

def analyze_packet(packet):
    """Analizuje pakiety i zlicza bajty przesłane przez IP"""
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        packet_size = len(packet)
        traffic[ip_src] = traffic.get(ip_src, 0) + packet_size

def monitor_traffic():
    """Sprawdza ruch co określony czas i blokuje IP, jeśli przekroczy limit"""
    while True:
        time.sleep(CHECK_INTERVAL)

        for ip, bytes_sent in list(traffic.items()):
            if bytes_sent > BANDWIDTH_LIMIT and not acl.is_blocked(ip):
                print(f"🛑 WYKRYTO ATAK: {ip} - {bytes_sent / (1024 * 1024):.2f} MB / {CHECK_INTERVAL} s")
                system_logger.warning(f"WYKRYTO ATAK: {ip} - {bytes_sent / (1024 * 1024):.2f} MB / {CHECK_INTERVAL} s")
                acl.block_ip(ip, reason="Zbyt duże zużycie pasma")

        traffic.clear()

def start_bandwidth_limiter():
    """Uruchamia monitorowanie ruchu i ograniczanie przepustowości"""
    print("🛡️ Bandwidth limiter uruchomiony...")
    system_logger.info("Monitorowanie ruchu zostało uruchomione.")

    threading.Thread(target=monitor_traffic, daemon=True).start()
    sniff(filter="ip", prn=analyze_packet, store=False)