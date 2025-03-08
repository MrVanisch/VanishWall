from scapy.all import sniff, IP, UDP
import time
import logging
import threading
import queue
from modules.acl import ACLManager

# Pobieramy logger systemowy z `main.py`
system_logger = logging.getLogger("system")

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=10)

# Limit pakietów UDP na sekundę
UDP_LIMIT = 200  
CHECK_INTERVAL = 10  # Sprawdzamy ruch co 10 sekund

# Kolejka do przechowywania pakietów UDP w czasie rzeczywistym
packet_queue = queue.Queue()

# Słownik do monitorowania ilości pakietów UDP od danego IP
udp_counters = {}

# Flaga kontrolna do zatrzymywania wątków
stop_event = threading.Event()

def process_udp_packets():
    """Przetwarza pakiety UDP z kolejki i aktualizuje liczniki IP"""
    while not stop_event.is_set():
        try:
            packet = packet_queue.get(timeout=1)
            if packet.haslayer(IP) and packet.haslayer(UDP):
                ip_src = packet[IP].src
                udp_counters[ip_src] = udp_counters.get(ip_src, 0) + 1
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            system_logger.error(f"❌ Błąd w process_udp_packets: {e}")

def monitor_udp_traffic():
    """Sprawdza liczbę pakietów UDP i blokuje IP, jeśli przekroczy limit"""
    while not stop_event.is_set():
        time.sleep(CHECK_INTERVAL)

        for ip, udp_count in list(udp_counters.items()):
            if udp_count > UDP_LIMIT and not acl.is_blocked(ip):
                print(f"🛑 UDP flood: Podejrzane IP {ip} - {udp_count} pakietów UDP w {CHECK_INTERVAL} sekund")
                system_logger.warning(f"UDP flood: Podejrzane IP {ip} - {udp_count} pakietów UDP w {CHECK_INTERVAL} sekund")
                acl.block_ip(ip, reason="UDP flood attack")

        # Resetowanie licznika pakietów UDP
        udp_counters.clear()

def analyze_udp_packet(packet):
    """Dodaje pakiet UDP do kolejki do analizy"""
    if not stop_event.is_set():
        packet_queue.put(packet)

def start_udp_flood():
    """Uruchamia wykrywanie ataków UDP flood"""
    print("🛡️ Ochrona przed UDP flood uruchomiona...")
    stop_event.clear()

    threading.Thread(target=process_udp_packets, daemon=True).start()
    threading.Thread(target=monitor_udp_traffic, daemon=True).start()

    sniff(filter="udp", prn=analyze_udp_packet, store=False, stop_filter=lambda _: stop_event.is_set())

def stop_udp_flood():
    """Zatrzymuje ochronę przed UDP flood"""
    print("🛑 Zatrzymywanie ochrony przed UDP flood...")
    stop_event.set()
    packet_queue.queue.clear()
