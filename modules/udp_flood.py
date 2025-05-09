from scapy.all import sniff, IP, UDP
import time
import logging
import threading
import queue
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger  # Dodano loggery

# Pobieramy logger systemowy z `main.py`
system_logger = logging.getLogger("system")  # Pozostawione dla kompatybilności, ale teraz nieużywane

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=10)

# Limit pakietów UDP na sekundę
from config import CONFIG
UDP_LIMIT = CONFIG.get("UDP_LIMIT", 200)
CHECK_INTERVAL = CONFIG.get("CHECK_INTERVAL_UDP", 10)

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
                debug_logger.debug(f"📦 Odebrano pakiet UDP od {ip_src}")
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            system_logger.error(f"❌ Błąd w process_udp_packets: {e}", exc_info=True)

def monitor_udp_traffic():
    """Sprawdza liczbę pakietów UDP i blokuje IP, jeśli przekroczy limit"""
    while not stop_event.is_set():
        time.sleep(CHECK_INTERVAL)

        for ip, udp_count in list(udp_counters.items()):
            if udp_count > UDP_LIMIT and not acl.is_blocked(ip):
                print(f"🛑 UDP flood: Podejrzane IP {ip} - {udp_count} pakietów UDP w {CHECK_INTERVAL} sekund")
                system_logger.warning(f"🛑 UDP flood: Podejrzane IP {ip} - {udp_count} pakietów UDP w {CHECK_INTERVAL} sekund")
                security_logger.warning(f"🚨 Wykryto możliwy atak UDP flood z IP: {ip}, pakietów: {udp_count}")
                acl.block_ip(ip, reason="UDP flood attack")
                debug_logger.debug(f"🔒 Zablokowano IP {ip} z powodu UDP flood")

        # Resetowanie licznika pakietów UDP
        debug_logger.debug("🔄 Resetowanie liczników pakietów UDP")
        udp_counters.clear()

def analyze_udp_packet(packet):
    """Dodaje pakiet UDP do kolejki do analizy"""
    if not stop_event.is_set():
        debug_logger.debug("➕ Dodano pakiet do kolejki analizy UDP")
        packet_queue.put(packet)

def start_udp_flood():
    """Uruchamia wykrywanie ataków UDP flood"""
    print("🛡️ Ochrona przed UDP flood uruchomiona...")
    system_logger.info("🛡️ Ochrona przed UDP flood uruchomiona")
    stop_event.clear()

    threading.Thread(target=process_udp_packets, daemon=True).start()
    threading.Thread(target=monitor_udp_traffic, daemon=True).start()

    try:
        sniff(filter="udp", prn=analyze_udp_packet, store=False, stop_filter=lambda _: stop_event.is_set())
    except Exception as e:
        system_logger.error("❌ Błąd podczas działania sniffera", exc_info=True)

def stop_udp_flood():
    """Zatrzymuje ochronę przed UDP flood"""
    print("🛑 Zatrzymywanie ochrony przed UDP flood...")
    system_logger.info("🛑 Zatrzymywanie ochrony przed UDP flood")
    stop_event.set()
    packet_queue.queue.clear()
    debug_logger.debug("🧹 Wyczyściłem kolejkę pakietów UDP")
