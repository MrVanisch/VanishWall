from scapy.all import sniff, IP, TCP
import time
import logging
import threading
import queue
from modules.acl import ACLManager

# Pobieramy logger systemowy z `main.py`
system_logger = logging.getLogger("system")

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=10)

# Limit pakietów SYN na sekundę
SYN_LIMIT = 100  
CHECK_INTERVAL = 10  # Sprawdzamy ruch co 10 sekund

# Kolejka do przechowywania pakietów SYN w czasie rzeczywistym
packet_queue = queue.Queue()

# Słownik do monitorowania ilości pakietów SYN od danego IP
syn_counters = {}

# Flaga kontrolna do zatrzymywania wątków
stop_event = threading.Event()

def process_syn_packets():
    """Przetwarza pakiety SYN z kolejki i aktualizuje liczniki IP"""
    while not stop_event.is_set():
        try:
            packet = packet_queue.get(timeout=1)
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == 0x02:  # SYN flag
                ip_src = packet[IP].src
                syn_counters[ip_src] = syn_counters.get(ip_src, 0) + 1
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            system_logger.error(f"❌ Błąd w process_syn_packets: {e}")

def monitor_syn_traffic():
    """Sprawdza liczbę pakietów SYN i blokuje IP, jeśli przekroczy limit"""
    while not stop_event.is_set():
        time.sleep(CHECK_INTERVAL)

        for ip, syn_count in list(syn_counters.items()):
            if syn_count > SYN_LIMIT and not acl.is_blocked(ip):
                print(f"🛑 SYN flood: Podejrzane IP {ip} - {syn_count} pakietów SYN w {CHECK_INTERVAL} sekund")
                system_logger.warning(f"SYN flood: Podejrzane IP {ip} - {syn_count} pakietów SYN w {CHECK_INTERVAL} sekund")
                acl.block_ip(ip, reason="SYN flood attack")

        # Resetowanie licznika pakietów SYN
        syn_counters.clear()

def analyze_syn_packet(packet):
    """Dodaje pakiet SYN do kolejki do analizy"""
    if not stop_event.is_set():
        packet_queue.put(packet)

def start_syn_flood():
    """Uruchamia wykrywanie ataków SYN flood"""
    print("🛡️ Ochrona przed SYN flood uruchomiona...")
    stop_event.clear()

    # Wątek do przetwarzania pakietów SYN w czasie rzeczywistym
    threading.Thread(target=process_syn_packets, daemon=True).start()

    # Wątek do sprawdzania liczby pakietów SYN
    threading.Thread(target=monitor_syn_traffic, daemon=True).start()

    # Nasłuchiwanie pakietów SYN
    sniff(filter="tcp", prn=analyze_syn_packet, store=False, stop_filter=lambda _: stop_event.is_set())

def stop_syn_flood():
    """Zatrzymuje ochronę przed SYN flood"""
    print("🛑 Zatrzymywanie ochrony przed SYN flood...")
    stop_event.set()
    packet_queue.queue.clear()
