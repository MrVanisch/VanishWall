from scapy.all import sniff, IP, UDP
import time
import logging
import threading
import queue
from modules.acl import ACLManager

# Pobieramy logger systemowy
system_logger = logging.getLogger("system")

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=10)

# Konfiguracja limitów
NTP_RESPONSE_LIMIT = 50  # Maksymalna liczba dużych odpowiedzi NTP w ciągu 10 sekund
CHECK_INTERVAL = 10  # Sprawdzamy ruch co 10 sekund
NTP_SIZE_THRESHOLD = 468  # Jeśli pakiet NTP > 468 bajtów, traktujemy jako podejrzany

# Kolejka do przetwarzania pakietów
packet_queue = queue.Queue()

# Słownik do monitorowania ilości dużych odpowiedzi NTP od danego IP
ntp_counters = {}

def process_ntp_packets():
    """Przetwarza pakiety NTP z kolejki i aktualizuje liczniki IP"""
    while True:
        packet = packet_queue.get()
        try:
            if packet.haslayer(IP) and packet.haslayer(UDP):
                if packet[UDP].sport == 123 and len(packet) > NTP_SIZE_THRESHOLD:
                    ip_src = packet[IP].src
                    ntp_counters[ip_src] = ntp_counters.get(ip_src, 0) + 1
        except Exception as e:
            system_logger.error(f"❌ Błąd w process_ntp_packets: {e}")
        packet_queue.task_done()

def monitor_ntp_traffic():
    """Sprawdza liczbę dużych odpowiedzi NTP i blokuje IP, jeśli przekroczy limit"""
    while True:
        time.sleep(CHECK_INTERVAL)

        for ip, ntp_count in list(ntp_counters.items()):
            if ntp_count > NTP_RESPONSE_LIMIT:
                if not acl.is_blocked(ip):  # Unikamy wielokrotnej blokady IP
                    print(f"🛑 NTP Amplification: Podejrzane IP {ip} - {ntp_count} dużych pakietów NTP w {CHECK_INTERVAL} sekund")
                    system_logger.warning(f"NTP Amplification: Podejrzane IP {ip} - {ntp_count} dużych pakietów NTP w {CHECK_INTERVAL} sekund")
                    acl.block_ip(ip, reason="NTP Amplification Attack")

        # Resetowanie licznika odpowiedzi NTP
        ntp_counters.clear()

def analyze_ntp_packet(packet):
    """Dodaje pakiet NTP do kolejki do analizy"""
    packet_queue.put(packet)

def start_ntp_protection():
    """Uruchamia wykrywanie ataków NTP Amplification"""
    print("🛡️ Ochrona przed NTP Amplification uruchomiona...")
    system_logger.info("Ochrona przed NTP Amplification została uruchomiona.")

    # Wątek do przetwarzania pakietów NTP w czasie rzeczywistym
    threading.Thread(target=process_ntp_packets, daemon=True).start()

    # Wątek do sprawdzania liczby dużych pakietów NTP
    threading.Thread(target=monitor_ntp_traffic, daemon=True).start()

    # Nasłuchiwanie pakietów NTP na porcie UDP 123
    sniff(filter="udp port 123", prn=analyze_ntp_packet, store=False)
