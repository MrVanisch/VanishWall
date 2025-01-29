from scapy.all import sniff, IP, UDP, DNS
import time
import logging
import threading
import queue
from modules.acl import ACLManager

# Pobieramy logger systemowy z `main.py`
system_logger = logging.getLogger("system")

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=10)

# Limit dużych odpowiedzi DNS na sekundę
DNS_RESPONSE_LIMIT = 100  
CHECK_INTERVAL = 10  # Sprawdzamy ruch co 10 sekund
DNS_SIZE_THRESHOLD = 500  # Jeśli odpowiedź DNS ma > 500 bajtów, traktujemy jako podejrzaną

# Kolejka do przetwarzania pakietów w czasie rzeczywistym
packet_queue = queue.Queue()

# Słownik do monitorowania ilości dużych odpowiedzi DNS od danego IP
dns_counters = {}

def process_dns_packets():
    """Przetwarza pakiety DNS z kolejki i aktualizuje liczniki IP"""
    while True:
        packet = packet_queue.get()
        try:
            if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS):
                if packet[UDP].sport == 53 and len(packet) > DNS_SIZE_THRESHOLD:
                    ip_src = packet[IP].src
                    dns_counters[ip_src] = dns_counters.get(ip_src, 0) + 1
        except Exception as e:
            system_logger.error(f"❌ Błąd w process_dns_packets: {e}")
        packet_queue.task_done()

def monitor_dns_traffic():
    """Sprawdza liczbę dużych odpowiedzi DNS i blokuje IP, jeśli przekroczy limit"""
    while True:
        time.sleep(CHECK_INTERVAL)

        for ip, dns_count in list(dns_counters.items()):
            if dns_count > DNS_RESPONSE_LIMIT and not acl.is_blocked(ip):
                print(f"🛑 DNS Amplification: Podejrzane IP {ip} - {dns_count} dużych pakietów DNS w {CHECK_INTERVAL} sekund")
                system_logger.warning(f"DNS Amplification: Podejrzane IP {ip} - {dns_count} dużych pakietów DNS w {CHECK_INTERVAL} sekund")
                acl.block_ip(ip, reason="DNS Amplification Attack")

        # Resetowanie licznika odpowiedzi DNS
        dns_counters.clear()

def analyze_dns_packet(packet):
    """Dodaje pakiet DNS do kolejki do analizy"""
    packet_queue.put(packet)

def start_dns_protection():
    """Uruchamia wykrywanie ataków DNS Amplification"""
    print("🛡️ Ochrona przed DNS Amplification uruchomiona...")

    # Wątek do przetwarzania pakietów DNS w czasie rzeczywistym
    threading.Thread(target=process_dns_packets, daemon=True).start()

    # Wątek do sprawdzania liczby dużych pakietów DNS
    threading.Thread(target=monitor_dns_traffic, daemon=True).start()

    # Nasłuchiwanie pakietów DNS na porcie UDP 53
    sniff(filter="udp port 53", prn=analyze_dns_packet, store=False)