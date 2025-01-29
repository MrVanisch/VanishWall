from scapy.all import sniff, IP
import time
import logging
import os
from collections import Counter

# Tworzymy katalog logs, jeśli nie istnieje
os.makedirs("logs", exist_ok=True)

# KONFIGURACJA LOGÓW TRAFFIC MONITOR
traffic_logger = logging.getLogger("traffic")
traffic_logger.setLevel(logging.INFO)

# Tworzymy oddzielny plik logs/traffic.log
file_handler = logging.FileHandler("logs/traffic.log")
formatter = logging.Formatter("%(asctime)s - %(message)s")
file_handler.setFormatter(formatter)
traffic_logger.addHandler(file_handler)

# Konfiguracja monitoringu
CHECK_INTERVAL = 10  # Sprawdzanie ruchu co 10 sekund

# Słowniki do przechowywania ruchu
packet_count = 0  # Liczba pakietów w danym okresie
traffic_data = {}  # Przechowywanie ilości przesłanych bajtów per IP

def analyze_packet(packet):
    """Analizuje pakiety i aktualizuje statystyki ruchu"""
    global packet_count
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        packet_size = len(packet)

        # Aktualizacja liczby pakietów
        packet_count += 1

        # Aktualizacja ilości przesłanych bajtów przez IP
        traffic_data[ip_src] = traffic_data.get(ip_src, 0) + packet_size

def log_traffic_stats():
    """Co 10 sekund loguje statystyki ruchu sieciowego"""
    global packet_count, traffic_data

    while True:
        time.sleep(CHECK_INTERVAL)

        # Konwersja bajtów na MB
        total_bytes = sum(traffic_data.values())
        total_mb = total_bytes / (1024 * 1024)

        # Znalezienie 5 najaktywniejszych adresów IP
        top_ips = Counter(traffic_data).most_common(5)

        # Logowanie danych
        log_message = f"📊 Ruch: {packet_count} pakietów | {total_mb:.2f} MB/s | Top 5 IP: {top_ips}"
        print(log_message)
        traffic_logger.info(log_message)

        # Resetowanie statystyk
        packet_count = 0
        traffic_data = {}

def start_traffic_monitor():
    """Uruchamia monitorowanie ruchu sieciowego"""
    print("📊 Monitorowanie ruchu sieciowego uruchomione...")
    traffic_logger.info("Monitorowanie ruchu sieciowego uruchomione.")

    # Uruchomienie wątku logowania statystyk
    from threading import Thread
    Thread(target=log_traffic_stats, daemon=True).start()

    # Sniffowanie pakietów
    sniff(filter="ip", prn=analyze_packet, store=False)
