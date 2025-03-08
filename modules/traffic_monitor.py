from scapy.all import sniff, IP, AsyncSniffer
import time
import logging
import os
import threading
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

# Flagi kontrolne do zatrzymywania monitorowania
monitoring_active = False
sniff_thread = None
log_thread = None
sniffer = None  # Sniffer Scapy

def analyze_packet(packet):
    """Analizuje pakiety i aktualizuje statystyki ruchu"""
    global packet_count, monitoring_active
    if not monitoring_active:
        return  # Jeśli monitorowanie wyłączone, ignorujemy pakiety

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        packet_size = len(packet)

        # Aktualizacja liczby pakietów
        packet_count += 1

        # Aktualizacja ilości przesłanych bajtów przez IP
        traffic_data[ip_src] = traffic_data.get(ip_src, 0) + packet_size

def log_traffic_stats():
    """Co 10 sekund loguje statystyki ruchu sieciowego"""
    global packet_count, traffic_data, monitoring_active

    while monitoring_active:
        time.sleep(CHECK_INTERVAL)

        if not monitoring_active:
            break  # Jeśli wyłączone, przerywamy pętlę

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
    global monitoring_active, sniff_thread, log_thread, sniffer

    if monitoring_active:
        print("⚠️ Monitorowanie już działa!")
        return

    print("📊 Monitorowanie ruchu sieciowego uruchomione...")
    traffic_logger.info("Monitorowanie ruchu sieciowego uruchomione.")
    monitoring_active = True

    # Tworzymy nowy obiekt sniffera (poprawka problemu restartu)
    sniffer = AsyncSniffer(filter="ip", prn=analyze_packet, store=False)

    # Uruchomienie wątku logowania statystyk
    log_thread = threading.Thread(target=log_traffic_stats, daemon=True)
    log_thread.start()

    # Uruchomienie sniffera w osobnym wątku
    sniff_thread = threading.Thread(target=sniffer.start, daemon=True)
    sniff_thread.start()

def stop_traffic_monitor():
    """Zatrzymuje monitorowanie ruchu"""
    global monitoring_active, sniff_thread, log_thread, sniffer

    if not monitoring_active:
        print("⚠️ Monitorowanie nie jest aktywne!")
        return

    print("🛑 Zatrzymuję monitorowanie ruchu...")
    traffic_logger.info("Monitorowanie ruchu sieciowego zatrzymane.")
    monitoring_active = False  # Wyłączanie flagi monitoringu

    # Zatrzymujemy sniffera
    try:
        if sniffer:
            sniffer.stop()
    except Exception as e:
        print(f"⚠️ Błąd podczas zatrzymywania sniffera: {e}")

    sniffer = None  # Kasujemy obiekt sniffera

    # Czekamy, aż wątki zakończą pracę
    if log_thread and log_thread.is_alive():
        log_thread.join(timeout=2)

    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join(timeout=2)

    sniff_thread = None
    log_thread = None

    print("✅ Monitorowanie ruchu zostało zatrzymane.")

def restart_traffic_monitor():
    """Restartuje monitorowanie ruchu"""
    print("🔄 Restartowanie monitorowania ruchu...")
    stop_traffic_monitor()
    time.sleep(1)  # Krótka przerwa, aby upewnić się, że wszystko się wyczyściło
    start_traffic_monitor()
    print("✅ Restart monitorowania ruchu zakończony.")

if __name__ == "__main__":
    start_traffic_monitor()
