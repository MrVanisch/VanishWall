import sys
import os
import importlib
import threading
import time
import logging
import queue
from scapy.all import sniff, IP, TCP, UDP
from modules.acl import ACLManager

# Pobieramy logger systemowy
system_logger = logging.getLogger("system")

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=30)  # Blokada IP na 30 sekund

# Porty podatne na Bypass Firewall
BYPASS_PORTS = [80, 443, 53, 22]  # HTTP, HTTPS, DNS, SSH
CHECK_INTERVAL = 10  # Co ile sekund analizujemy ruch
THREAT_THRESHOLD = 100  # Domyślny próg dla wszystkich portów
SSH_THRESHOLD = 250  # WYŻSZY próg dla SSH (port 22)
DECAY_FACTOR = 0.9  # Po każdym cyklu "starzenie" wyników

# 🛡️ Biała lista IP
WHITELISTED_IPS = {""}  # <- Dodaj swoje IP!

# Kolejka do przetwarzania pakietów
packet_queue = queue.Queue()

# Baza dynamicznego scoringu IP
threat_scores = {}

# Flagi kontrolne
detection_active = False
detection_thread = None
monitoring_thread = None

# Konfiguracja ochrony przed NTP Amplification
NTP_RESPONSE_LIMIT = 50
NTP_SIZE_THRESHOLD = 468
ntp_counters = {}
ntp_detection_active = False

def calculate_threat(ip, port):
    """Zwiększa punktację IP na podstawie wzorca ruchu"""
    if ip in WHITELISTED_IPS:
        return

    base_score = 5
    if port == 443:
        base_score *= 1.2
    elif port == 22:
        base_score *= 0.5
    elif port == 53:
        base_score *= 2

    threat_scores[ip] = threat_scores.get(ip, 0) + base_score


def process_bypass_packets():
    """Analizuje pakiety i przypisuje im scoring zagrożenia"""
    while detection_active:
        packet = packet_queue.get()
        try:
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                if dst_port in BYPASS_PORTS:
                    ip_src = packet[IP].src
                    calculate_threat(ip_src, dst_port)
        except Exception as e:
            system_logger.error(f"❌ Błąd w process_bypass_packets: {e}")
        packet_queue.task_done()


def process_ntp_packets():
    """Przetwarza pakiety NTP z kolejki i aktualizuje liczniki IP"""
    while ntp_detection_active:
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
    """Sprawdza liczbę dużych odpowiedzi NTP i blokuje IP"""
    while ntp_detection_active:
        time.sleep(CHECK_INTERVAL)
        for ip, ntp_count in list(ntp_counters.items()):
            if ntp_count > NTP_RESPONSE_LIMIT:
                if not acl.is_blocked(ip):
                    print(f"🛑 NTP Amplification: Podejrzane IP {ip} - {ntp_count} dużych pakietów NTP w {CHECK_INTERVAL} sekund")
                    system_logger.warning(f"NTP Amplification: Podejrzane IP {ip} - {ntp_count} dużych pakietów NTP w {CHECK_INTERVAL} sekund")
                    acl.block_ip(ip, reason="NTP Amplification Attack")
        ntp_counters.clear()


def start_ntp_ampl():
    """Uruchamia wykrywanie ataków NTP Amplification"""
    global ntp_detection_active
    if ntp_detection_active:
        print("⚠️ Ochrona przed NTP Amplification już działa!")
        return
    print("🛡️ Ochrona przed NTP Amplification uruchomiona...")
    system_logger.info("Ochrona przed NTP Amplification została uruchomiona.")
    ntp_detection_active = True
    threading.Thread(target=process_ntp_packets, daemon=True).start()
    threading.Thread(target=monitor_ntp_traffic, daemon=True).start()
    sniff(filter="udp port 123", prn=lambda pkt: packet_queue.put(pkt), store=False)


def stop_ntp_ampl():
    """Zatrzymuje ochronę przed NTP Amplification"""
    global ntp_detection_active
    print("🛑 Zatrzymywanie ochrony przed NTP Amplification...")
    ntp_detection_active = False


def restart_ntp_ampl():
    """Restartuje ochronę przed NTP Amplification"""
    print("🔄 Restartowanie ochrony przed NTP Amplification...")
    stop_ntp_ampl()
    time.sleep(1)
    start_ntp_ampl()
    print("✅ Restart ochrony przed NTP Amplification zakończony.")