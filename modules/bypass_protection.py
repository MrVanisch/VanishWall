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


def monitor_bypass_traffic():
    """Analizuje scoring IP i blokuje podejrzane IP"""
    while detection_active:
        time.sleep(CHECK_INTERVAL)

        for ip, score in list(threat_scores.items()):
            threshold = SSH_THRESHOLD if ip in threat_scores and score < SSH_THRESHOLD else THREAT_THRESHOLD

            if score > threshold:
                if not acl.is_blocked(ip):
                    print(f"🛑 Blokowanie IP {ip} (Threat Score: {score:.1f})")
                    system_logger.warning(f"Blokowanie IP {ip} (Threat Score: {score:.1f})")
                    acl.block_ip(ip, reason="Bypass Firewall Attack")

        for ip in threat_scores.keys():
            threat_scores[ip] *= DECAY_FACTOR


def analyze_bypass_packet(packet):
    """Dodaje pakiet do kolejki do analizy"""
    packet_queue.put(packet)


def start_bypass_protection():
    """Uruchamia wykrywanie ataków Bypass Firewall"""
    global detection_active, detection_thread, monitoring_thread
    if detection_active:
        print("⚠️ Ochrona przed bypass już działa!")
        return
    print("🛡️ Bypass Protection System uruchomiony...")
    system_logger.info("Bypass Protection System został uruchomiony.")
    detection_active = True
    detection_thread = threading.Thread(target=process_bypass_packets, daemon=True)
    detection_thread.start()
    monitoring_thread = threading.Thread(target=monitor_bypass_traffic, daemon=True)
    monitoring_thread.start()
    sniff(filter="tcp or udp", prn=analyze_bypass_packet, store=False)


def stop_bypass_protection():
    """Zatrzymuje ochronę przed bypass"""
    global detection_active, detection_thread, monitoring_thread
    if not detection_active:
        print("⚠️ Ochrona przed bypass nie jest aktywna!")
        return
    print("🛑 Zatrzymywanie ochrony przed bypass...")
    detection_active = False
    if detection_thread and detection_thread.is_alive():
        detection_thread.join(timeout=2)
    if monitoring_thread and monitoring_thread.is_alive():
        monitoring_thread.join(timeout=2)
    detection_thread = None
    monitoring_thread = None
    print("✅ Ochrona przed bypass została zatrzymana.")


def restart_bypass_protection():
    """Restartuje ochronę przed bypass"""
    print("🔄 Restartowanie ochrony przed bypass...")
    stop_bypass_protection()
    time.sleep(1)
    start_bypass_protection()
    print("✅ Restart ochrony przed bypass zakończony.")
