from scapy.all import sniff, IP, TCP, UDP
import time
import logging
import threading
import queue
from modules.acl import ACLManager

# Pobieramy logger systemowy
system_logger = logging.getLogger("system")

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=30)  # Blokada IP na 30 sekund

# Porty podatne na Bypass Firewall
BYPASS_PORTS = [80, 443, 53, 22]  # HTTP, HTTPS, DNS, SSH
CHECK_INTERVAL = 10  # Co ile sekund analizujemy ruch

# Konfiguracja dynamicznych progów zagrożenia
THREAT_THRESHOLD = 100  # Domyślny próg dla wszystkich portów
SSH_THRESHOLD = 250  # WYŻSZY próg dla SSH (port 22)
DECAY_FACTOR = 0.9  # Po każdym cyklu "starzenie" wyników (zapobiega fałszywym alarmom)

# 🛡️ Biała lista IP (np. Twoje IP, VPN)
WHITELISTED_IPS = {""}  # <- Dodaj swoje IP!

# Kolejka do przetwarzania pakietów
packet_queue = queue.Queue()

# Baza dynamicznego scoringu IP
threat_scores = {}

def calculate_threat(ip, port):
    """Zwiększa punktację IP na podstawie wzorca ruchu"""
    if ip in WHITELISTED_IPS:
        return  # Nie liczymy ruchu dla zaufanych IP

    base_score = 5  # Domyślna wartość zagrożenia za pakiet
    if port == 443:
        base_score *= 1.2  # Ruch HTTPS może być trudniejszy do wykrycia
    elif port == 22:
        base_score *= 0.5  # ⚠️ SSH ma niższy priorytet, bo jest używane legalnie
    elif port == 53:
        base_score *= 2  # DNS może być używane do amplifikacji

    # Zwiększamy punktację zagrożenia
    threat_scores[ip] = threat_scores.get(ip, 0) + base_score

def process_bypass_packets():
    """Analizuje pakiety i przypisuje im scoring zagrożenia"""
    while True:
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
    while True:
        time.sleep(CHECK_INTERVAL)

        for ip, score in list(threat_scores.items()):
            # Ustalanie dynamicznego progu dla portu SSH
            threshold = SSH_THRESHOLD if ip in threat_scores and score < SSH_THRESHOLD else THREAT_THRESHOLD

            if score > threshold:
                if not acl.is_blocked(ip):  # Unikamy podwójnej blokady
                    print(f"🛑 Bypass Protection System: Blokowanie IP {ip} (Threat Score: {score:.1f})")
                    system_logger.warning(f"Bypass Protection System: Blokowanie IP {ip} (Threat Score: {score:.1f})")
                    acl.block_ip(ip, reason="Bypass Firewall Attack")

        # "Starzenie" punktacji, aby unikać fałszywych alarmów
        for ip in threat_scores.keys():
            threat_scores[ip] *= DECAY_FACTOR

def analyze_bypass_packet(packet):
    """Dodaje pakiet do kolejki do analizy"""
    packet_queue.put(packet)

def start_bypass_protection():
    """Uruchamia wykrywanie ataków Bypass Firewall"""
    print("🛡️ Bypass Protection System uruchomiony...")
    system_logger.info("Bypass Protection System został uruchomiony.")

    # Wątek do przetwarzania pakietów
    threading.Thread(target=process_bypass_packets, daemon=True).start()

    # Wątek do monitorowania ruchu
    threading.Thread(target=monitor_bypass_traffic, daemon=True).start()

    # Nasłuchiwanie pakietów TCP i UDP na ważnych portach
    sniff(filter="tcp or udp", prn=analyze_bypass_packet, store=False)
