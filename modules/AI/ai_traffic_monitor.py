import threading
import logging
import time
from scapy.all import sniff, IP, TCP, UDP
from modules.AI.ai_model import AIModel
from modules.AI.ai_database import AIDatabase
from modules.acl import ACLManager

# Pobieramy logger systemowy
system_logger = logging.getLogger("system")

# ✅ Obiekty są inicjalizowane dopiero po wywołaniu funkcji
acl = None
ai = None
db = None
stop_event = threading.Event()  # Flaga do zatrzymywania monitorowania

def initialize_ai():
    """Inicjalizuje AI, ACL i bazę danych (wywoływane tylko wtedy, gdy potrzebne)."""
    global acl, ai, db
    if acl is None:
        acl = ACLManager(block_time=30)
    if ai is None:
        ai = AIModel()
    if db is None:
        db = AIDatabase()

# **Whitelista IP (nie blokujemy ruchu od tych adresów)**
WHITELISTED_IPS = {
    "51.38.135.70",  # Twój serwer
    #"149.156.124.1",  # Twoje IP
}

# **Czas nauki AI (np. 10 minut)**
LEARNING_TIME = 600  # 10 minut
LEARNING_MODE = True  
SUSPECT_THRESHOLD = 3  # AI musi wykryć anomalie X razy, zanim zablokuje

# Słownik do monitorowania podejrzanych IP
suspect_ips = {}

def disable_learning_mode():
    """Po 10 minutach AI zaczyna blokować IP"""
    global LEARNING_MODE
    time.sleep(LEARNING_TIME)
    if not stop_event.is_set():  # Sprawdzamy, czy program został zatrzymany
        LEARNING_MODE = False
        print("✅ AI zakończyło tryb nauki. Teraz zaczyna wykrywać anomalie.")

def extract_bit_pattern(packet):
    """Pobiera pierwsze 64 bajty pakietu i konwertuje je na bity"""
    raw_data = bytes(packet)
    return ''.join(format(byte, '08b') for byte in raw_data[:64])  # Pierwsze 64 bajty

def analyze_packet(packet):
    """Analizuje pakiety i wykrywa anomalie"""
    if stop_event.is_set():  # Sprawdzamy, czy program został zatrzymany
        return

    if packet.haslayer(IP):
        ip_src = packet[IP].src

        # **Jeśli IP jest na whiteliście, ignorujemy**
        if ip_src in WHITELISTED_IPS:
            return  

        packet_size = len(packet)
        protocol = "TCP" if packet.haslayer(TCP) else "UDP"

        # **Pobieramy binarny wzorzec pakietu**
        bit_pattern = extract_bit_pattern(packet)

        # **Zapisujemy ruch do bazy danych**
        db.insert_traffic(ip_src, bit_pattern, protocol)

        # **AI zbiera dane**
        if ip_src not in ai.traffic_data:
            ai.traffic_data[ip_src] = []
        ai.traffic_data[ip_src].append([bit_pattern, 1 if protocol == "TCP" else 0])

        # **Tryb nauki – AI zbiera dane, ale NIE BLOKUJE**
        if LEARNING_MODE:
            print(f"📊 AI Learning Mode: {ip_src} -> {bit_pattern} ({protocol})")
            return  

        # **AI sprawdza, czy ruch jest anomalią**
        if ai.predict(ip_src, bit_pattern, protocol):
            # Jeśli IP już było oznaczone jako podejrzane, zwiększamy licznik
            suspect_ips[ip_src] = suspect_ips.get(ip_src, 0) + 1

            if suspect_ips[ip_src] >= SUSPECT_THRESHOLD:  # **Blokujemy dopiero po X wykryciach**
                system_logger.warning(f"AI: Wykryto atak od {ip_src}, blokowanie!")
                acl.block_ip(ip_src, reason="AI Detected Anomaly")

def start_ai_traffic_monitor():
    """Inicjalizuje AI i uruchamia monitorowanie ruchu"""
    initialize_ai()  # ✅ Teraz AI uruchomi się tylko, jeśli to wywołasz!
    
    print("🛡️ AI Traffic Monitor uruchomione...")
    system_logger.info("AI Traffic Monitor uruchomione.")

    stop_event.clear()  # Resetujemy flagę stopowania

    threading.Thread(target=disable_learning_mode, daemon=True).start()
    sniff(filter="ip", prn=analyze_packet, store=False, stop_filter=lambda _: stop_event.is_set())

def stop_ai_traffic_monitor():
    """Zatrzymuje monitorowanie ruchu AI"""
    print("🛑 Zatrzymywanie AI Traffic Monitor...")
    system_logger.info("AI Traffic Monitor zatrzymane.")
    stop_event.set()  # Ustawienie flagi zatrzymania
