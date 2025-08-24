from scapy.all import sniff, IP, TCP, AsyncSniffer
import time
import logging
import threading
import queue
import importlib
import config
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger

# Tworzymy instancję ACLManager
acl = ACLManager(block_time=10)

# Kolejka do przechowywania pakietów SYN
packet_queue = queue.Queue()

# Liczniki SYN na IP
syn_counters = {}

# Flaga zatrzymania i sniffer globalny
stop_event = threading.Event()
sniffer_thread = None

def get_syn_settings():
    """Wczytuje bieżące ustawienia SYN z config.py"""
    importlib.reload(config)
    return (
        config.CONFIG.get("SYN_LIMIT", 100),
        config.CONFIG.get("CHECK_INTERVAL_SYN", 10)
    )

def process_syn_packets():
    """Zlicza pakiety SYN z kolejki"""
    while not stop_event.is_set():
        try:
            packet = packet_queue.get(timeout=1)
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == 0x02:
                ip_src = packet[IP].src
                syn_counters[ip_src] = syn_counters.get(ip_src, 0) + 1
                debug_logger.debug(f"SYN od {ip_src}: {syn_counters[ip_src]}")
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            system_logger.error(f"❌ Błąd w process_syn_packets: {e}", exc_info=True)

def monitor_syn_traffic():
    """Monitoruje SYN flood i blokuje atakujące IP"""
    while not stop_event.is_set():
        SYN_LIMIT, CHECK_INTERVAL = get_syn_settings()
        time.sleep(CHECK_INTERVAL)

        suspicious_count = 0
        for ip, count in list(syn_counters.items()):
            if count > SYN_LIMIT and not acl.is_blocked(ip):
                msg = f"SYN flood: IP {ip} - {count} SYN w {CHECK_INTERVAL}s"
                print(f"🛑 {msg}")
                system_logger.warning(msg)
                security_logger.warning(f"🔐 Zablokowano IP {ip} (SYN flood)")
                acl.block_ip(ip, reason="SYN flood attack")
                suspicious_count += 1

        if suspicious_count > 0:
            debug_logger.debug(f"🧠 Wykryto {suspicious_count} agresywnych IP")

        syn_counters.clear()
        debug_logger.debug("🧹 Wyczyszczono liczniki SYN")

def analyze_syn_packet(packet):
    """Przekazuje pakiet do kolejki"""
    if not stop_event.is_set():
        packet_queue.put(packet)

def start_syn_flood():
    """Startuje ochronę SYN flood"""
    print("🛡️ Ochrona przed SYN flood uruchomiona...")
    system_logger.info("🛡️ SYN flood protection started")
    stop_event.clear()

    threading.Thread(target=process_syn_packets, daemon=True).start()
    threading.Thread(target=monitor_syn_traffic, daemon=True).start()

    try:
        global sniffer_thread
        sniffer_thread = AsyncSniffer(
            filter="tcp",
            prn=analyze_syn_packet,
            store=False
        )
        sniffer_thread.start()
    except Exception as e:
        system_logger.error(f"❌ Błąd sniffowania: {e}", exc_info=True)
        print(f"❌ Błąd sniffowania: {e}")

def stop_syn_flood():
    """Zatrzymuje ochronę SYN flood"""
    print("🛑 Zatrzymywanie SYN flood...")
    system_logger.info("🛑 SYN flood protection stopped")
    stop_event.set()

    global sniffer_thread
    if sniffer_thread:
        sniffer_thread.stop()
        sniffer_thread = None

    packet_queue.queue.clear()
    debug_logger.debug("🧹 Kolejka pakietów wyczyszczona")
