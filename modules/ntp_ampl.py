import threading
import time
import queue
from scapy.all import sniff, IP, UDP
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger
from config import CONFIG

# Dynamiczne ustawienia
NTP_RESPONSE_LIMIT = CONFIG.get("NTP_RESPONSE_LIMIT", 50)
NTP_SIZE_THRESHOLD = CONFIG.get("NTP_SIZE_THRESHOLD", 468)
CHECK_INTERVAL_NTP = CONFIG.get("CHECK_INTERVAL_NTP", 10)

# ACL i stan
acl = ACLManager(block_time=30)
ntp_counters = {}
ntp_detection_active = False
packet_queue = queue.Queue()

def process_ntp_packets():
    """Zlicza duże pakiety NTP i aktualizuje liczniki IP"""
    while ntp_detection_active:
        try:
            packet = packet_queue.get(timeout=1)
            if packet.haslayer(IP) and packet.haslayer(UDP):
                if packet[UDP].sport == 123 and len(packet) > NTP_SIZE_THRESHOLD:
                    ip = packet[IP].src
                    ntp_counters[ip] = ntp_counters.get(ip, 0) + 1
                    debug_logger.debug(f"📦 Duży pakiet NTP od {ip} (rozmiar: {len(packet)} B)")
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            system_logger.error(f"❌ Błąd w process_ntp_packets: {e}", exc_info=True)

def monitor_ntp_traffic():
    """Sprawdza IP z dużą liczbą odpowiedzi NTP i je blokuje"""
    while ntp_detection_active:
        time.sleep(CHECK_INTERVAL_NTP)
        for ip, count in list(ntp_counters.items()):
            if count > NTP_RESPONSE_LIMIT and not acl.is_blocked(ip):
                msg = f"🚨 NTP Amplification: {ip} - {count} dużych pakietów w {CHECK_INTERVAL_NTP}s"
                print(f"🛑 {msg}")
                system_logger.warning(msg)
                security_logger.warning(msg)
                acl.block_ip(ip, reason="NTP Amplification Attack")
        ntp_counters.clear()
        debug_logger.debug("🔄 Liczniki NTP wyczyszczone")

def start_ntp_ampl():
    """Uruchamia analizę NTP"""
    global ntp_detection_active
    if ntp_detection_active:
        print("⚠️ NTP Amplification już działa")
        return

    print("🛡️ Uruchamiam ochronę NTP Amplification...")
    system_logger.info("NTP Amplification został uruchomiony")
    ntp_detection_active = True

    threading.Thread(target=process_ntp_packets, daemon=True).start()
    threading.Thread(target=monitor_ntp_traffic, daemon=True).start()

    try:
        sniff(filter="udp port 123", prn=lambda pkt: packet_queue.put(pkt), store=False, stop_filter=lambda _: not ntp_detection_active)
    except Exception as e:
        system_logger.error("❌ Błąd sniffowania UDP/123", exc_info=True)

def stop_ntp_ampl():
    """Zatrzymuje analizę NTP"""
    global ntp_detection_active
    print("🛑 Zatrzymuję ochronę NTP Amplification...")
    system_logger.info("Zatrzymano ochronę NTP Amplification")
    ntp_detection_active = False
    packet_queue.queue.clear()

def restart_ntp_ampl():
    """Restartuje analizę NTP"""
    print("🔄 Restartuję ochronę NTP Amplification...")
    stop_ntp_ampl()
    time.sleep(1)
    start_ntp_ampl()
    print("✅ Restart zakończony")
