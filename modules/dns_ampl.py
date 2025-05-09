from scapy.all import sniff, IP, UDP, DNS
import time
import logging
import threading
import queue
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger
import importlib
import config

# 🔁 Funkcja do pobierania dynamicznych wartości z CONFIG
def get_dns_config():
    importlib.reload(config)
    return (
        config.CONFIG.get("DNS_RESPONSE_LIMIT", 100),
        config.CONFIG.get("DNS_SIZE_THRESHOLD", 500),
        config.CONFIG.get("CHECK_INTERVAL_DNS", 10)
    )

# Inicjalizacja
acl = ACLManager(block_time=10)
packet_queue = queue.Queue()
dns_counters = {}
stop_event = threading.Event()

def process_dns_packets():
    """Przetwarza pakiety DNS z kolejki i aktualizuje liczniki IP"""
    while not stop_event.is_set():
        try:
            _, size_threshold, _ = get_dns_config()
            packet = packet_queue.get(timeout=1)
            if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS):
                if packet[UDP].sport == 53 and len(packet) > size_threshold:
                    ip_src = packet[IP].src
                    dns_counters[ip_src] = dns_counters.get(ip_src, 0) + 1
                    debug_logger.debug(f"📦 Duża odpowiedź DNS od {ip_src} (rozmiar: {len(packet)} B)")
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            system_logger.error("❌ Błąd w process_dns_packets", exc_info=True)

def monitor_dns_traffic():
    """Sprawdza liczbę dużych odpowiedzi DNS i blokuje IP, jeśli przekroczy limit"""
    while not stop_event.is_set():
        response_limit, _, check_interval = get_dns_config()
        time.sleep(check_interval)

        for ip, dns_count in list(dns_counters.items()):
            if dns_count > response_limit and not acl.is_blocked(ip):
                msg = f"🛑 DNS Amplification: IP {ip} - {dns_count} dużych pakietów w {check_interval}s"
                print(msg)
                system_logger.warning(msg)
                security_logger.warning(f"🚨 Wykryto atak DNS Amplification z IP: {ip}")
                acl.block_ip(ip, reason="DNS Amplification Attack")
                debug_logger.debug(f"🔒 Zablokowano IP {ip}")

        debug_logger.debug("🔄 Resetowanie liczników DNS")
        dns_counters.clear()

def analyze_dns_packet(packet):
    """Dodaje pakiet DNS do kolejki do analizy"""
    if not stop_event.is_set():
        packet_queue.put(packet)

def start_dns_ampl():
    """Uruchamia ochronę DNS Amplification"""
    print("🛡️ Ochrona przed DNS Amplification uruchomiona...")
    system_logger.info("🛡️ Ochrona przed DNS Amplification uruchomiona")
    stop_event.clear()

    threading.Thread(target=process_dns_packets, daemon=True).start()
    threading.Thread(target=monitor_dns_traffic, daemon=True).start()

    try:
        sniff(filter="udp port 53", prn=analyze_dns_packet, store=False, stop_filter=lambda _: stop_event.is_set())
    except Exception as e:
        system_logger.error("❌ Błąd działania sniffera DNS", exc_info=True)

def stop_dns_ampl():
    """Zatrzymuje ochronę DNS Amplification"""
    print("🛑 Zatrzymywanie ochrony DNS Amplification...")
    system_logger.info("🛑 Ochrona DNS Amplification zatrzymana")
    stop_event.set()
    packet_queue.queue.clear()
    debug_logger.debug("🧹 Wyczyściłem kolejkę DNS")
