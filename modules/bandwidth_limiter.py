from scapy.all import sniff, IP
import time
import threading
import importlib
import config
from modules.acl import ACLManager
from modules.logger import (
    system_logger, security_logger, traffic_logger,
    log_attack_detected, log_blocked_ip
)

# ACL do blokowania IP
acl = ACLManager(block_time=60)

# Stan działania
traffic = {}
monitoring_active = False
sniffer = None
monitor_thread = None

def get_dynamic_config():
    try:
        importlib.reload(config)
        return config.CONFIG.get("BANDWIDTH_LIMIT", 50 * 1024 * 1024), config.CONFIG.get("CHECK_INTERVAL", 10)
    except Exception as e:
        system_logger.error(f"Błąd ładowania config.py: {e}")
        return 50 * 1024 * 1024, 10

def analyze_packet(packet):
    """Zlicza bajty przesyłane przez IP źródłowe"""
    if not monitoring_active:
        return
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            packet_size = len(packet)
            traffic[ip_src] = traffic.get(ip_src, 0) + packet_size
    except Exception as e:
        system_logger.error(f"Błąd podczas analizy pakietu: {e}")

def monitor_traffic():
    """Analiza ilości przesłanych danych"""
    global monitoring_active
    while monitoring_active:
        bandwidth_limit, check_interval = get_dynamic_config()
        time.sleep(check_interval)

        for ip, bytes_sent in list(traffic.items()):
            mb = bytes_sent / (1024 * 1024)
            traffic_logger.info(f"{ip} przesłał {mb:.2f} MB w ciągu {check_interval} s")

            if bytes_sent > bandwidth_limit and not acl.is_blocked(ip):
                msg = f"WYKRYTO ATAK: {ip} - {mb:.2f} MB / {check_interval} s"
                print(f"🚨 {msg}")
                system_logger.warning(msg)

                log_attack_detected("Bandwidth Flood", ip, f"{mb:.2f} MB w {check_interval}s")
                log_blocked_ip(ip)

                acl.block_ip(ip, reason="Zbyt duże zużycie pasma")

        traffic.clear()

def start_bandwidth_limiter():
    """Uruchamia analizę przepustowości"""
    global monitoring_active, sniffer, monitor_thread

    if monitoring_active:
        print("⚠️ Monitorowanie już trwa.")
        return

    print("🛡️ Bandwidth limiter startuje...")
    system_logger.info("Bandwidth limiter został uruchomiony.")
    monitoring_active = True

    monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
    monitor_thread.start()

    try:
        sniffer = sniff(
            filter="ip",
            prn=analyze_packet,
            store=False,
            stop_filter=lambda _: not monitoring_active
        )
    except Exception as e:
        system_logger.error(f"Błąd sniffowania: {e}")
        stop_bandwidth_limiter()

def stop_bandwidth_limiter():
    """Zatrzymuje monitorowanie"""
    global monitoring_active, sniffer, monitor_thread

    if not monitoring_active:
        print("⚠️ Monitorowanie już wyłączone.")
        return

    print("🛑 Zatrzymywanie bandwidth limiter...")
    system_logger.info("Zatrzymano bandwidth limiter.")
    monitoring_active = False

    if monitor_thread and monitor_thread.is_alive():
        monitor_thread.join(timeout=2)

    sniffer = None
    monitor_thread = None
    print("✅ Bandwidth limiter zatrzymany.")

def restart_bandwidth_limiter():
    """Restartuje cały system"""
    print("🔄 Restartowanie bandwidth limiter...")
    stop_bandwidth_limiter()
    time.sleep(1)
    start_bandwidth_limiter()
    print("✅ Restart zakończony.")

if __name__ == "__main__":
    try:
        start_bandwidth_limiter()
    except KeyboardInterrupt:
        print("\n⛔ Przerwano przez użytkownika.")
        stop_bandwidth_limiter()
    except Exception as e:
        system_logger.error(f"Nieoczekiwany błąd główny: {e}")
        stop_bandwidth_limiter()
