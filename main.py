# -*- coding: utf-8 -*-
import threading
import time
from config import CONFIG
from modules.logger import system_logger, log_active_modules
from modules.traffic_monitor import start_traffic_monitor
from modules.bandwidth_limiter import start_bandwidth_limiter
from modules.syn_flood import start_syn_protection
from modules.udp_flood import start_udp_protection
from modules.dns_ampl import start_dns_protection
from modules.ntp_ampl import start_ntp_protection
from modules.bypass_protection_system import start_bypass_protection

def main():
    """Główna funkcja uruchamiająca moduły ochrony"""
    print("🚀 Uruchamiam system ACL...")
    system_logger.info("System ACL został uruchomiony.")

    # Logowanie aktywnych modułów
    log_active_modules(CONFIG)

    # Lista modułów do uruchomienia w osobnych wątkach
    modules = []

    if CONFIG["enable_traffic_monitor"]:
        modules.append(threading.Thread(target=start_traffic_monitor, daemon=True))
    
    if CONFIG["enable_bandwidth_limiter"]:
        system_logger.info("🛡️ Ochrona Bandwidth Limiter aktywna")
        modules.append(threading.Thread(target=start_bandwidth_limiter, daemon=True))
    
    if CONFIG["enable_syn_flood_protection"]:
        system_logger.info("🛡️ Ochrona SYN Flood aktywna")
        modules.append(threading.Thread(target=start_syn_protection, daemon=True))

    if CONFIG["enable_udp_flood_protection"]:
        system_logger.info("🛡️ Ochrona UDP Flood aktywna")
        modules.append(threading.Thread(target=start_udp_protection, daemon=True))

    if CONFIG["enable_dns_amplification_protection"]:
        system_logger.info("🛡️ Ochrona DNS Amplification aktywna")
        modules.append(threading.Thread(target=start_dns_protection, daemon=True))

    if CONFIG["enable_ntp_protection"]:
        system_logger.info("🛡️ Ochrona NTP Amplification aktywna")
        modules.append(threading.Thread(target=start_ntp_protection, daemon=True))

    if CONFIG["enable_bypass_protection"]:
        system_logger.info("🛡️ Bypass Protection System aktywny")
        modules.append(threading.Thread(target=start_bypass_protection, daemon=True))

    # Uruchamiamy wszystkie moduły w osobnych wątkach
    for module in modules:
        module.start()

    try:
        while True:
            time.sleep(1)  
    except KeyboardInterrupt:
        print("\n🛑 Zatrzymywanie systemu ACL...")
        system_logger.info("System ACL został zatrzymany.")

if __name__ == "__main__":
    main()