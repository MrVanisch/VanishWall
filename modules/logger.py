import logging
import os

# Tworzymy katalog logs, jeśli nie istnieje
os.makedirs("logs", exist_ok=True)

# FORMAT LOGÓW
log_format = "%(asctime)s - %(levelname)s - %(message)s"
date_format = "%Y-%m-%d %H:%M:%S"

# Usuwamy `basicConfig`, żeby uniknąć konfliktów

def setup_logger(name, log_file):
    """Konfiguruje logger i dodaje tylko jeden FileHandler, jeśli jeszcze go nie ma"""
    logger = logging.getLogger(name)
    
    # Sprawdzamy, czy logger już ma handler, żeby nie dodawać kolejnego
    if not logger.hasHandlers():
        logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
        logger.addHandler(file_handler)
    
    return logger

# Log systemowy (moduły + ochrona)
system_logger = setup_logger("system", "logs/system.log")

# Log ruchu sieciowego (statystyki)
traffic_logger = setup_logger("traffic", "logs/traffic.log")

def log_active_modules(config):
    """Loguje aktywne moduły do system.log"""
    active_modules = []

    if config["enable_traffic_monitor"]:
        active_modules.append("Traffic Monitor")
    if config["enable_bandwidth_limiter"]:
        active_modules.append("Bandwidth Limiter")
    if config["enable_syn_flood_protection"]:
        active_modules.append("SYN Flood Protection")
    if config["enable_udp_flood_protection"]:
        active_modules.append("UDP Flood Protection")
    if config["enable_dns_amplification_protection"]:
        active_modules.append("DNS Amplification Protection")

    modules_list = ", ".join(active_modules) if active_modules else "Brak aktywnych modułów"
    log_message = f"🚀 Uruchomione moduły: {modules_list}"

    print(log_message)
    system_logger.info(log_message)
