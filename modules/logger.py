import logging
import os

# Tworzymy katalog logs, jeśli nie istnieje
os.makedirs("logs", exist_ok=True)

# FORMAT LOGÓW - zawiera nazwę loggera, nazwę pliku i linię
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
date_format = "%Y-%m-%d %H:%M:%S"

# Stałe na nazwy loggerów
SYSTEM_LOGGER_NAME = "ACL.System"
TRAFFIC_LOGGER_NAME = "ACL.Traffic"
SECURITY_LOGGER_NAME = "ACL.Security"
DEBUG_LOGGER_NAME = "ACL.Debug"

def setup_logger(name, log_file):
    """Konfiguruje logger i dodaje tylko jeden FileHandler, jeśli jeszcze go nie ma"""
    logger = logging.getLogger(name)
    
    if not logger.hasHandlers():
        logger.setLevel(logging.DEBUG if name == DEBUG_LOGGER_NAME else logging.INFO)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
        logger.addHandler(file_handler)
    
    return logger

# Log systemowy (moduły + ochrona)
system_logger = setup_logger(SYSTEM_LOGGER_NAME, "logs/system.log")

# Log ruchu sieciowego (statystyki)
traffic_logger = setup_logger(TRAFFIC_LOGGER_NAME, "logs/traffic.log")

# Log bezpieczeństwa (alerty, blokady, incydenty)
security_logger = setup_logger(SECURITY_LOGGER_NAME, "logs/security.log")

# Log debug (szczegóły techniczne, pakiety, zmienne)
debug_logger = setup_logger(DEBUG_LOGGER_NAME, "logs/debug.log")

def log_active_modules(config):
    """Loguje aktywne moduły do system.log"""
    try:
        active_modules = []

        if config.get("enable_traffic_monitor"):
            active_modules.append("Traffic Monitor")
        if config.get("enable_bandwidth_limiter"):
            active_modules.append("Bandwidth Limiter")
        if config.get("enable_syn_flood_protection"):
            active_modules.append("SYN Flood Protection")
        if config.get("enable_udp_flood_protection"):
            active_modules.append("UDP Flood Protection")
        if config.get("enable_dns_amplification_protection"):
            active_modules.append("DNS Amplification Protection")

        modules_list = ", ".join(active_modules) if active_modules else "Brak aktywnych modułów"
        log_message = f"🚀 Uruchomione moduły: {modules_list}"

        print(log_message)
        system_logger.info(log_message)

    except Exception as e:
        system_logger.error("Błąd podczas logowania aktywnych modułów", exc_info=True)

# Funkcje bezpieczeństwa
def log_blocked_ip(ip):
    """Loguje zablokowany adres IP"""
    msg = f"🛡️ Zablokowano pakiet od podejrzanego IP: {ip}"
    security_logger.warning(msg)

def log_attack_detected(attack_type, src_ip, details=""):
    """Loguje wykryty atak (np. flood)"""
    msg = f"🚨 Wykryto atak typu {attack_type} z IP: {src_ip}. {details}"
    security_logger.error(msg)

def log_firewall_breach_attempt(src_ip, reason):
    """Loguje próbę obejścia ochrony"""
    msg = f"⚠️ Próba obejścia systemu ochrony z IP {src_ip}. Powód: {reason}"
    security_logger.critical(msg)

# Funkcje debug
def log_packet_parsing(proto, src_ip, dst_ip, flags=None):
    msg = f"📦 Pakiet {proto} | {src_ip} → {dst_ip} | Flags: {flags}"
    debug_logger.debug(msg)

def log_module_state(module, state_dict):
    msg = f"⚙️ Stan modułu {module}: {state_dict}"
    debug_logger.debug(msg)

def log_loaded_config(config):
    msg = f"📚 Załadowana konfiguracja: {config}"
    debug_logger.debug(msg)

def log_ai_decision(ip, score, decision):
    msg = f"🤖 AI analiza: IP={ip}, score={score}, decyzja={decision}"
    debug_logger.debug(msg)

def log_raw_exception(context, error):
    msg = f"🐞 Błąd w {context}: {error}"
    debug_logger.debug(msg, exc_info=True)
