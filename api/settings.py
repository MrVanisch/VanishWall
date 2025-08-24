from flask import Blueprint, jsonify, request
import importlib
import config

settings_bp = Blueprint("settings", __name__)

def _reload_config():
    importlib.reload(config)
    return config.CONFIG

def get_setting(key, default=None):
    return _reload_config().get(key, default)

def update_settings(updates: dict):
    config_dict = _reload_config()
    config_dict.update(updates)

    new_lines = ["CONFIG = {\n"]
    for key, value in config_dict.items():
        val_repr = f'"{value}"' if isinstance(value, str) else str(value)
        new_lines.append(f'    "{key}": {val_repr},\n')
    new_lines.append("}\n")

    with open("config.py", "w") as f:
        f.writelines(new_lines)


# -------------------- BANDWIDTH LIMITER --------------------
@settings_bp.route('/get_bandwidth_limiter_settings', methods=['GET'])
def get_bandwidth_limiter_settings():
    return jsonify({
        "title": "Ustawienia: Bandwidth Limiter",
        "fields": [
            {
                "id": "limit",
                "label": "Limit pasma (MB)",
                "type": "number",
                "value": get_setting("BANDWIDTH_LIMIT", 50 * 1024 * 1024) // (1024 * 1024)
            },
            {
                "id": "interval",
                "label": "Interwał sprawdzania (s)",
                "type": "number",
                "value": get_setting("CHECK_INTERVAL", 10)
            }
        ]
    })

@settings_bp.route('/update_bandwidth_limiter_settings', methods=['POST'])
def update_bandwidth_limiter_settings():
    data = request.get_json()
    update_settings({
        "BANDWIDTH_LIMIT": int(data.get("limit")) * 1024 * 1024,
        "CHECK_INTERVAL": int(data.get("interval"))
    })
    return jsonify({"status": "success"})


# -------------------- PORT SCANNER PROTECTION --------------------
@settings_bp.route('/get_port_scanner_settings', methods=['GET'])
def get_port_scanner_settings():
    suspicious_ports = get_setting("PORTSCAN_SUSPICIOUS_PORTS", [21, 22, 23, 25, 53, 80, 110, 143, 443])
    ports_str = ",".join(map(str, suspicious_ports))
    
    return jsonify({
        "title": "Ustawienia: Port Scanner Protection",
        "fields": [
            {
                "id": "threshold",
                "label": "Próg wykrycia (liczba portów)",
                "type": "number",
                "value": get_setting("PORTSCAN_THRESHOLD", 10)
            },
            {
                "id": "time_window",
                "label": "Okno czasowe (sekundy)",
                "type": "number",
                "value": get_setting("PORTSCAN_TIME_WINDOW", 30)
            },
            {
                "id": "block_time",
                "label": "Czas blokady (sekundy)",
                "type": "number",
                "value": get_setting("PORTSCAN_BLOCK_TIME", 600)
            },
            {
                "id": "suspicious_ports",
                "label": "Podejrzane porty (oddzielone przecinkami)",
                "type": "text",
                "value": ports_str
            },
            {
                "id": "check_interval",
                "label": "Interwał sprawdzania (sekundy)",
                "type": "number",
                "value": get_setting("CHECK_INTERVAL_PORTSCAN", 10)
            }
        ]
    })

@settings_bp.route('/update_port_scanner_settings', methods=['POST'])
def update_port_scanner_settings():
    data = request.get_json()
    
    # Parsowanie portów z string na listę int
    ports_str = data.get("suspicious_ports", "")
    suspicious_ports = []
    
    if ports_str:
        try:
            suspicious_ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
        except ValueError:
            return jsonify({"status": "error", "message": "Nieprawidłowy format portów"}), 400
    
    update_settings({
        "PORTSCAN_THRESHOLD": int(data.get("threshold")),
        "PORTSCAN_TIME_WINDOW": int(data.get("time_window")),
        "PORTSCAN_BLOCK_TIME": int(data.get("block_time")),
        "PORTSCAN_SUSPICIOUS_PORTS": suspicious_ports,
        "CHECK_INTERVAL_PORTSCAN": int(data.get("check_interval"))
    })
    
    return jsonify({"status": "success"})

# -------------------- PORT SCANNER STATS --------------------
@settings_bp.route('/get_port_scanner_stats', methods=['GET'])
def get_port_scanner_stats():
    try:
        from modules.port_scanner import get_port_scanner_stats
        stats = get_port_scanner_stats()
        return jsonify({"status": "success", "data": stats})
    except ImportError:
        return jsonify({"status": "error", "message": "Moduł port scanner niedostępny"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



# -------------------- SYN FLOOD --------------------
@settings_bp.route('/get_syn_flood_settings', methods=['GET'])
def get_syn_flood_settings():
    return jsonify({
        "title": "Ustawienia: SYN Flood",
        "fields": [
            {
                "id": "limit",
                "label": "Limit SYN (pakiety)",
                "type": "number",
                "value": get_setting("SYN_LIMIT", 100)
            },
            {
                "id": "interval",
                "label": "Interwał sprawdzania (s)",
                "type": "number",
                "value": get_setting("CHECK_INTERVAL_SYN", 10)
            }
        ]
    })

@settings_bp.route('/update_syn_flood_settings', methods=['POST'])
def update_syn_flood_settings():
    data = request.get_json()
    update_settings({
        "SYN_LIMIT": int(data.get("limit")),
        "CHECK_INTERVAL_SYN": int(data.get("interval"))
    })
    return jsonify({"status": "success"})


# -------------------- UDP FLOOD --------------------
# -------------------- UDP FLOOD --------------------
@settings_bp.route('/get_udp_flood_settings', methods=['GET'])
def get_udp_flood_settings():
    return jsonify({
        "title": "Ustawienia: UDP Flood Detection",
        "fields": [
            {
                "id": "limit",
                "label": "Limit UDP (pakiety/okres)",
                "type": "number",
                "value": get_setting("UDP_LIMIT", 200)
            },
            {
                "id": "interval",
                "label": "Interwał sprawdzania (s)",
                "type": "number",
                "value": get_setting("CHECK_INTERVAL_UDP", 10)
            },
            {
                "id": "worker_threads",
                "label": "Liczba wątków roboczych",
                "type": "number",
                "value": get_setting("UDP_WORKER_THREADS", 2)
            },
            {
                "id": "queue_size",
                "label": "Rozmiar kolejki pakietów",
                "type": "number",
                "value": get_setting("PACKET_QUEUE_SIZE", 1000)
            },
            {
                "id": "history_size",
                "label": "Rozmiar historii statystyk",
                "type": "number",
                "value": get_setting("MAX_HISTORY_SIZE", 10)
            },
            {
                "id": "anomaly_multiplier",
                "label": "Mnożnik progu anomalii",
                "type": "number",
                "value": get_setting("ANOMALY_THRESHOLD_MULTIPLIER", 3)
            },
            {
                "id": "block_time",
                "label": "Czas blokady (s)",
                "type": "number",
                "value": get_setting("UDP_BLOCK_TIME", 300)
            }
        ]
    })

@settings_bp.route('/update_udp_flood_settings', methods=['POST'])
def update_udp_flood_settings():
    data = request.get_json()
    update_settings({
        "UDP_LIMIT": int(data.get("limit")),
        "CHECK_INTERVAL_UDP": int(data.get("interval")),
        "UDP_WORKER_THREADS": int(data.get("worker_threads")),
        "PACKET_QUEUE_SIZE": int(data.get("queue_size")),
        "MAX_HISTORY_SIZE": int(data.get("history_size")),
        "ANOMALY_THRESHOLD_MULTIPLIER": float(data.get("anomaly_multiplier")),
        "UDP_BLOCK_TIME": int(data.get("block_time"))
    })
    return jsonify({"status": "success"})


# -------------------- NTP --------------------
@settings_bp.route('/get_ntp_ampl_settings', methods=['GET'])
def get_ntp_ampl_settings():
    return jsonify({
        "title": "Ustawienia: NTP Amplification",
        "fields": [
            {
                "id": "limit",
                "label": "Limit odpowiedzi NTP (pakiety)",
                "type": "number",
                "value": get_setting("NTP_RESPONSE_LIMIT", 50)
            },
            {
                "id": "size_threshold",
                "label": "Próg rozmiaru pakietu (B)",
                "type": "number",
                "value": get_setting("NTP_SIZE_THRESHOLD", 468)
            },
            {
                "id": "interval",
                "label": "Interwał sprawdzania (s)",
                "type": "number",
                "value": get_setting("CHECK_INTERVAL_NTP", 10)
            }
        ]
    })

@settings_bp.route('/update_ntp_ampl_settings', methods=['POST'])
def update_ntp_ampl_settings():
    data = request.get_json()
    update_settings({
        "NTP_RESPONSE_LIMIT": int(data.get("limit")),
        "NTP_SIZE_THRESHOLD": int(data.get("size_threshold")),
        "CHECK_INTERVAL_NTP": int(data.get("interval"))
    })
    return jsonify({"status": "success"})

# -------------------- DNS --------------------

# -------------------- DNS --------------------

@settings_bp.route('/get_dns_ampl_settings', methods=['GET'])
def get_dns_ampl_settings():
    return jsonify({
        "title": "Ustawienia: DNS Amplification",
        "fields": [
            {"id": "response_limit", "label": "Limit odpowiedzi DNS (na interwał)", "type": "number", "value": get_setting("DNS_RESPONSE_LIMIT", 50)},
            {"id": "size_threshold", "label": "Minimalny rozmiar pakietu DNS (B)", "type": "number", "value": get_setting("DNS_SIZE_THRESHOLD", 300)},
            {"id": "check_interval", "label": "Interwał sprawdzania (s)", "type": "number", "value": get_setting("CHECK_INTERVAL_DNS", 5)},
            {"id": "rate_limit", "label": "Limit zapytań/sekundę", "type": "number", "value": get_setting("DNS_RATE_LIMIT", 20)},
            {"id": "ratio_threshold", "label": "Próg amplifikacji", "type": "number", "value": get_setting("DNS_RATIO_THRESHOLD", 5.0)},
            {"id": "time_window", "label": "Okno czasowe (s)", "type": "number", "value": get_setting("TIME_WINDOW", 60)},
        ]
    })

@settings_bp.route('/update_dns_ampl_settings', methods=['POST'])
def update_dns_ampl_settings():
    data = request.get_json()
    update_settings({
        "DNS_RESPONSE_LIMIT": int(data.get("response_limit")),
        "DNS_SIZE_THRESHOLD": int(data.get("size_threshold")),
        "CHECK_INTERVAL_DNS": int(data.get("check_interval")),
        "DNS_RATE_LIMIT": int(data.get("rate_limit")),
        "DNS_RATIO_THRESHOLD": float(data.get("ratio_threshold")),
        "TIME_WINDOW": int(data.get("time_window"))
    })
    return jsonify({"status": "success"})


# -------------------- BYPASS PROTECTION --------------------

# -------------------- BYPASS PROTECTION --------------------

@settings_bp.route('/get_bypass_protection_settings', methods=['GET'])
def get_bypass_protection_settings():
    ports = get_setting("BYPASS_PORTS", [])
    suspicious_patterns = get_setting("SUSPICIOUS_PATTERNS", [])
    iface = get_setting("BYPASS_IFACE", "ens3")

    return jsonify({
        "title": "Ustawienia: bypass_protection",
        "fields": [
            {
                "id": "BYPASS_PORTS",
                "label": "Porty podatne (oddzielone przecinkami)",
                "type": "text",
                "value": ",".join(map(str, ports))
            },
            {
                "id": "BYPASS_IFACE",
                "label": "Interfejs (np. ens3 / eth0)",
                "type": "text",
                "value": iface
            },
            {
                "id": "CHECK_INTERVAL_BYPASS",
                "label": "Interwał sprawdzania (s)",
                "type": "number",
                "value": get_setting("CHECK_INTERVAL_BYPASS", 10)
            },
            {
                "id": "THREAT_THRESHOLD",
                "label": "Próg zagrożenia",
                "type": "number",
                "value": get_setting("THREAT_THRESHOLD", 100)
            },
            {
                "id": "SSH_THRESHOLD",
                "label": "Próg dla SSH",
                "type": "number",
                "value": get_setting("SSH_THRESHOLD", 250)
            },
            {
                "id": "DECAY_FACTOR",
                "label": "Współczynnik wygaszania",
                "type": "text",
                "value": str(get_setting("DECAY_FACTOR", 0.9)).replace(".", ",")
            },
            {
                "id": "RATE_LIMIT_PER_SECOND",
                "label": "Limit pakietów na sekundę",
                "type": "number",
                "value": get_setting("RATE_LIMIT_PER_SECOND", 10)
            },
            {
                "id": "SUSPICIOUS_PATTERNS",
                "label": "Podejrzane wzorce (oddzielone przecinkami)",
                "type": "text",
                "value": ",".join(suspicious_patterns)
            }
        ]
    })


@settings_bp.route('/update_bypass_protection_settings', methods=['POST'])
def update_bypass_protection_settings():
    data = request.get_json() or {}

    # porty -> lista int
    ports = [int(p.strip()) for p in (data.get("BYPASS_PORTS", "")).split(",") if p.strip().isdigit()]

    # wzorce -> lista str (bez pustych)
    patterns = [p.strip() for p in (data.get("SUSPICIOUS_PATTERNS", "")).split(",") if p.strip()]

    # DECAY: obsługa przecinka
    decay_str = str(data.get("DECAY_FACTOR", "0.9")).replace(",", ".")

    # interfejs (np. ens3)
    iface = (data.get("BYPASS_IFACE") or "ens3").strip() or "ens3"

    update_settings({
        "BYPASS_PORTS": ports,
        "BYPASS_IFACE": iface,
        "CHECK_INTERVAL_BYPASS": int(data.get("CHECK_INTERVAL_BYPASS", 10)),
        "THREAT_THRESHOLD": int(data.get("THREAT_THRESHOLD", 100)),
        "SSH_THRESHOLD": int(data.get("SSH_THRESHOLD", 250)),
        "DECAY_FACTOR": float(decay_str),
        "RATE_LIMIT_PER_SECOND": int(data.get("RATE_LIMIT_PER_SECOND", 10)),
        "SUSPICIOUS_PATTERNS": patterns
    })

    return jsonify({"status": "success"})


# -------------------- monitor --------------------

@settings_bp.route('/get_traffic_monitor_settings', methods=['GET'])
def get_traffic_monitor_settings():
    return jsonify({
        "fields": [
            {
                "id": "CHECK_INTERVAL_TRAFFIC",
                "label": "Interwał logowania (sekundy)",
                "type": "number",
                "value": get_setting("CHECK_INTERVAL_TRAFFIC", 10)
            }
        ]
    })


@settings_bp.route('/update_traffic_monitor_settings', methods=['POST'])
def update_traffic_monitor_settings():
    data = request.get_json()
    interval = int(data.get("CHECK_INTERVAL_TRAFFIC"))

    update_settings({
        "CHECK_INTERVAL_TRAFFIC": interval
    })

    return jsonify({"status": "success"})

