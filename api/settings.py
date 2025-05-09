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
@settings_bp.route('/get_udp_flood_settings', methods=['GET'])
def get_udp_flood_settings():
    return jsonify({
        "title": "Ustawienia: UDP Flood",
        "fields": [
            {
                "id": "limit",
                "label": "Limit UDP (pakiety)",
                "type": "number",
                "value": get_setting("UDP_LIMIT", 200)
            },
            {
                "id": "interval",
                "label": "Interwał sprawdzania (s)",
                "type": "number",
                "value": get_setting("CHECK_INTERVAL_UDP", 10)
            }
        ]
    })

@settings_bp.route('/update_udp_flood_settings', methods=['POST'])
def update_udp_flood_settings():
    data = request.get_json()
    update_settings({
        "UDP_LIMIT": int(data.get("limit")),
        "CHECK_INTERVAL_UDP": int(data.get("interval"))
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

@settings_bp.route('/get_dns_ampl_settings', methods=['GET'])
def get_dns_ampl_settings():
    return jsonify({
        "title": "Ustawienia: DNS Amplification",
        "fields": [
            {"id": "limit", "label": "Limit odpowiedzi DNS (na interwał)", "type": "number", "value": get_setting("DNS_RESPONSE_LIMIT", 100)},
            {"id": "size_threshold", "label": "Minimalny rozmiar pakietu DNS (B)", "type": "number", "value": get_setting("DNS_SIZE_THRESHOLD", 500)},
            {"id": "interval", "label": "Interwał sprawdzania (s)", "type": "number", "value": get_setting("CHECK_INTERVAL_DNS", 10)},
        ]
    })

@settings_bp.route('/update_dns_ampl_settings', methods=['POST'])
def update_dns_ampl_settings():
    data = request.get_json()
    update_settings({
        "DNS_RESPONSE_LIMIT": int(data.get("limit")),
        "DNS_SIZE_THRESHOLD": int(data.get("size_threshold")),
        "CHECK_INTERVAL_DNS": int(data.get("interval"))
    })
    return jsonify({"status": "success"})


# -------------------- BYPASS PROTECTION --------------------

@settings_bp.route('/get_bypass_protection_settings', methods=['GET'])
def get_bypass_protection_settings():
    ports = get_setting("BYPASS_PORTS", [])
    return jsonify({
        "title": "Ustawienia: bypass_protection",
        "fields": [
            {
                "id": "BYPASS_PORTS",
                "label": "Porty podatne (oddzielone przecinkami)",
                "type": "text",
                "value": ",".join(map(str, ports))  # list[int] → str
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
                "type": "number",
                "value": get_setting("DECAY_FACTOR", 0.9)
            }
        ]
    })


@settings_bp.route('/update_bypass_protection_settings', methods=['POST'])
def update_bypass_protection_settings():
    data = request.get_json()

    # porty jako lista int
    ports = [int(p.strip()) for p in data.get("BYPASS_PORTS", "").split(",") if p.strip().isdigit()]

    update_settings({
        "BYPASS_PORTS": ports,
        "CHECK_INTERVAL_BYPASS": int(data.get("CHECK_INTERVAL_BYPASS")),
        "THREAT_THRESHOLD": int(data.get("THREAT_THRESHOLD")),
        "SSH_THRESHOLD": int(data.get("SSH_THRESHOLD")),
        "DECAY_FACTOR": float(data.get("DECAY_FACTOR"))
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