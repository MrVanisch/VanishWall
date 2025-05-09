from scapy.all import sniff, IP, TCP, UDP
import time
import logging
import threading
import queue
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger
import importlib
import config

# 🔁 Dynamiczne wczytanie konfiguracji z config.py
def get_bypass_config():
    importlib.reload(config)
    return (
        config.CONFIG.get("BYPASS_PORTS", [80, 443, 53, 22]),
        config.CONFIG.get("CHECK_INTERVAL_BYPASS", 10),
        config.CONFIG.get("THREAT_THRESHOLD", 100),
        config.CONFIG.get("SSH_THRESHOLD", 250),
        config.CONFIG.get("DECAY_FACTOR", 0.9)
    )

acl = ACLManager(block_time=30)
packet_queue = queue.Queue()
threat_scores = {}
stop_event = threading.Event()
WHITELISTED_IPS = {""}  

def calculate_threat(ip, port):
    if ip in WHITELISTED_IPS:
        debug_logger.debug(f"🟢 IP {ip} na białej liście")
        return

    base_score = 5
    if port == 443:
        base_score *= 1.2
    elif port == 22:
        base_score *= 0.5
    elif port == 53:
        base_score *= 2

    threat_scores[ip] = threat_scores.get(ip, 0) + base_score
    debug_logger.debug(f"📈 IP {ip}: +{base_score} (port {port}) => {threat_scores[ip]:.1f}")

def process_bypass_packets():
    while not stop_event.is_set():
        try:
            bypass_ports, *_ = get_bypass_config()
            packet = packet_queue.get(timeout=1)
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                if dst_port in bypass_ports:
                    ip_src = packet[IP].src
                    calculate_threat(ip_src, dst_port)
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            system_logger.error("❌ Błąd w process_bypass_packets", exc_info=True)

def monitor_bypass_traffic():
    while not stop_event.is_set():
        _, interval, general_threshold, ssh_threshold, decay = get_bypass_config()
        time.sleep(interval)

        for ip, score in list(threat_scores.items()):
            threshold = ssh_threshold if score < ssh_threshold else general_threshold

            if score > threshold and not acl.is_blocked(ip):
                msg = f"🛑 Blokowanie IP {ip} (Threat Score: {score:.1f})"
                print(msg)
                system_logger.warning(msg)
                security_logger.warning(f"🚨 Atak typu Bypass Firewall z IP {ip}")
                acl.block_ip(ip, reason="Bypass Firewall Attack")
                debug_logger.debug(f"🔒 IP {ip} zablokowane")

        for ip in list(threat_scores.keys()):
            old_score = threat_scores[ip]
            threat_scores[ip] *= decay
            debug_logger.debug(f"⬇️ IP {ip}: {old_score:.1f} → {threat_scores[ip]:.1f}")

def analyze_bypass_packet(packet):
    packet_queue.put(packet)

def start_bypass_protection():
    print("🛡️ Bypass Protection System uruchomiony...")
    system_logger.info("🛡️ Start ochrony Bypass Protection")
    stop_event.clear()

    threading.Thread(target=process_bypass_packets, daemon=True).start()
    threading.Thread(target=monitor_bypass_traffic, daemon=True).start()

    try:
        sniff(filter="tcp or udp", prn=analyze_bypass_packet, store=False, stop_filter=lambda _: stop_event.is_set())
    except Exception as e:
        system_logger.error("❌ Błąd działania sniffera Bypass", exc_info=True)

def stop_bypass_protection():
    print("🛑 Zatrzymywanie Bypass Protection System...")
    system_logger.info("🛑 Stop ochrony Bypass Protection")
    stop_event.set()
    while not packet_queue.empty():
        packet_queue.get()
        packet_queue.task_done()
    debug_logger.debug("🧹 Kolejka Bypass Protection wyczyszczona")
    print("✅ Bypass Protection zatrzymany.")
