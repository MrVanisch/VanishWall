from scapy.all import sniff, IP, TCP, UDP, Raw, AsyncSniffer
import time
import threading
import queue
import importlib
import collections
import ipaddress

import config
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger

# ================== CONFIG ==================
def get_bypass_config():
    """Pobierz konfigurację i znormalizuj typy."""
    importlib.reload(config)
    ports = {int(p) for p in config.CONFIG.get("BYPASS_PORTS", [80, 443, 53, 22, 123])}
    return (
        ports,
        int(config.CONFIG.get("CHECK_INTERVAL_BYPASS", 10)),
        float(config.CONFIG.get("THREAT_THRESHOLD", 100)),
        float(config.CONFIG.get("SSH_THRESHOLD", 250)),
        float(config.CONFIG.get("DECAY_FACTOR", 0.9)),
        int(config.CONFIG.get("RATE_LIMIT_PER_SECOND", 10)),
        [s.lower() for s in config.CONFIG.get("SUSPICIOUS_PATTERNS", ["tunnel", "proxy", "bypass"])],
        config.CONFIG.get("BYPASS_IFACE", "ens3"),   # <— domyślnie ens3
    )

def build_bpf(ports: set[int]) -> str:
    """Zbuduj filtr BPF z listy portów (do 1000) albo użyj ogólnego."""
    if not ports or len(ports) > 1000:
        return "tcp or udp"
    plist = " or ".join(str(p) for p in sorted(ports))
    return f"(udp and (port {plist})) or (tcp and (port {plist}))"

# ================== STAN ==================
acl = ACLManager(block_time=30)

packet_queue = queue.Queue(maxsize=10000)
stop_event = threading.Event()
sniffer_handle = None

# globalne struktury
threat_scores: dict[str, float] = {}                         # score per IP
last_update: dict[str, float] = {}                           # ostatni czas pakietu per IP
connection_tracking = {}                                     # ConnectionInfo per IP
rate_limiters: dict[str, collections.deque] = {}             # deque timestampów per IP

WHITELISTED_IPS = {"127.0.0.1", "::1", "localhost"}

ConnectionInfo = collections.namedtuple(
    "ConnectionInfo",
    ["first_seen", "last_seen", "packet_count", "bytes_count", "ports_accessed", "flags_pattern"]
)

# ================== POMOCNICZE ==================
def analyze_payload_patterns(packet, suspicious_patterns):
    """Wykrywanie prostych wzorców w payloadzie (opcjonalny mnożnik)."""
    if not packet.haslayer(Raw):
        return 1.0
    payload = bytes(packet[Raw].load).lower()
    mult = 1.0
    for patt in suspicious_patterns:
        if patt.encode() in payload:
            mult += 0.5
            debug_logger.debug("payload suspicious: %s", patt)
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        if b"connect" in payload or b"tunnel" in payload:
            mult += 1.0
        if b"x-forwarded" in payload or b"x-real-ip" in payload:
            mult += 0.3
    return mult

def check_rate_limit(ip: str, rate_limit: int) -> bool:
    """True gdy IP przekroczyło limit pakietów/s."""
    now = time.time()
    dq = rate_limiters.get(ip)
    if dq is None:
        dq = collections.deque(maxlen=rate_limit)
        rate_limiters[ip] = dq
    while dq and now - dq[0] > 1.0:
        dq.popleft()
    dq.append(now)
    return len(dq) >= rate_limit

def analyze_connection_pattern(ip: str, packet):
    """Analiza zachowania IP (skan portów, nietypowe flagi)."""
    now = time.time()
    info = connection_tracking.get(ip)
    if info is None:
        info = ConnectionInfo(now, now, 0, 0, set(), [])
    size = len(packet)
    dport = int(packet[TCP].dport) if packet.haslayer(TCP) else int(packet[UDP].dport)
    flags = int(packet[TCP].flags) if packet.haslayer(TCP) else 0

    info = ConnectionInfo(
        first_seen=info.first_seen,
        last_seen=now,
        packet_count=info.packet_count + 1,
        bytes_count=info.bytes_count + size,
        ports_accessed=info.ports_accessed | {dport},
        flags_pattern=info.flags_pattern + [flags],
    )
    connection_tracking[ip] = info

    mult = 1.0
    # szybkie skanowanie wielu portów / szeroki wachlarz portów
    if (now - info.first_seen) < 10 and len(info.ports_accessed) > 3:
        mult += 1.2
    if len(info.ports_accessed) > 5:
        mult += 0.8
    # nietypowe flagi TCP
    if packet.haslayer(TCP):
        if (flags & 0x03) == 0x03:   # SYN+FIN
            mult += 1.5
        elif flags == 0:            # NULL scan
            mult += 1.0
    return mult

def calculate_threat(ip: str, port: int, packet, rate_limit: int, suspicious_patterns):
    """Twoja metryka + stabilizacje."""
    if ip in WHITELISTED_IPS or acl.is_blocked(ip):
        return

    base = 5.0
    if port == 443:
        base *= 1.2
    elif port == 22:
        base *= 0.5
    elif port == 53:
        base *= 2.0
    elif port == 80:
        base *= 1.5

    mult = 1.0
    if check_rate_limit(ip, rate_limit):
        mult *= 2.0
    mult *= analyze_connection_pattern(ip, packet)
    mult *= analyze_payload_patterns(packet, suspicious_patterns)

    # bonus za "gęstość" pakietów w krótkim czasie
    now = time.time()
    lu = last_update.get(ip, now - 60)
    if (now - lu) < 5.0:
        mult *= 1.3
    last_update[ip] = now

    inc = base * mult
    threat_scores[ip] = threat_scores.get(ip, 0.0) + inc
    debug_logger.debug("THREAT %s: +%.1f (port %d, mult %.2f) => %.1f", ip, inc, port, mult, threat_scores[ip])

# ================== WORKERY ==================
def process_bypass_packets():
    """Kolejkuje i zlicza tylko porty z konfiguracji (cache + okresowe odświeżenie)."""
    ports, *_ = get_bypass_config()
    last_cfg = time.time()
    while not stop_event.is_set():
        try:
            packet = packet_queue.get(timeout=1)
        except queue.Empty:
            # lekkie odświeżenie konfigu co 5s
            if time.time() - last_cfg > 5:
                ports, *_ = get_bypass_config()
                last_cfg = time.time()
            continue

        try:
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                src_ip = packet[IP].src
                dport = int(packet[TCP].dport) if packet.haslayer(TCP) else int(packet[UDP].dport)
                if dport in ports:
                    _, _, _, _, _, rate_limit, suspicious, _ = get_bypass_config()
                    calculate_threat(src_ip, dport, packet, rate_limit, suspicious)
        except Exception:
            system_logger.error("❌ Błąd w process_bypass_packets", exc_info=True)
        finally:
            packet_queue.task_done()

def monitor_bypass_traffic():
    """Decyzje blokujące + decay."""
    while not stop_event.is_set():
        ports, interval, general_thr, _, decay, *_ = get_bypass_config()
        time.sleep(interval)

        # decyzje
        for ip, score in list(threat_scores.items()):
            threshold = general_thr
            # „recydywa” (jeśli korzystasz z bazki w ACL)
            try:
                if hasattr(acl, "cursor"):
                    acl.cursor.execute("SELECT fail_count FROM acl_rules WHERE ip=?", (ip,))
                    row = acl.cursor.fetchone()
                    if row and row[0] > 3:
                        threshold *= 0.7
            except Exception:
                pass

            if score > threshold and not acl.is_blocked(ip):
                info = connection_tracking.get(ip)
                ports_info = f" (porty: {sorted(info.ports_accessed)})" if info else ""
                msg = f"🛑 Blokowanie IP {ip} (Threat Score: {score:.1f}){ports_info}"
                print(msg)
                system_logger.warning(msg)
                security_logger.warning(f"🚨 Próba bypass z IP {ip} — score={score:.1f}")
                if info:
                    security_logger.info(f"📊 {ip}: pkts={info.packet_count}, ports={len(info.ports_accessed)}, bytes={info.bytes_count}")
                try:
                    acl.block_ip(ip, reason=f"Bypass Firewall Attack (Score {score:.1f})")
                finally:
                    threat_scores[ip] = 0.0
                    connection_tracking.pop(ip, None)
                    rate_limiters.pop(ip, None)
                    last_update.pop(ip, None)

        # decay i cleanup
        now = time.time()
        for ip in list(threat_scores.keys()):
            before = threat_scores[ip]
            threat_scores[ip] = before * decay
            if threat_scores[ip] < 1.0:
                threat_scores.pop(ip, None)
                info = connection_tracking.get(ip)
                if info and (now - info.last_seen) > 300:
                    connection_tracking.pop(ip, None)
            else:
                debug_logger.debug("⬇️ %s: %.1f → %.1f", ip, before, threat_scores[ip])

        # czyść stare ratelimity (>60s bez aktywności)
        for ip, dq in list(rate_limiters.items()):
            if dq and (now - dq[-1]) > 60:
                rate_limiters.pop(ip, None)

# ================== SNIFFER ==================
def analyze_bypass_packet(packet):
    if not stop_event.is_set():
        try:
            packet_queue.put_nowait(packet)
        except queue.Full:
            debug_logger.warning("⚠️ Kolejka pełna — porzucam pakiet")

def start_bypass_protection():
    print("🛡️ Ochrona bypass uruchomiona")
    ports, _, _, _, _, _, _, iface = get_bypass_config()
    bpf = build_bpf(ports)
    system_logger.info("Start bypass: iface='%s', bpf='%s', ports=%s", iface, bpf, sorted(ports))
    stop_event.clear()

    threading.Thread(target=process_bypass_packets, daemon=True).start()
    threading.Thread(target=monitor_bypass_traffic, daemon=True).start()

    global sniffer_handle
    try:
        sniffer_handle = AsyncSniffer(filter=bpf, prn=analyze_bypass_packet, store=False, iface=iface)
        sniffer_handle.start()
        print(f"🔍 Nasłuchiwanie pakietów: iface={iface}, bpf={bpf}")
    except Exception as e:
        system_logger.error("❌ Błąd sniffowania: %s", e, exc_info=True)
        print(f"❌ Błąd sniffowania: {e}")

def stop_bypass_protection():
    print("🛑 Zatrzymywanie ochrony bypass…")
    system_logger.info("Stop bypass")
    stop_event.set()

    global sniffer_handle
    if sniffer_handle:
        try:
            sniffer_handle.stop()
        except Exception:
            pass
        sniffer_handle = None

    while not packet_queue.empty():
        try:
            packet_queue.get_nowait(); packet_queue.task_done()
        except queue.Empty:
            break
    print("✅ Ochrona bypass zatrzymana")

# ================== DIAG ==================
def get_threat_statistics():
    return {
        "active_threats": len(threat_scores),
        "tracked_connections": len(connection_tracking),
        "rate_limiters": len(rate_limiters),
        "queue_size": packet_queue.qsize(),
        "top_threats": dict(sorted(threat_scores.items(), key=lambda x: x[1], reverse=True)[:10]),
    }

def print_statistics():
    s = get_threat_statistics()
    print("\n📊 Statystyki systemu ochrony:")
    print(f"   Aktywne zagrożenia: {s['active_threats']}")
    print(f"   Śledzone połączenia: {s['tracked_connections']}")
    print(f"   Kolejka pakietów: {s['queue_size']}")
    if s["top_threats"]:
        print("   Top zagrożenia:")
        for ip, score in list(s["top_threats"].items())[:5]:
            print(f"     {ip}: {score:.1f}")
