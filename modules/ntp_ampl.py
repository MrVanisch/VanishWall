import threading
import time
import queue
from collections import Counter
from scapy.all import sniff, IP, UDP, conf
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger
from config import CONFIG

# ================== USTAWIENIA ==================
FORCE_IFACE = None  # np. "eth0" / "ens3" / "any" ; None = autodetect

# Konfiguracja
NTP_RESPONSE_LIMIT = CONFIG.get("NTP_RESPONSE_LIMIT", 50)
NTP_SIZE_THRESHOLD = CONFIG.get("NTP_SIZE_THRESHOLD", 468)
CHECK_INTERVAL_NTP = CONFIG.get("CHECK_INTERVAL_NTP", 5)

# ================== STAN ==================
acl = ACLManager(block_time=30)

packet_queue = queue.Queue(maxsize=10000)
stop_event = threading.Event()

lock = threading.Lock()            # chroni ntp_counters i top_talkers
ntp_counters = {}                  # src_ip -> liczba "dużych" pakietów w bieżącym oknie
top_talkers = Counter()            # diagnostyka: src_ip -> liczba pakietów (wszystkich)

_seen_lock = threading.Lock()
_seen_pkts_total = 0
_seen_bytes_total = 0
_seen_big_total = 0

# ================== POMOCNICZE ==================
def _pkt_len_bytes(pkt) -> int:
    try:
        ip = pkt.getlayer(IP)
        if ip and getattr(ip, "len", None):
            return int(ip.len)
    except Exception:
        pass
    try:
        return len(bytes(pkt))
    except Exception:
        return 0

def _detect_iface() -> str:
    if FORCE_IFACE:
        return FORCE_IFACE
    try:
        iface = conf.route.route("8.8.8.8")[0]
        if iface:
            return iface
    except Exception:
        pass
    return "any"

# ================== WORKERY ==================
def process_ntp_packets():
    debug_logger.debug("[worker] process_ntp_packets start")
    while not stop_event.is_set():
        try:
            pkt = packet_queue.get(timeout=1)
        except queue.Empty:
            continue

        try:
            if pkt.haslayer(IP) and pkt.haslayer(UDP):
                ip = pkt[IP]; udp = pkt[UDP]
                src = ip.src
                length = _pkt_len_bytes(pkt)

                # globalna telemetria
                global _seen_pkts_total, _seen_bytes_total, _seen_big_total
                with _seen_lock:
                    _seen_pkts_total += 1
                    _seen_bytes_total += length

                # top talkers (wszystkie pakiety)
                with lock:
                    top_talkers[src] += 1

                # detekcja liczy tylko "duże" UDP/123
                if (udp.sport == 123 or udp.dport == 123) and length > NTP_SIZE_THRESHOLD:
                    with lock:
                        ntp_counters[src] = ntp_counters.get(src, 0) + 1
                    with _seen_lock:
                        _seen_big_total += 1

        except Exception:
            system_logger.error("Błąd w process_ntp_packets", exc_info=True)
        finally:
            packet_queue.task_done()

def decision_and_metrics():
    debug_logger.debug("[worker] decision_and_metrics start")
    last_pkts = 0
    last_bytes = 0
    last_big = 0
    window_started = time.monotonic()

    while not stop_event.is_set():
        time.sleep(1.0)

        # ===== METRYKI co sekundę (do debug logów) =====
        with _seen_lock:
            d_pkts  = _seen_pkts_total  - last_pkts
            d_bytes = _seen_bytes_total - last_bytes
            d_big   = _seen_big_total   - last_big
            last_pkts  = _seen_pkts_total
            last_bytes = _seen_bytes_total
            last_big   = _seen_big_total

        pps = d_pkts / 1.0
        bps = d_bytes * 8
        debug_logger.debug(
            "PPS=%.1f, BPS=%d, big_in_1s=%d, queue_len=%d, window=%ds",
            pps, bps, d_big, packet_queue.qsize(), CHECK_INTERVAL_NTP
        )

        # ===== DECYZJA: gdy minęło pełne okno =====
        if time.monotonic() - window_started >= CHECK_INTERVAL_NTP:
            try:
                with lock:
                    snapshot = list(ntp_counters.items())
                    ntp_counters.clear()

                # log diagnostyczny top źródeł w oknie (debug)
                if snapshot:
                    top3 = sorted(snapshot, key=lambda x: x[1], reverse=True)[:3]
                    debug_logger.debug("TOP w oknie (duże NTP): %s", ", ".join(f"{ip}:{cnt}" for ip, cnt in top3))

                # decyzje ACL
                for ip, count in snapshot:
                    already = False
                    try:
                        already = acl.is_blocked(ip)
                    except Exception as e:
                        system_logger.warning("acl.is_blocked(%s) wyjątek: %s", ip, e)

                    if count > NTP_RESPONSE_LIMIT:
                        if not already:
                            msg = (f"Wykryto NTP Amplification: {ip} — "
                                   f"{count} dużych pakietów w {CHECK_INTERVAL_NTP}s (limit>{NTP_RESPONSE_LIMIT})")
                            system_logger.warning(msg)
                            security_logger.warning(msg)
                            try:
                                acl.block_ip(ip, reason="NTP Amplification Attack")
                                system_logger.info("block_ip(%s) wywołane", ip)
                            except Exception:
                                system_logger.error("Błąd block_ip(%s)", ip, exc_info=True)

                # reset timera okna
                window_started = time.monotonic()

            except Exception:
                system_logger.error("Błąd w decision_and_metrics()", exc_info=True)

def sniffer_thread():
    iface = _detect_iface()
    system_logger.info("[sniffer] start — iface='%s', promisc=True, bpf='udp port 123'", iface)
    try:
        sniff(
            filter="udp port 123",
            iface=iface,
            prn=_enqueue_pkt,
            store=False,
            promisc=True,
            stop_filter=lambda _: stop_event.is_set()
        )
    except Exception:
        system_logger.error("Błąd sniffowania UDP/123", exc_info=True)

def _enqueue_pkt(pkt):
    try:
        packet_queue.put(pkt, block=False)
    except queue.Full:
        # tylko log — bez printa
        system_logger.warning("packet_queue pełna — pakiety NTP są zrzucane")

# ================== API ==================
def start_ntp_ampl():
    if stop_event.is_set():
        stop_event.clear()

    # ✅ tylko najważniejszy komunikat na STDOUT
    print("🛡️ Ochrona NTP Amplification AKTYWNA")
    system_logger.info("Ochrona NTP Amplification uruchomiona")

    with lock:
        ntp_counters.clear()
        top_talkers.clear()
    global _seen_pkts_total, _seen_bytes_total, _seen_big_total
    with _seen_lock:
        _seen_pkts_total = 0
        _seen_bytes_total = 0
        _seen_big_total = 0

    threading.Thread(target=process_ntp_packets, daemon=True).start()
    threading.Thread(target=decision_and_metrics, daemon=True).start()
    threading.Thread(target=sniffer_thread, daemon=True).start()

def stop_ntp_ampl():
    # ✅ tylko najważniejszy komunikat na STDOUT
    print("🛑 Zatrzymywanie ochrony NTP Amplification…")
    system_logger.info("Ochrona NTP Amplification zatrzymana")
    stop_event.set()

    # szybkie opróżnianie kolejki (bez printów cząstkowych)
    drained = 0
    try:
        while not packet_queue.empty():
            packet_queue.get_nowait()
            packet_queue.task_done()
            drained += 1
    except Exception:
        pass
    # ✅ lakoniczny status końcowy
    print(f"🧹 Kolejka opróżniona: {drained} elementów")

    with lock:
        ntp_counters.clear()
        top_talkers.clear()

def restart_ntp_ampl():
    # ✅ najważniejszy komunikat na STDOUT
    print("🔄 Restart ochrony NTP Amplification…")
    stop_ntp_ampl()
    time.sleep(1)
    start_ntp_ampl()
    # ✅ potwierdzenie
    print("✅ Restart zakończony")
