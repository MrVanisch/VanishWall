import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff, IP, UDP, DNS
import time
import threading
import queue
from collections import defaultdict, deque
from datetime import datetime, timedelta
from modules.acl import ACLManager
from modules.logger import system_logger, security_logger, debug_logger
import importlib
import config

def get_dns_config():
    importlib.reload(config)
    return (
        config.CONFIG.get("DNS_RESPONSE_LIMIT", 10),      # Bardzo niski na test
        config.CONFIG.get("DNS_SIZE_THRESHOLD", 200),     # Niski próg
        config.CONFIG.get("CHECK_INTERVAL_DNS", 2),       # Częste sprawdzanie
        config.CONFIG.get("DNS_RATE_LIMIT", 5),           # Bardzo niski limit
        config.CONFIG.get("DNS_RATIO_THRESHOLD", 2.0),    # Niski próg amplifikacji
        config.CONFIG.get("TIME_WINDOW", 30)              # Krótkie okno
    )

acl = ACLManager(block_time=10, max_block_time=600)
packet_queue = queue.Queue(maxsize=10000)
stop_event = threading.Event()

# Liczniki dla debugowania
packet_count = 0
dns_query_count = 0
dns_response_count = 0
large_response_count = 0

class DNSTracker:
    def __init__(self):
        self.queries = defaultdict(lambda: deque())
        self.responses = defaultdict(lambda: deque())
        self.query_types = defaultdict(lambda: defaultdict(int))
        self.response_sizes = defaultdict(list)

    def add_query(self, ip, timestamp, qtype, qname):
        self.queries[ip].append(timestamp)
        self.query_types[ip][qtype] += 1
        print(f"🔍 QUERY: {ip} -> {qname} ({qtype})")
        
        _, _, _, _, _, time_window = get_dns_config()
        cutoff = timestamp - time_window
        while self.queries[ip] and self.queries[ip][0] < cutoff:
            self.queries[ip].popleft()

    def add_response(self, ip, timestamp, size):
        self.responses[ip].append((timestamp, size))
        self.response_sizes[ip].append(size)
        print(f"📦 RESPONSE: {ip} -> {size}B")
        
        _, _, _, _, _, time_window = get_dns_config()
        cutoff = timestamp - time_window
        while (self.responses[ip] and 
               self.responses[ip][0][0] < cutoff):
            self.responses[ip].popleft()

    def get_stats(self, ip):
        query_count = len(self.queries[ip])
        response_count = len(self.responses[ip])
        avg_size = sum(self.response_sizes[ip][-10:]) / min(10, len(self.response_sizes[ip])) if self.response_sizes[ip] else 0
        return query_count, response_count, avg_size

dns_tracker = DNSTracker()

def process_dns_packets():
    global packet_count, dns_query_count, dns_response_count, large_response_count
    
    while not stop_event.is_set():
        try:
            _, size_threshold, _, _, _, _ = get_dns_config()
            packet = packet_queue.get(timeout=1)
            packet_count += 1
            current_time = time.time()

            if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS)):
                continue

            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            dns_layer = packet[DNS]
            pkt_len = len(packet)

            print(f"📡 Pakiet DNS: {ip_src} -> {ip_dst}, rozmiar: {pkt_len}B, QR={dns_layer.qr}")

            # Zapytania DNS (QR=0) - śledzenie ATAKUJĄCEGO
            if dns_layer.qr == 0 and packet[UDP].dport == 53:
                dns_query_count += 1
                try:
                    qname = str(dns_layer.qd.qname.decode('utf-8', errors='ignore')) if dns_layer.qd else ""
                    qtype = dns_layer.qd.qtype if dns_layer.qd else 0
                    qtype_name = DNS.qtypes.get(qtype, str(qtype))
                except:
                    qname = "unknown"
                    qtype_name = "unknown"
                
                
                dns_tracker.add_query(ip_src, current_time, qtype_name, qname)
                print(f"🔍 QUERY: ATAKUJĄCY {ip_src} -> serwer {ip_dst}, zapytanie o {qname} ({qtype_name})")

            # Odpowiedzi DNS (QR=1) - śledzenie ODPOWIEDZI do ATAKUJĄCEGO
            elif dns_layer.qr == 1 and packet[UDP].sport == 53:
                dns_response_count += 1
                
                
                # Śledzimy ODPOWIEDZI wysyłane DO atakującego (ip_dst)
                dns_tracker.add_response(ip_dst, current_time, pkt_len)  # ZMIANA: ip_dst zamiast ip_src
                
                if pkt_len > size_threshold:
                    large_response_count += 1
                    print(f"📦 DUŻA ODPOWIEDŹ: serwer {ip_src} -> ATAKUJĄCY {ip_dst} ({pkt_len}B) ⚠️")
                
                print(f"📤 RESPONSE: serwer {ip_src} -> ATAKUJĄCY {ip_dst} ({pkt_len}B)")

            packet_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            print(f"❌ Błąd parsowania: {e}")

def monitor_dns_traffic():
    while not stop_event.is_set():
        response_limit, size_threshold, interval, rate_limit, ratio_threshold, time_window = get_dns_config()
        time.sleep(interval)

#        print(f"\n🔍 ANALIZA DNS (co {interval}s):")
#        print(f"   Pakiety ogółem: {packet_count}")
#        print(f"   Zapytania DNS: {dns_query_count}")
#        print(f"   Odpowiedzi DNS: {dns_response_count}")
#        print(f"   Duże odpowiedzi: {large_response_count}")
#        print(f"   Monitorowane ATAKUJĄCE IP: {len(dns_tracker.queries)}")
#        print(f"   IP otrzymujące odpowiedzi: {len(dns_tracker.responses)}")

        threats_found = 0
        
        # Sprawdź IP które OTRZYMUJĄ dużo odpowiedzi (potencjalni atakujący)
        for ip in list(dns_tracker.responses.keys()):
            query_count, response_count, avg_size = dns_tracker.get_stats(ip)
            
            print(f"   📊 POTENCJALNY ATAKUJĄCY {ip}: wysłał {query_count} zapytań, otrzymał {response_count} odpowiedzi, śr.rozm: {avg_size:.0f}B")
            
            # Test 1: Za dużo dużych odpowiedzi OTRZYMANYCH
            large_responses = sum(1 for _, size in dns_tracker.responses[ip] if size > size_threshold)
            if large_responses > response_limit:
                threats_found += 1
                print(f"   🚨 THREAT 1: ATAKUJĄCY {ip} otrzymał {large_responses} dużych odpowiedzi (limit: {response_limit})")
                block_ip_with_reason(ip, f"DNS Amplification: received {large_responses} large responses")
                continue
            
            # Test 2: Wysoka częstotliwość OTRZYMANYCH odpowiedzi
            if response_count > rate_limit * (time_window / interval):
                threats_found += 1
                print(f"   🚨 THREAT 2: ATAKUJĄCY {ip} otrzymuje {response_count} odpowiedzi (limit: {rate_limit * (time_window / interval)})")
                block_ip_with_reason(ip, f"DNS High Rate: received {response_count} responses")
                continue
            
            # Test 3: Duży średni rozmiar OTRZYMANYCH odpowiedzi
            if avg_size > size_threshold * ratio_threshold:
                threats_found += 1
                print(f"   🚨 THREAT 3: ATAKUJĄCY {ip} otrzymuje średnio {avg_size:.0f}B na odpowiedź (próg: {size_threshold * ratio_threshold})")
                block_ip_with_reason(ip, f"DNS Large Responses: avg received {avg_size:.0f}B")

        if threats_found == 0:
            print("   ✅ Brak wykrytych zagrożeń")
        else:
            print(f"   🛑 Wykryto {threats_found} zagrożeń!")

def block_ip_with_reason(ip, reason):
    if not acl.is_blocked(ip):
        print(f"🛑 BLOKUJĘ IP: {ip} - {reason}")
        system_logger.warning(f"🛑 DNS Attack blocked: {ip} - {reason}")
        security_logger.critical(f"🚨 BLOCKED: {ip} - {reason}")
        acl.block_ip(ip, reason=reason)
    else:
        print(f"🔁 IP {ip} już zablokowane")

def analyze_dns_packet(packet):
    if not stop_event.is_set():
        try:
            packet_queue.put_nowait(packet)
        except queue.Full:
            print("⚠️ Kolejka pełna - możliwy intensywny atak!")

def start_dns_ampl():
    print("🛡️ Start DEBUG DNS Protection...")
    print(f"Konfiguracja: response_limit={get_dns_config()[0]}, size_threshold={get_dns_config()[1]}")
    
    stop_event.clear()
    
    threading.Thread(target=process_dns_packets, daemon=True).start()
    threading.Thread(target=monitor_dns_traffic, daemon=True).start()

    try:
        print("🎯 Przechwytywanie ruchu DNS na porcie 53...")
        sniff(filter="udp and port 53", 
              prn=analyze_dns_packet, 
              store=False,
              stop_filter=lambda _: stop_event.is_set())
    except Exception as e:
        print(f"❌ Błąd sniffera: {e}")

def stop_dns_ampl():
    print("🛑 Zatrzymywanie DEBUG DNS Protection...")
    stop_event.set()
    
    with packet_queue.mutex:
        packet_queue.queue.clear()
    
    dns_tracker.queries.clear()
    dns_tracker.responses.clear()
    print("🧹 Wyczyszczono struktury DNS")

# Funkcja testowa
def print_current_stats():
    print(f"\n📊 CURRENT STATS:")
    print(f"   Packets: {packet_count}")
    print(f"   Queries: {dns_query_count}")
    print(f"   Responses: {dns_response_count}")
    print(f"   Large responses: {large_response_count}")
    for ip, responses in dns_tracker.responses.items():
        if responses:
            avg_size = sum(size for _, size in responses) / len(responses)
            print(f"   IP {ip}: {len(responses)} responses, avg {avg_size:.0f}B")