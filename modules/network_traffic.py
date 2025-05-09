from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.all import conf
import threading
import time
from datetime import datetime
import os

from api.app import app, db, NetworkTraffic


# === RUCH SIECIOWY ===

network_traffic_data = {
    'total_tcp': [0],
    'total_udp': [0],
    'total_icmp': [0],
    'total_all': [0],
    'sent': [0],
    'received': [0]
}

def log_traffic_to_db(data):
    """Zapisuje dane o ruchu sieciowym do bazy danych"""
    with app.app_context():
        entry = NetworkTraffic(
            timestamp=datetime.utcnow(),
            total_tcp=data['total_tcp'],
            total_udp=data['total_udp'],
            total_icmp=data['total_icmp'],
            total_all=data['total_all'],
            sent_packets=data['sent_packets'],
            received_packets=data['received_packets']
        )
        db.session.add(entry)
        db.session.commit()
        #print(f"✅ Zapisano dane: TCP={entry.total_tcp}, UDP={entry.total_udp}, ICMP={entry.total_icmp}, ALL={entry.total_all}")

def analyze_packet(packet):
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            network_traffic_data['total_tcp'][-1] += 1
        elif packet.haslayer(UDP):
            network_traffic_data['total_udp'][-1] += 1
        elif packet.haslayer(ICMP):
            network_traffic_data['total_icmp'][-1] += 1

        network_traffic_data['total_all'][-1] += 1

        if packet[IP].src == conf.iface.ip:
            network_traffic_data['sent'][-1] += 1
        else:
            network_traffic_data['received'][-1] += 1

def reset_traffic_data():
    """Resetuje dane o ruchu co 5 sekund i zapisuje do bazy"""
    while True:
        time.sleep(5)

        data_to_save = {
            'total_tcp': network_traffic_data['total_tcp'][-1],
            'total_udp': network_traffic_data['total_udp'][-1],
            'total_icmp': network_traffic_data['total_icmp'][-1],
            'total_all': network_traffic_data['total_all'][-1],
            'sent_packets': network_traffic_data['sent'][-1],
            'received_packets': network_traffic_data['received'][-1],
        }

        log_traffic_to_db(data_to_save)

        # Reset
        for key in network_traffic_data:
            network_traffic_data[key].append(0)

def start_network_traffic_monitor():
    sniff(prn=analyze_packet, store=0)

def stop_network_traffic_monitor():
    pass

# === WĄTKI ===

network_traffic_monitor_thread = threading.Thread(target=start_network_traffic_monitor, daemon=True)
network_traffic_monitor_thread.start()

reset_thread = threading.Thread(target=reset_traffic_data, daemon=True)
reset_thread.start()