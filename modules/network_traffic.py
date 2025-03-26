from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
from datetime import datetime
import os

from flask_sqlalchemy import SQLAlchemy
from flask import Flask

# === BAZA DANYCH ===

# Utworzenie aplikacji Flask tylko po to, aby SQLAlchemy działało
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chart.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Model danych do wykresu
class NetworkTraffic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    total_tcp = db.Column(db.Integer, nullable=False)
    total_udp = db.Column(db.Integer, nullable=False)
    total_icmp = db.Column(db.Integer, nullable=False)
    total_all = db.Column(db.Integer, nullable=False)

# Tworzymy bazę i tabelę, jeśli jeszcze nie istnieje
with app.app_context():
    if not os.path.exists('chart.db'):
        print("📈 Tworzę bazę danych chart.db...")
    db.create_all()

# === RUCH SIECIOWY ===

# Inicjalizacja danych o ruchu
network_traffic_data = {
    'total_tcp': [0],
    'total_udp': [0],
    'total_icmp': [0],
    'total_all': [0]
}

def log_traffic_to_db(data):
    """Zapisuje dane o ruchu sieciowym do bazy danych"""
    with app.app_context():
        entry = NetworkTraffic(
            timestamp=datetime.utcnow(),
            total_tcp=data['total_tcp'],
            total_udp=data['total_udp'],
            total_icmp=data['total_icmp'],
            total_all=data['total_all']
        )
        db.session.add(entry)
        db.session.commit()
        print(f"✅ Zapisano dane: TCP={entry.total_tcp}, UDP={entry.total_udp}, ICMP={entry.total_icmp}, ALL={entry.total_all}")

def analyze_packet(packet):
    """Analizuje pakiety i zlicza wszystkie protokoły"""
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            network_traffic_data['total_tcp'][-1] += 1
            network_traffic_data['total_all'][-1] += 1
        elif packet.haslayer(UDP):
            network_traffic_data['total_udp'][-1] += 1
            network_traffic_data['total_all'][-1] += 1
        elif packet.haslayer(ICMP):
            network_traffic_data['total_icmp'][-1] += 1
            network_traffic_data['total_all'][-1] += 1

def reset_traffic_data():
    """Resetuje dane o ruchu co 5 sekund i zapisuje do bazy"""
    while True:
        time.sleep(5)

        # Dane do zapisu
        data_to_save = {
            'total_tcp': network_traffic_data['total_tcp'][-1],
            'total_udp': network_traffic_data['total_udp'][-1],
            'total_icmp': network_traffic_data['total_icmp'][-1],
            'total_all': network_traffic_data['total_all'][-1]
        }

        log_traffic_to_db(data_to_save)

        # Reset na nową turę
        network_traffic_data['total_tcp'].append(0)
        network_traffic_data['total_udp'].append(0)
        network_traffic_data['total_icmp'].append(0)
        network_traffic_data['total_all'].append(0)

def start_network_traffic_monitor():
    """Uruchamia sniffing pakietów w tle"""
    sniff(prn=analyze_packet, store=0)

def stop_network_traffic_monitor():
    """Zatrzymuje monitorowanie pakietów"""
    pass  # Można dodać obsługę stopowania sniffera

# === WĄTKI ===

# Uruchamiamy monitorowanie w osobnym wątku
network_traffic_monitor_thread = threading.Thread(target=start_network_traffic_monitor, daemon=True)
network_traffic_monitor_thread.start()

# Uruchomienie wątku resetującego dane
reset_thread = threading.Thread(target=reset_traffic_data, daemon=True)
reset_thread.start()
