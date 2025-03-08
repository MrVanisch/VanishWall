import sqlite3
import os

DB_DIR = "modules/AI/database"
DB_PATH = os.path.join(DB_DIR, "ai_traffic.db")

class AIDatabase:
    def __init__(self):
        if not os.path.exists(DB_DIR):
            os.makedirs(DB_DIR)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        """Tworzy tabelę dla bazy AI"""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                packet_size INTEGER,
                protocol TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                label TEXT DEFAULT 'unknown'
            )
        """)
        self.conn.commit()

    def insert_traffic(self, ip, packet_size, protocol):
        """Dodaje nowy wpis o ruchu sieciowym"""
        self.cursor.execute("""
            INSERT INTO traffic_data (ip, packet_size, protocol)
            VALUES (?, ?, ?)
        """, (ip, packet_size, protocol))
        self.conn.commit()

    def get_all_traffic(self):
        """Pobiera wszystkie dane ruchu"""
        self.cursor.execute("SELECT ip, packet_size, protocol FROM traffic_data")
        return self.cursor.fetchall()

    def label_ip(self, ip, label):
        """Oznaczamy IP jako normalne (safe) lub atakujące (attack)"""
        self.cursor.execute("""
            UPDATE traffic_data SET label = ? WHERE ip = ?
        """, (label, ip))
        self.conn.commit()

    def close(self):
        """Zamyka połączenie z bazą danych"""
        self.conn.close()
