import subprocess
import sqlite3
import time
import threading
from modules.logger import system_logger  # Poprawne logowanie

class ACLManager:
    """Klasa do zarządzania regułami ACL (blokowanie i odblokowywanie IP)."""

    def __init__(self, block_time=10, whitelist=None, db_path="blocklist.db"):
        """
        Inicjalizacja ACL Managera.
        :param block_time: Czas blokady IP w sekundach.
        :param whitelist: Lista IP, które nigdy nie będą blokowane.
        :param db_path: Ścieżka do bazy danych SQLite.
        """
        self.block_time = block_time
        self.whitelist = whitelist if whitelist else {"8.8.8.8", "1.1.1.1"}
        self.db_path = db_path

        # Połączenie z bazą danych
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS acl_rules (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                last_seen TIMESTAMP
            )
        """)
        self.conn.commit()

    def block_ip(self, ip, reason="Unknown"):
        """Blokuje IP w iptables i zapisuje do bazy danych."""
        if ip in self.whitelist:
            system_logger.info(f"ACL: IP {ip} jest na whiteliście - pomijam blokowanie.")
            return

        system_logger.warning(f"ACL: ZABLOKOWANO IP: {ip} (Powód: {reason})")
        print(f"ACL: ZABLOKOWANO IP: {ip} (Powód: {reason})")

        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        self.cursor.execute("INSERT OR REPLACE INTO acl_rules (ip, reason, last_seen) VALUES (?, ?, ?)", 
                            (ip, reason, time.time()))
        self.conn.commit()

        # Zaplanowanie automatycznego odblokowania po upływie block_time
        threading.Timer(self.block_time, self.unblock_ip, [ip]).start()

    def unblock_ip(self, ip):
        """Odblokowuje IP w iptables i usuwa je z bazy danych."""
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        self.cursor.execute("DELETE FROM acl_rules WHERE ip=?", (ip,))
        self.conn.commit()

        system_logger.info(f"ACL: ODBLOKOWANO IP: {ip} po {self.block_time} sekundach")
        print(f"ACL: ODBLOKOWANO IP: {ip} po {self.block_time} sekundach")

    def is_blocked(self, ip):
        """Sprawdza, czy IP jest już zablokowane."""
        self.cursor.execute("SELECT ip FROM acl_rules WHERE ip=?", (ip,))
        return self.cursor.fetchone() is not None

    def close(self):
        """Zamyka połączenie z bazą danych."""
        self.conn.close()
