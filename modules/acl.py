import subprocess
import sqlite3
import time
import threading
import os
from modules.logger import system_logger


class ACLManager:
    def __init__(self, block_time=10, max_block_time=300, db_name="blocklist.db", whitelist=None):
        self.default_block_time = block_time
        self.max_block_time = max_block_time
        # Zawsze umieszczaj bazę w folderze instance
        self.db_path = os.path.join("instance", db_name)
        self.whitelist = set(whitelist or {"127.0.0.1", "8.8.8.8", "1.1.1.1"})

        self._setup_database()

    def _setup_database(self):
        # Upewnij się, że folder instance istnieje
        os.makedirs("instance", exist_ok=True)

        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()

        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS acl_rules (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                last_seen REAL,
                fail_count INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0
            )
        """)
        self.conn.commit()

    def block_ip(self, ip, reason="Unknown"):
        if ip in self.whitelist:
            system_logger.info(f"ACL: IP {ip} znajduje się na whiteliście – pomijam.")
            return

        now = time.time()

        self.cursor.execute("SELECT fail_count FROM acl_rules WHERE ip=?", (ip,))
        row = self.cursor.fetchone()

        if row:
            fail_count = row[0] + 1
        else:
            fail_count = 1

        block_time = min(self.default_block_time * fail_count, self.max_block_time)

        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        self.cursor.execute("""
            INSERT INTO acl_rules (ip, reason, last_seen, fail_count, is_blocked)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(ip) DO UPDATE SET
                reason=excluded.reason,
                last_seen=excluded.last_seen,
                fail_count=excluded.fail_count,
                is_blocked=1
        """, (ip, reason, now, fail_count))
        self.conn.commit()

        system_logger.warning(f"ACL: ZABLOKOWANO IP: {ip} (Powód: {reason}) na {block_time}s")
        print(f"ACL: ZABLOKOWANO IP: {ip} (Powód: {reason}) na {block_time}s")

        threading.Timer(block_time, self.unblock_ip, [ip]).start()

    def unblock_ip(self, ip):
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            system_logger.error(f"Błąd odblokowania IP {ip}: {e}")

        # Zamiast usuwać – oznacz jako odblokowane
        self.cursor.execute("UPDATE acl_rules SET is_blocked=0 WHERE ip=?", (ip,))
        self.conn.commit()

        system_logger.info(f"ACL: ODBLOKOWANO IP: {ip}")
        print(f"ACL: ODBLOKOWANO IP: {ip}")

    def is_blocked(self, ip):
        self.cursor.execute("SELECT is_blocked FROM acl_rules WHERE ip=?", (ip,))
        result = self.cursor.fetchone()
        return result and result[0] == 1

    def close(self):
        self.conn.close()