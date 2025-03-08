# -*- coding: utf-8 -*-
import threading
import time
import os
from config import CONFIG
from modules.logger import system_logger
from api.app import db, create_default_admin, app

def start_flask_app():
    """Uruchamia API Flask w osobnym wątku."""
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)

def initialize_database():
    """Tworzy bazę danych, jeśli nie istnieje."""
    db_path = os.path.join(app.instance_path, "database.db")

    # Tworzymy folder instance, jeśli nie istnieje
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    with app.app_context():
        print("📂 Sprawdzam bazę danych...")
        db.create_all()
        create_default_admin()
        print("✅ Baza danych i użytkownik admin zostały utworzone.")

if __name__ == "__main__":
    initialize_database()  # Upewniamy się, że baza danych istnieje

    # Uruchamiamy API Flask
    api_thread = threading.Thread(target=start_flask_app, daemon=True)
    api_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 System zatrzymany.")
