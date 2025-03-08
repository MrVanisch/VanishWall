VanishWall

VanishWall to system ochrony sieci wykorzystujący analizę ruchu oraz mechanizmy blokowania podejrzanych pakietów. Obsługuje wykrywanie ataków SYN Flood, UDP Flood, DNS Amplification oraz analizę anomalii przy użyciu AI.

📌 Funkcje

🔍 Monitorowanie ruchu sieciowego (TCP, UDP, DNS)

🚨 Wykrywanie ataków (SYN Flood, UDP Flood, DNS Amplification)

🤖 AI Traffic Monitor – wykrywanie anomalii w ruchu sieciowym

🔒 Automatyczne blokowanie IP wykrytych atakujących

📝 Logowanie i analiza ruchu

📦 Instalacja

1️⃣ Pobierz repozytorium

git clone https://github.com/twoje-konto/VanishWall.git
cd VanishWall

2️⃣ Stwórz i aktywuj wirtualne środowisko

python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate    # Windows

3️⃣ Zainstaluj wymagane zależności

pip install -r requirements.txt

🚀 Uruchamianie

1️⃣ Konfiguracja (opcjonalnie)

Edytuj config.py, aby dostosować ustawienia (np. czas blokady IP, tryb AI).

2️⃣ Uruchomienie aplikacji

python main.py

3️⃣ Sprawdzenie działania

Aplikacja rozpocznie nasłuchiwanie i monitorowanie ruchu sieciowego.

⚙️ Moduły

ACL – Zarządza listą blokowanych adresów IP.

AI Traffic Monitor – Analizuje ruch i wykrywa anomalie.

SYN Flood Protection – Wykrywa i blokuje ataki SYN Flood.

UDP Flood Protection – Monitoruje ataki UDP Flood.

DNS Amplification Protection – Ochrona przed atakami wzmacniania DNS.

📜 Logi

Aplikacja zapisuje zdarzenia w katalogu logs/. W przypadku problemów sprawdź pliki logów.

🛑 Zatrzymywanie

Aby zatrzymać działanie aplikacji, użyj:

CTRL + C

Jeśli aplikacja działa w tle:

pkill -f main.py  # Linux/macOS
taskkill /IM python.exe /F  # Windows

🛠️ Przydatne komendy

Lista aktywnych modułów:

curl http://localhost:5000/api/modules/status

Blokowanie adresu IP ręcznie:

curl -X POST http://localhost:5000/api/block -d '{"ip": "1.2.3.4"}' -H "Content-Type: application/json"

📌 Wymagania systemowe

Python 3.8+

Linux/macOS/Windows (zalecany Linux)

Uprawnienia administratora (dla przechwytywania pakietów)

📩 Kontakt

Jeśli masz pytania lub pomysły na rozwój projektu, otwórz zgłoszenie na GitHubie!

📢 VanishWall – Twój firewall oparty na AI i analizie ruchu! 🚀
