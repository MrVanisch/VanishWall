from sklearn.ensemble import IsolationForest
import numpy as np
from modules.AI.ai_database import AIDatabase

WHITELISTED_IPS = {"51.38.135.70"}  # Lista IP, które AI ignoruje

class AIModel:
    def __init__(self):
        """Inicjalizacja modelu AI"""
        self.db = AIDatabase()
        self.model = IsolationForest(n_estimators=100, contamination=0.02)
        self.trained = False  
        self.traffic_data = {}  # Przechowuje dane pakietów

        try:
            data = self.db.get_all_traffic()
            if len(data) >= 50:  # Jeśli mamy wystarczająco dużo danych, AI uczy się od razu
                X = np.array([[int(pkt[1], 2), 1 if pkt[2] == "TCP" else 0] for pkt in data])
                self.model.fit(X)
                self.trained = True
                print("✅ AI przetrenowane na danych bazowych!")
        except Exception as e:
            print(f"⚠️ Brak danych bazowych! AI uczy się od zera. {e}")

    def train(self):
        """Trenuje model na podstawie normalnego ruchu bitowego"""
        if len(self.traffic_data) >= 10:  # AI uczy się dopiero, gdy ma co najmniej 10 IP
            try:
                X_train = np.array([np.mean(data, axis=0) for data in self.traffic_data.values()])
                if X_train.shape[0] > 1:
                    self.model.fit(X_train)  
                    self.trained = True  
                    print("✅ Model AI został przetrenowany!")
                self.traffic_data.clear()
            except Exception as e:
                print(f"❌ Błąd podczas trenowania AI: {e}")

    def predict(self, ip, bit_data, protocol):
        """Wykrywa anomalię na podstawie bitów pakietu"""
        if ip in WHITELISTED_IPS:
            return False  # IP na whiteliście nie są blokowane

        if not self.trained:
            return False  # AI nie podejmuje decyzji, jeśli nie jest gotowe

        try:
            X_test = np.array([[int(bit_data, 2), 1 if protocol == "TCP" else 0]])  # Konwersja bitów na liczby
            prediction = self.model.predict(X_test)

            # AI blokuje IP tylko, jeśli 3 razy z rzędu wykryło anomalię
            if prediction[0] == -1:
                if ip not in self.traffic_data:
                    self.traffic_data[ip] = []
                self.traffic_data[ip].append([int(bit_data, 2), 1 if protocol == "TCP" else 0])

                if len(self.traffic_data[ip]) >= 3:  # AI musi wykryć anomalie 3 razy
                    return True

            return False
        except Exception as e:
            print(f"❌ Błąd w AI predykcji: {e}")
            return False  
