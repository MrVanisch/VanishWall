import sys
import os
import importlib
import threading
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from config import CONFIG
from modules.logger import system_logger
from datetime import datetime, timedelta

# Ustawienie katalogu głównego projektu
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

# Mapowanie modułów do konfiguracji
MODULES_MAP = {
    "traffic_monitor": "enable_traffic_monitor",
    "bandwidth_limiter": "enable_bandwidth_limiter",
    "syn_flood": "enable_syn_flood_protection",
    "udp_flood": "enable_udp_flood_protection",
    "dns_ampl": "enable_dns_amplification_protection",
    "ntp_ampl": "enable_ntp_protection",
    "bypass_protection": "enable_bypass_protection",
    "AI.ai_traffic_monitor": "enable_ai_protection",
}

AVAILABLE_MODULES = {}

# Dynamiczne ładowanie dostępnych modułów
for module_name, config_key in MODULES_MAP.items():
    if CONFIG.get(config_key, False):
        try:
            module_import = importlib.import_module(f"modules.{module_name}")
            start_function = getattr(module_import, f"start_{module_name.split('.')[-1]}", None)
            stop_function = getattr(module_import, f"stop_{module_name.split('.')[-1]}", None)
            restart_function = getattr(module_import, f"restart_{module_name.split('.')[-1]}", None)
            AVAILABLE_MODULES[module_name] = {
                "start": start_function,
                "stop": stop_function,
                "restart": restart_function
            }
        except Exception as e:
            print(f"⚠️ Błąd przy ładowaniu modułu {module_name}: {e}")

print(f"📌 Finalna lista dostępnych modułów: {list(AVAILABLE_MODULES.keys())}")

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  # główna domyślna (login)
app.config["SQLALCHEMY_BINDS"] = {
    "chart": "sqlite:///chart.db"
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True)

class NetworkTraffic(db.Model):
    __bind_key__ = "chart"  # WSKAZANIE że to ma iść do chart.db
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    total_tcp = db.Column(db.Integer, nullable=False)
    total_udp = db.Column(db.Integer, nullable=False)
    total_icmp = db.Column(db.Integer, nullable=False)
    total_all = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField("Nazwa użytkownika", validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField("Hasło", validators=[DataRequired()])
    submit = SubmitField("Zaloguj")

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField("Nowe hasło", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Potwierdź hasło", validators=[DataRequired()])
    submit = SubmitField("Zmień hasło")

running_threads = {}

def create_default_admin():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            hashed_password = bcrypt.generate_password_hash("admin123").decode("utf-8")
            admin_user = User(username="admin", password=hashed_password, must_change_password=True)
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Utworzono domyślnego użytkownika: admin / admin123")

@app.route("/")
@login_required
def index():
    return render_template("index.html", available_modules=AVAILABLE_MODULES.keys())

@app.route("/start_module", methods=["POST"])
@login_required
def start_module():
    module_name = request.json.get("name")
    if module_name in AVAILABLE_MODULES and AVAILABLE_MODULES[module_name]["start"]:
        if module_name in running_threads:
            return jsonify({"status": "error", "message": "Moduł już działa!"}), 400
        system_logger.info(f"Uruchamiam moduł: {module_name}")
        t = threading.Thread(target=AVAILABLE_MODULES[module_name]["start"], daemon=True)
        running_threads[module_name] = t
        t.start()
        return jsonify({"status": "success", "message": f"Uruchomiono {module_name}"})
    return jsonify({"status": "error", "message": "Nieznany moduł lub brak funkcji start!"}), 400

@app.route("/stop_module", methods=["POST"])
@login_required
def stop_module():
    module_name = request.json.get("name")
    if module_name in AVAILABLE_MODULES and AVAILABLE_MODULES[module_name]["stop"]:
        system_logger.info(f"Zatrzymuję moduł: {module_name}")
        AVAILABLE_MODULES[module_name]["stop"]()
        running_threads.pop(module_name, None)
        return jsonify({"status": "success", "message": f"Zatrzymano {module_name}!"})
    return jsonify({"status": "error", "message": "Moduł nie działa lub brak funkcji stop!"}), 400

@app.route("/restart_module", methods=["POST"])
@login_required
def restart_module():
    module_name = request.json.get("name")
    if module_name in AVAILABLE_MODULES and AVAILABLE_MODULES[module_name]["restart"]:
        system_logger.info(f"Restartuję moduł: {module_name}")
        AVAILABLE_MODULES[module_name]["restart"]()
        return jsonify({"status": "success", "message": f"Restart modułu {module_name} zakończony!"})
    return jsonify({"status": "error", "message": "Nieznany moduł lub brak funkcji restart!"}), 400

@app.route("/list_modules", methods=["GET"])
@login_required
def list_modules():
    return jsonify({"active_modules": list(running_threads.keys())})

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if form.new_password.data != form.confirm_password.data:
            flash("❌ Hasła nie pasują do siebie!", "danger")
            return render_template("change_password.html", form=form)

        current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode("utf-8")
        current_user.must_change_password = False
        db.session.commit()
        flash("✅ Hasło zostało zmienione!", "success")
        return redirect(url_for("index"))

    return render_template("change_password.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("✅ Zalogowano!", "success")
            return redirect(url_for("index"))
        else:
            flash("❌ Błędny login lub hasło!", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("✅ Wylogowano!", "info")
    return redirect(url_for("login"))

from modules.network_traffic import network_traffic_data, start_network_traffic_monitor, stop_network_traffic_monitor

# Dodaj do dostępnych modułów
AVAILABLE_MODULES["network_traffic"] = {
    "start": start_network_traffic_monitor,
    "stop": stop_network_traffic_monitor,
    "restart": None
}

@app.route('/api/status', methods=['GET'])
def get_traffic_status():
    """Zwraca dane z ostatnich 2 dni do wykresu"""
    two_days_ago = datetime.utcnow() - timedelta(days=2)
    entries = NetworkTraffic.query.filter(NetworkTraffic.timestamp >= two_days_ago).all()

    return jsonify({
        'labels': [e.timestamp.strftime('%Y-%m-%d %H:%M:%S') for e in entries],
        'tcp_data': [e.total_tcp for e in entries],
        'udp_data': [e.total_udp for e in entries],
        'icmp_data': [e.total_icmp for e in entries],
        'all_data': [e.total_all for e in entries]
    })

@app.route('/status')
def status():
    return render_template('status.html')

if __name__ == "__main__":
    db.create_all()  # domyślna baza
    db.create_all(bind='chart')  # utwórz tabelę dla wykresu
    create_default_admin()
    app.run(host="0.0.0.0", port=5000, debug=True)