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
from flask import abort
from wtforms import SelectField  # dodaj do importów jeśli jeszcze nie ma
from functools import wraps
from flask import send_file
from api.settings import settings_bp

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
    role = db.Column(db.String(50), default='user')  # <--- NEW

class CreateUserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    role = SelectField(
        "Role",
        choices=[("user", "User"), ("admin", "Administrator"), ("moderator", "Moderator")],
        default="user"
    )
    submit = SubmitField("Create User")

class EditUserForm(FlaskForm):
    password = PasswordField("New Password", validators=[Length(min=6)])
    role = SelectField(
        "Role",
        choices=[("user", "User"), ("admin", "Administrator"), ("moderator", "Moderator")],
        default="user"
    )
    submit = SubmitField("Save Changes")

#role 

def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                # Obsługa AJAX/fetch – zwracamy JSON
                if request.accept_mimetypes.accept_json:
                    return jsonify({"status": "error", "message": "You do not have permission to perform this action."}), 403
                # Dla zwykłej przeglądarki – klasyczne 403
                return abort(403)
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


@app.route("/admin/users")
@login_required
def user_list():
    if current_user.role != 'admin':
        return abort(403)
    users = User.query.all()
    return render_template("admin/user_list.html", users=users)

@app.route("/admin/users/create", methods=["GET", "POST"])
@login_required
def create_user():
    if current_user.role != 'admin':
        return abort(403)
    form = CreateUserForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        new_user = User(username=form.username.data, password=hashed_pw, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash("✅ Użytkownik utworzony!", "success")
        return redirect(url_for("user_list"))
    return render_template("admin/create_user.html", form=form)

@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return abort(403)
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)
    if form.validate_on_submit():
        if form.password.data:
            user.password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user.role = form.role.data
        db.session.commit()
        flash("✅ Zmieniono dane użytkownika!", "success")
        return redirect(url_for("user_list"))
    return render_template("admin/edit_user.html", form=form, user=user)

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return abort(403)
    user = User.query.get_or_404(user_id)
    if user.username == "admin":
        flash("❌ Nie można usunąć konta admina!", "danger")
        return redirect(url_for("user_list"))
    db.session.delete(user)
    db.session.commit()
    flash("🗑️ Użytkownik usunięty", "info")
    return redirect(url_for("user_list"))


class NetworkTraffic(db.Model):
    __bind_key__ = "chart"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    total_tcp = db.Column(db.Integer, nullable=False)
    total_udp = db.Column(db.Integer, nullable=False)
    total_icmp = db.Column(db.Integer, nullable=False)
    total_all = db.Column(db.Integer, nullable=False)
    sent_packets = db.Column(db.Integer, nullable=False, default=0)
    received_packets = db.Column(db.Integer, nullable=False, default=0)


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
            admin_user = User(
                username="admin",
                password=hashed_password,
                must_change_password=True,
                role="admin"  # <- TO USTAWIA UPRAWNIENIA
            )
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Utworzono domyślnego użytkownika: admin / admin123")

@app.route("/")
@login_required
def index():
    return render_template("index.html", available_modules=AVAILABLE_MODULES.keys())

@app.route("/start_module", methods=["POST"])
@role_required("admin", "moderator")
def start_module():
    module_name = request.json.get("name")
    if module_name in AVAILABLE_MODULES and AVAILABLE_MODULES[module_name]["start"]:
        if module_name in running_threads:
            return jsonify({"status": "error", "message": "Moduł już działa!"}), 400
        
        # LOGOWANIE MODERATORA
        if current_user.role == "moderator":
            system_logger.warning(f"[MODERATOR] {current_user.username} started module: {module_name}")
        else:
            system_logger.info(f"[ADMIN] {current_user.username} started module: {module_name}")

        t = threading.Thread(target=AVAILABLE_MODULES[module_name]["start"], daemon=True)
        running_threads[module_name] = t
        t.start()
        return jsonify({"status": "success", "message": f"Uruchomiono {module_name}"})
    return jsonify({"status": "error", "message": "Nieznany moduł lub brak funkcji start!"}), 400


@app.route("/stop_module", methods=["POST"])
@role_required("admin", "moderator")
def stop_module():
    module_name = request.json.get("name")
    if module_name in AVAILABLE_MODULES and AVAILABLE_MODULES[module_name]["stop"]:
        if current_user.role == "moderator":
            system_logger.warning(f"[MODERATOR] {current_user.username} stopped module: {module_name}")
        else:
            system_logger.info(f"[ADMIN] {current_user.username} stopped module: {module_name}")
        AVAILABLE_MODULES[module_name]["stop"]()
        running_threads.pop(module_name, None)
        return jsonify({"status": "success", "message": f"Zatrzymano {module_name}!"})
    return jsonify({"status": "error", "message": "Moduł nie działa lub brak funkcji stop!"}), 400


@app.route("/restart_module", methods=["POST"])
@role_required("admin", "moderator")
def restart_module():
    module_name = request.json.get("name")
    if module_name in AVAILABLE_MODULES and AVAILABLE_MODULES[module_name]["restart"]:
        if current_user.role == "moderator":
            system_logger.warning(f"[MODERATOR] {current_user.username} restarted module: {module_name}")
        else:
            system_logger.info(f"[ADMIN] {current_user.username} restarted module: {module_name}")
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
    flash(" Wylogowano!", "info")
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
    range_minutes = request.args.get("range", type=int)

    if range_minutes:
        time_threshold = datetime.utcnow() - timedelta(minutes=range_minutes)
    else:
        time_threshold = datetime.utcnow() - timedelta(days=2)

    entries = NetworkTraffic.query.filter(NetworkTraffic.timestamp >= time_threshold).all()

    return jsonify({
        'labels':   [(e.timestamp + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S') for e in entries],
        'tcp_data': [e.total_tcp for e in entries],
        'udp_data': [e.total_udp for e in entries],
        'icmp_data': [e.total_icmp for e in entries],
        'all_data': [e.total_all for e in entries],
        'sent_data': [e.sent_packets for e in entries],
        'received_data': [e.received_packets for e in entries],

        # ⬇️⬇️⬇️ TO DODAJ:
        'ratio_data': [
            (e.sent_packets / e.received_packets) if e.received_packets > 0 else 0
            for e in entries
        ]
    })

@app.route('/status')
def status():
    return render_template('status.html')

LOG_DIR = os.path.join(BASE_DIR, "logs")

LOG_FILES = {
    "system": os.path.join(LOG_DIR, "system.log"),
    "traffic": os.path.join(LOG_DIR, "traffic.log"),
    "security": os.path.join(LOG_DIR, "security.log"),
    "debug": os.path.join(LOG_DIR, "debug.log")
}


@app.route("/api/logs/<log_type>")
@role_required("admin", "moderator")
@login_required
def get_log_content(log_type):
    path = LOG_FILES.get(log_type)
    if not path or not os.path.exists(path):
        return abort(404, "Nie znaleziono logu.")
    
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-500:]  # ostatnie 500 linii
    return jsonify(lines)

@app.route("/download/log/<log_type>")
@role_required("admin", "moderator")
@login_required
def download_log_file(log_type):
    path = LOG_FILES.get(log_type)
    if not path or not os.path.exists(path):
        return abort(404)
    return send_file(path, as_attachment=True)

@app.route("/logs")
@role_required("admin", "moderator")
@login_required
def logs():
    return render_template("logs.html")

#api do procesora i do ramu 
import psutil

@app.route("/api/system_status")
@login_required
def system_status():
    memory = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=0.5)
    
    return jsonify({
        "cpu": cpu,
        "memory": memory.percent
    })

from api.settings import settings_bp
app.register_blueprint(settings_bp)


if __name__ == "__main__":
    db.create_all()  # domyślna baza
    db.create_all(bind='chart')  # utwórz tabelę dla wykresu
    create_default_admin()
    app.run(host="0.0.0.0", port=5000, debug=True)