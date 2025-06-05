# 🧱 VanishWall — Intelligent Network Firewall

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)

> 🚨 A modern Python-based firewall with real-time traffic analysis, DDoS detection, and anomaly detection using AI.

---

## 🧠 About

**VanishWall** is a network protection system designed to:
- 📊 Monitor and analyze live network traffic
- 🛡️ Detect and block attacks like **SYN Flood**, **UDP Flood**, and **DNS Amplification**
- 🤖 Leverage artificial intelligence to identify anomalies
- 🌐 Provide a simple and secure web interface
- 🧾 Store blocked IP addresses in a local SQLite database

---

## 🚀 Getting Started

### 📥 Clone the Repository

```bash
git clone https://github.com/MrVanisch/VanishWall.git
cd VanishWall
```
📦 Install Requirements
Ensure you're using Python 3.10 or newer:
```bash
pip install -r requirements.txt
```
▶️ Launch the App
```bash
python main.py
```
Once launched, access it in your browser at:
🌐 http://localhost:5000
```
## 🔐 Default Login

| Username | Password |
|----------|----------|
| admin    | admin1   |
```
⚠️ It's strongly recommended to change your credentials immediately after first login.

---
## 🧩 Project Structure
```
VanishWall/
├── api/ # REST API endpoints (Flask)
├── modules/ # Attack detection logic (SYN, UDP, DNS, AI)
├── instance/ # Environment-specific configurations
├── logs/ # Logging system
├── config.py # Main configuration
├── main.py # Entry point
├── blocklist.db # SQLite DB for blocked IPs
└── requirements.txt # Python dependencies
```
---

## 🛡️ Features

✅ **DDoS Attack Detection:**
- SYN Flood  
- UDP Flood  
- DNS Amplification  

✅ IP Auto-blocking System  
✅ AI-Powered Anomaly Detection  
✅ Built-in Web Interface  
✅ Real-time Logging & Monitoring  
✅ SQLite Support for IP Management  

---

## 🔮 Planned Features

- 🔐 Admin password management interface  
- 📊 Real-time traffic visualization  
- ☁️ Threat Intelligence feed integration  
- 📡 Port and service monitoring  

---

## 📜 License

This project is licensed under the **Apache 2.0 License**.  
See the [LICENSE](LICENSE) file for full details.

---

## 👤 Author

Developed with 🧠 and 💻 by **MrVanisch**  
Cybersecurity enthusiast & software developer

---

## 🙌 Contribute & Support

If you like the project:

- ⭐ Star the repo  
- 🐛 Report bugs or issues  
- 🤝 Submit a pull request  
- 💬 For questions, feedback or ideas — open an issue or get in touch!
