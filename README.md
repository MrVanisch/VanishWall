# VanishWall

VanishWall is an advanced, open-source network protection system that uses real-time traffic analysis and machine learning to detect and block suspicious activity. This project includes:

- **Attack Detection Modules** (SYN Flood, UDP Flood, DNS Amplification)
- **AI-Based Anomaly Detector** for identifying unusual traffic patterns
- **Web Interface (Flask + REST API)** for monitoring and managing blocked IPs
- **SQLite Blocklist Database** for storing information about blocked addresses
- **Logging System** (logs saved under `logs/`)
- **Configurable Settings** (defined in `config.py`)

Below you will find a comprehensive documentation to help you install, configure, and deploy VanishWall in your infrastructure.

---

## Table of Contents

1. [Project Overview](#project-overview)  
2. [Key Features](#key-features)  
3. [Requirements](#requirements)  
4. [Installation](#installation)  
5. [Configuration](#configuration)  
6. [Running VanishWall](#running-vanishwall)  
7. [Directory Structure](#directory-structure)  
8. [Attack Detection Modules](#attack-detection-modules)  
9. [Web Interface / REST API](#web-interface--rest-api)  
10. [Database and Logs](#database-and-logs)  
11. [Example Usage](#example-usage)  
12. [Tips and Best Practices](#tips-and-best-practices)  
13. [Contributing](#contributing)  
14. [License](#license)  

---

## Project Overview

VanishWall functions as a **next-generation firewall** by:

1. **Monitoring network traffic in real time** using low-level packet capture (e.g., Scapy).
2. **Automatically detecting SYN Flood, UDP Flood, and DNS Amplification attacks** via dedicated modules.
3. **Identifying anomalies** in traffic patterns with the support of an AI-based model.
4. **Blocking suspicious sources** either by manipulating the system firewall (iptables/nftables) or maintaining a local SQLite blocklist.
5. **Providing a simple web interface and REST API** for viewing logs, statistics, and managing blocked IPs.

With VanishWall, you gain an **intelligent guardian** that responds not only to volumetric DDoS attempts but also to subtle anomalies not covered by signature-based methods.

---

## Key Features

- 🔍 **SYN Flood Detection**  
  - Monitors TCP SYN packets and identifies excessive connection attempts.  
- 🌊 **UDP Flood Detection**  
  - Tracks the rate of UDP packets per source IP and flags abnormal spikes.  
- 🌐 **DNS Amplification Detection**  
  - Detects unusually large DNS response packets or high query rates indicative of amplification.  
- 🤖 **AI-Based Anomaly Detection**  
  - Utilizes a machine learning model (e.g., IsolationForest, OneClassSVM) trained on normal traffic patterns to flag deviations.  
- 🛠️ **Dynamic Blocklist**  
  - Stores blocked IP addresses in `blocklist.db` (SQLite) with automatic insertion and removal logic.  
- 📝 **Event Logging**  
  - Records all detected incidents in `logs/` (timestamp, attack type, source IP, etc.).  
- 🌐 **Web Interface & REST API**  
  - Flask-powered dashboard for viewing logs, blocked IPs, and traffic statistics, plus API endpoints for integration.  
- ⚙️ **Flexible Configuration**  
  - All parameters are defined in `config.py` (network interface, detection thresholds, database paths, admin credentials).

---

## Requirements

1. **Operating System**  
   - Linux (recommended: Ubuntu or Debian). Must support raw sockets and firewall rule management (iptables/nftables).  
   - (Optionally) macOS—most components should work but may require additional permissions.  

2. **Python**  
   - **Python 3.8+**  
   - (Strongly recommended) Use a virtual environment (`venv` or `virtualenv`).  

3. **System Privileges**  
   - **Root access** (or equivalent sudo privileges) to capture packets at the raw socket level and modify firewall rules.  

4. **Python Libraries** (listed in `requirements.txt`)  
   - Flask  
   - Scapy (or an equivalent packet-capture library)  
   - SQLAlchemy (or `sqlite3`)  
   - pandas, numpy, scikit-learn (or another ML toolkit)  
   - (Optional) python-dotenv (if environment variables are preferred over editing `config.py`)

   > **Note:** Verify the exact library versions in `requirements.txt` before installing.

---

## Installation

Assuming you have Python 3.8+ installed and root/sudo access, follow these steps:

1. **Clone the repository**  
   ```bash
   git clone https://github.com/MrVanisch/VanishWall.git
   cd VanishWall
2.Create and activate a virtual environment (optional but recommended)
```bash
python3 -m venv venv
source venv/bin/activate
```
3.Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
4.(Optional) Use a .env file
If you prefer not to edit config.py directly, create a .env file in the project root and define necessary variables, for example:
```env
FW_INTERFACE=eth0
ADMIN_USER=admin
ADMIN_PASS=admin123
DETECTION_THRESHOLD_SYN=100
DETECTION_THRESHOLD_UDP=200
DETECTION_THRESHOLD_DNS=50
```
5.Review the configuration
Open config.py and ensure settings match your environment (network interface, database and log paths, detection thresholds, admin credentials).

## Configuration
All configurable parameters are located in config.py. Below is an example snippet with explanations:

```python3
CONFIG = {
    "enable_traffic_monitor": True,
    "enable_bandwidth_limiter": True,
    "enable_syn_flood_protection": True,
    "enable_udp_flood_protection": True,
    "enable_dns_amplification_protection": True,
    "enable_ntp_protection": True,
    "enable_bypass_protection": True,
    "enable_ai_protection": True,
    "BANDWIDTH_LIMIT": 104857600,
    "CHECK_INTERVAL": 10,
    "SYN_LIMIT": 100,
    "CHECK_INTERVAL_SYN": 1,
    "UDP_LIMIT": 200,
    "CHECK_INTERVAL_UDP": 1,
    "NTP_RESPONSE_LIMIT": 50,
    "NTP_SIZE_THRESHOLD": 468,
    "CHECK_INTERVAL_NTP": 10,
    "DNS_RESPONSE_LIMIT": 100,
    "DNS_SIZE_THRESHOLD": 500,
    "CHECK_INTERVAL_DNS": 10,
    "BYPASS_PORTS": [80, 443, 53, 22],
    "CHECK_INTERVAL_BYPASS": 10,
    "THREAT_THRESHOLD": 100,
    "SSH_THRESHOLD": 250,
    "DECAY_FACTOR": 0.9,
    "CHECK_INTERVAL_TRAFFIC": 10,
}
```


