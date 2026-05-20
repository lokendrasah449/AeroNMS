# ✈️ AeroNMS — Network Management System

<div align="center">

![AeroNMS](https://img.shields.io/badge/AeroNMS-v1.5-00aaff?style=for-the-badge&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Deploy](https://img.shields.io/badge/Deployed-Railway-0B0D0E?style=for-the-badge&logo=railway&logoColor=white)

### 🌐 [Live Demo](https://aeronms-production.up.railway.app) &nbsp;|&nbsp; 📖 [Documentation](#setup) &nbsp;|&nbsp; 🐛 [Report Bug](https://github.com/lokendrasah449/AeroNMS/issues)

<br>

[![Live Demo](https://img.shields.io/badge/➡️%20Open%20Live%20Demo-aeronms--production.up.railway.app-00aaff?style=for-the-badge)](https://aeronms-production.up.railway.app)

> Login with `admin` / `aero2024`

<br>

A lightweight, production-quality open-source Network Management System  
designed for **Buddha Air Nepal** to monitor network devices across airport locations.

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📊 **Dashboard** | Real-time overview — total, online, offline devices + health bar |
| 🖥️ **Device Inventory** | Add, edit, delete, search devices with full details |
| 📡 **Live Monitor** | Concurrent ping all devices simultaneously — results stream live |
| 🗺️ **Topology Map** | Interactive canvas network diagram — drag, click, filter |
| 📈 **Device Detail** | Latency history chart, uptime %, status timeline per device |
| 📻 **SNMP Polling** | Poll devices for system info, uptime, interfaces |
| 💾 **Config Backup** | Generate and download device config backups |
| 📧 **Email Alerts** | Auto-send HTML email when device goes DOWN |
| 📥 **CSV Export** | Export full device inventory to CSV |
| 🌗 **Light/Dark Mode** | Toggle theme — persists across sessions |
| 🔐 **Authentication** | Session-based login — admin and NOC roles |

---

## 🚀 Live Demo

<div align="center">

### **[https://aeronms-production.up.railway.app](https://aeronms-production.up.railway.app)**

| Credential | Value |
|------------|-------|
| Username | `admin` |
| Password | `aero2024` |

</div>

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI (Python 3.11) |
| **Database** | SQLite via SQLAlchemy |
| **Frontend** | Bootstrap 5 + Jinja2 Templates |
| **Monitoring** | Linux `ping` via subprocess + asyncio |
| **Streaming** | Server-Sent Events (SSE) |
| **Deployment** | Railway |
| **Fonts** | Exo 2 + Share Tech Mono |

---

## 📁 Project Structure

```
aeronms/
├── main.py              # FastAPI app — all routes
├── database.py          # SQLite/SQLAlchemy setup
├── models.py            # Device + PingHistory models
├── crud.py              # Database operations
├── monitor.py           # Ping, SNMP, backup, email alerts
├── seed.py              # Demo data — 20 airline devices
├── requirements.txt     # Python dependencies
├── Procfile             # Railway deployment config
├── runtime.txt          # Python version for deployment
│
├── templates/           # Jinja2 HTML templates
│   ├── base.html        # Layout: sidebar, topbar, theme toggle
│   ├── login.html       # Login page
│   ├── dashboard.html   # Main dashboard
│   ├── devices.html     # Device inventory + search
│   ├── device_form.html # Add/edit device form
│   ├── device_detail.html # Detail + latency chart + timeline
│   ├── monitor.html     # Live ping monitor with SSE stream
│   ├── topology.html    # Network topology map
│   ├── snmp.html        # SNMP polling
│   ├── backup.html      # Config backup manager
│   └── alerts.html      # Email alert configuration
│
└── static/
    ├── css/aero.css     # Dark/light NOC theme
    └── js/aero.js       # Clock, theme toggle, sidebar
```

---

<a name="setup"></a>
## ⚙️ Local Setup

### Requirements
- Linux (Ubuntu / Kali / Debian)
- Python 3.11+
- Terminal

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/lokendrasah449/AeroNMS.git
cd AeroNMS

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Seed demo data (20 airline devices)
python3 seed.py

# 5. Run the server
venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Open in Browser
```
http://localhost:8000
```

| Username | Password | Role |
|----------|----------|------|
| `admin` | `aero2024` | Administrator |
| `noc` | `buddha@noc` | NOC Engineer |

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard |
| GET | `/devices` | Device list |
| GET | `/devices/detail/{id}` | Device detail + chart |
| GET | `/monitor` | Live monitor |
| GET | `/api/monitor/stream` | SSE live ping stream |
| GET | `/topology` | Topology map |
| GET | `/api/topology` | Topology JSON data |
| GET | `/api/snmp/{id}` | SNMP poll device |
| GET | `/devices/export/csv` | Export to CSV |
| POST | `/api/backup/{id}` | Backup device config |
| GET | `/alerts` | Email alert config |
| GET | `/api/seed` | Seed demo data |

---

## 🏢 Demo Devices

20 realistic Buddha Air network devices across 6 Nepal airports:

| Location | Devices |
|----------|---------|
| Kathmandu HQ | Router, Switch, Firewall, Server, AP |
| Pokhara Airport | Router, Switch, Firewall, AP |
| Bharatpur Airport | Router, Switch, Firewall |
| Biratnagar Airport | Router, Switch, AP |
| Janakpur Airport | Router, Switch |
| Tumlingtar Airport | Router, Switch |

---

## 🚢 Deploy Your Own

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template)

```bash
# 1. Fork this repository
# 2. Go to railway.app → New Project → Deploy from GitHub
# 3. Select your forked repo
# 4. Railway auto-deploys — visit /api/seed to load demo data
```

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">

Built with ❤️ for Buddha Air Nepal NOC

**[⭐ Star this repo](https://github.com/lokendrasah449/AeroNMS)** if you found it useful!

</div>
