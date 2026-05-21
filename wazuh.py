"""
AeroNMS - Wazuh Integration Module
Connects to Wazuh Manager REST API (port 55000) via JWT auth.
Falls back to realistic simulated data if Wazuh is not running.
"""

import os
import json
import requests
import urllib3
from datetime import datetime, timedelta
import random
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Config ───────────────────────────────────────────────────────────────────
WAZUH_CONFIG_PATH = "wazuh_config.json"

DEFAULT_CONFIG = {
    "enabled":   False,
    "host":      "localhost",
    "port":      55000,
    "username":  "wazuh-wui",
    "password":  "",
    "verify_ssl": False,
}

def load_config() -> dict:
    if os.path.exists(WAZUH_CONFIG_PATH):
        with open(WAZUH_CONFIG_PATH) as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    # Check environment variables (for Railway deployment)
    if os.environ.get("WAZUH_HOST"):
        return {
            "enabled":   os.environ.get("WAZUH_ENABLED", "false").lower() == "true",
            "host":      os.environ.get("WAZUH_HOST", "localhost"),
            "port":      int(os.environ.get("WAZUH_PORT", 55000)),
            "username":  os.environ.get("WAZUH_USER", "wazuh-wui"),
            "password":  os.environ.get("WAZUH_PASS", ""),
            "verify_ssl": False,
        }
    return DEFAULT_CONFIG

def save_config(cfg: dict):
    with open(WAZUH_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

# ─── JWT Auth ─────────────────────────────────────────────────────────────────
def get_token(cfg: dict) -> str | None:
    try:
        url = f"https://{cfg['host']}:{cfg['port']}/security/user/authenticate?raw=true"
        resp = requests.post(
            url,
            auth=(cfg["username"], cfg["password"]),
            verify=cfg.get("verify_ssl", False),
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.text.strip()
        return None
    except Exception:
        return None

def api_get(cfg: dict, endpoint: str, params: dict = None) -> dict | None:
    token = get_token(cfg)
    if not token:
        return None
    try:
        url = f"https://{cfg['host']}:{cfg['port']}{endpoint}"
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
            verify=cfg.get("verify_ssl", False),
            timeout=8,
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None

# ─── Real Wazuh Data ──────────────────────────────────────────────────────────
def get_alerts_live(cfg: dict, limit: int = 50) -> list:
    data = api_get(cfg, "/alerts", {"limit": limit, "sort": "-timestamp"})
    if not data:
        return []
    items = data.get("data", {}).get("affected_items", [])
    alerts = []
    for item in items:
        rule = item.get("rule", {})
        agent = item.get("agent", {})
        alerts.append({
            "id":          item.get("id", ""),
            "timestamp":   item.get("timestamp", ""),
            "level":       rule.get("level", 0),
            "rule_id":     rule.get("id", ""),
            "description": rule.get("description", "Unknown"),
            "agent_name":  agent.get("name", "Unknown"),
            "agent_id":    agent.get("id", "000"),
            "groups":      rule.get("groups", []),
            "method":      "live",
        })
    return alerts

def get_agents_live(cfg: dict) -> list:
    data = api_get(cfg, "/agents", {"limit": 100})
    if not data:
        return []
    items = data.get("data", {}).get("affected_items", [])
    agents = []
    for item in items:
        agents.append({
            "id":           item.get("id", "000"),
            "name":         item.get("name", "Unknown"),
            "ip":           item.get("ip", "N/A"),
            "status":       item.get("status", "unknown"),
            "os":           item.get("os", {}).get("name", "Unknown") if item.get("os") else "Unknown",
            "version":      item.get("version", "N/A"),
            "last_keepalive": item.get("lastKeepAlive", "N/A"),
            "method":       "live",
        })
    return agents

def get_summary_live(cfg: dict) -> dict:
    data = api_get(cfg, "/agents/summary/status")
    if not data:
        return {}
    summary = data.get("data", {})
    return {
        "active":           summary.get("active", 0),
        "disconnected":     summary.get("disconnected", 0),
        "never_connected":  summary.get("neverconnected", 0),
        "pending":          summary.get("pending", 0),
        "total":            summary.get("total", 0),
        "method":           "live",
    }

# ─── Simulated Data ───────────────────────────────────────────────────────────
RULE_TEMPLATES = [
    (3,  "5001",  "User login attempt",                          ["authentication"]),
    (5,  "5501",  "PAM: Login session opened",                   ["authentication", "pam"]),
    (7,  "1002",  "Unknown problem somewhere in the system",     ["syslog"]),
    (8,  "5551",  "Multiple authentication failures",            ["authentication_failed"]),
    (10, "5712",  "SSHD brute force attempt",                    ["authentication_failed", "ssh"]),
    (10, "31101", "Web server 400 error code",                   ["web", "accesslog"]),
    (12, "5763",  "SSHD - multiple authentication failures",     ["authentication_failed", "ssh"]),
    (13, "2502",  "Ossec server started",                        ["ossec"]),
    (8,  "86601", "Suricata: Alert - ET SCAN Nmap",              ["ids", "suricata"]),
    (10, "86602", "Suricata: Alert - ET DROP Spamhaus",          ["ids", "suricata"]),
    (7,  "533",   "File modified: /etc/passwd",                  ["syscheck"]),
    (9,  "550",   "Integrity checksum changed",                  ["syscheck"]),
    (12, "554",   "File added to the system",                    ["syscheck"]),
    (6,  "1003",  "Non standard syslog message (size).",         ["syslog"]),
    (8,  "5104",  "Process not running",                         ["service_check"]),
    (10, "18101", "Port scan detected",                          ["ids", "network"]),
    (14, "40101", "Possible SQL injection attempt",              ["web", "attack"]),
    (15, "100001","Critical: Unauthorized root access detected", ["authentication_failed", "privilege_escalation"]),
]

AGENT_TEMPLATES = [
    ("ktm-server-01",   "10.1.1.50",  "Ubuntu 22.04",    "active"),
    ("ktm-firewall-01", "10.1.1.254", "FortiOS 7.4",     "active"),
    ("pkr-server-01",   "10.2.1.50",  "CentOS 8",        "active"),
    ("brt-server-01",   "10.4.1.50",  "Ubuntu 20.04",    "disconnected"),
    ("ktm-router-01",   "10.1.1.1",   "Cisco IOS 15.7",  "active"),
    ("pkr-firewall-01", "10.2.1.254", "pfSense 2.7",     "active"),
    ("jkp-server-01",   "10.5.1.50",  "Windows Server 2019", "never_connected"),
]

def _sim_seed(extra: int = 0) -> random.Random:
    minute = int(datetime.now().timestamp() / 300)  # changes every 5 min
    return random.Random(42 + minute + extra)

def get_alerts_simulated(limit: int = 50) -> list:
    rng = _sim_seed()
    alerts = []
    now = datetime.now()
    for i in range(min(limit, 30)):
        rule = rng.choice(RULE_TEMPLATES)
        agent = rng.choice(AGENT_TEMPLATES)
        mins_ago = rng.randint(1, 480)
        ts = (now - timedelta(minutes=mins_ago)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        alerts.append({
            "id":          f"sim_{i:04d}",
            "timestamp":   ts,
            "level":       rule[0],
            "rule_id":     rule[1],
            "description": rule[2],
            "agent_name":  agent[0],
            "agent_id":    f"{i+1:03d}",
            "groups":      rule[3],
            "method":      "simulated",
        })
    # Sort by timestamp descending
    alerts.sort(key=lambda x: x["timestamp"], reverse=True)
    return alerts

def get_agents_simulated() -> list:
    agents = []
    now = datetime.now()
    rng = _sim_seed(99)
    for i, (name, ip, os_name, status) in enumerate(AGENT_TEMPLATES):
        mins = rng.randint(1, 60)
        agents.append({
            "id":             f"{i+1:03d}",
            "name":           name,
            "ip":             ip,
            "status":         status,
            "os":             os_name,
            "version":        f"Wazuh v4.{rng.randint(7,9)}.{rng.randint(0,3)}",
            "last_keepalive": (now - timedelta(minutes=mins)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method":         "simulated",
        })
    return agents

def get_summary_simulated() -> dict:
    agents = get_agents_simulated()
    return {
        "active":           sum(1 for a in agents if a["status"] == "active"),
        "disconnected":     sum(1 for a in agents if a["status"] == "disconnected"),
        "never_connected":  sum(1 for a in agents if a["status"] == "never_connected"),
        "pending":          0,
        "total":            len(agents),
        "method":           "simulated",
    }

# ─── Public Interface ─────────────────────────────────────────────────────────
def get_alerts(limit: int = 50) -> dict:
    cfg = load_config()
    if cfg.get("enabled") and cfg.get("password"):
        alerts = get_alerts_live(cfg, limit)
        if alerts:
            return {"alerts": alerts, "source": "live", "total": len(alerts)}
    alerts = get_alerts_simulated(limit)
    return {"alerts": alerts, "source": "simulated", "total": len(alerts)}

def get_agents() -> dict:
    cfg = load_config()
    if cfg.get("enabled") and cfg.get("password"):
        agents = get_agents_live(cfg)
        if agents:
            return {"agents": agents, "source": "live", "total": len(agents)}
    agents = get_agents_simulated()
    return {"agents": agents, "source": "simulated", "total": len(agents)}

def get_summary() -> dict:
    cfg = load_config()
    if cfg.get("enabled") and cfg.get("password"):
        summary = get_summary_live(cfg)
        if summary:
            return {**summary, "source": "live"}
    return {**get_summary_simulated(), "source": "simulated"}

def test_connection(cfg: dict) -> dict:
    token = get_token(cfg)
    if token:
        info = api_get(cfg, "/manager/info")
        version = info.get("data", {}).get("affected_items", [{}])[0].get("version", "Unknown") if info else "Unknown"
        return {"success": True, "version": version, "message": "Connected to Wazuh Manager"}
    return {"success": False, "message": "Could not connect — check host, port, and credentials"}

def severity_label(level: int) -> str:
    if level >= 13: return "critical"
    if level >= 10: return "high"
    if level >= 7:  return "medium"
    if level >= 4:  return "low"
    return "info"

def severity_color(level: int) -> str:
    if level >= 13: return "#ff3d5a"
    if level >= 10: return "#ff6b35"
    if level >= 7:  return "#ffaa00"
    if level >= 4:  return "#00aaff"
    return "#5a7a9a"
