"""
AeroNMS - Monitoring Engine
Ping via Linux subprocess, SNMP polling, backup generation, alert logging
"""

import subprocess
import re
import os
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


# ─── Email Config ─────────────────────────────────────────────────────────────
EMAIL_CONFIG_PATH = "email_config.json"

def load_email_config() -> dict:
    if os.path.exists(EMAIL_CONFIG_PATH):
        with open(EMAIL_CONFIG_PATH, "r") as f:
            return json.load(f)
    return {}

def save_email_config(cfg: dict):
    with open(EMAIL_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


# ─── Ping ─────────────────────────────────────────────────────────────────────
def ping_host(ip: str) -> dict:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            match = re.search(r"time[=<]([\d.]+)\s*ms", result.stdout)
            latency = float(match.group(1)) if match else None
            return {"status": "UP", "latency_ms": latency}
        else:
            return {"status": "DOWN", "latency_ms": None}
    except subprocess.TimeoutExpired:
        return {"status": "DOWN", "latency_ms": None}
    except FileNotFoundError:
        return _simulate_ping(ip)
    except Exception:
        return {"status": "DOWN", "latency_ms": None}


def _simulate_ping(ip: str) -> dict:
    import hashlib, random
    seed = int(hashlib.md5(ip.encode()).hexdigest(), 16) % 1000
    rng = random.Random(seed + int(datetime.now().timestamp() / 60))
    if rng.random() < 0.80:
        latency = round(rng.uniform(1.5, 45.0), 2)
        return {"status": "UP", "latency_ms": latency}
    return {"status": "DOWN", "latency_ms": None}


# ─── SNMP Polling ─────────────────────────────────────────────────────────────
SNMP_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysUpTime":   "1.3.6.1.2.1.1.3.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact":  "1.3.6.1.2.1.1.4.0",
    "ifNumber":    "1.3.6.1.2.1.2.1.0",
}

def snmp_poll(ip: str, community: str = "public", version: str = "2c") -> dict:
    results = {}
    for name, oid in SNMP_OIDS.items():
        try:
            cmd = ["snmpget", f"-v{version}", "-c", community, "-t", "2", "-r", "1", ip, oid]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout.strip():
                line = out.stdout.strip()
                val = line.split(":", 2)[-1].strip().strip('"')
                results[name] = val
            else:
                results[name] = "N/A"
        except FileNotFoundError:
            return _simulate_snmp(ip)
        except Exception:
            results[name] = "Error"
    results["polled_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results["ip"] = ip
    results["method"] = "snmpget"
    return results


def _simulate_snmp(ip: str) -> dict:
    import hashlib, random
    seed = int(hashlib.md5(ip.encode()).hexdigest(), 16) % 9999
    rng = random.Random(seed)
    updays = rng.randint(1, 420)
    uphours = rng.randint(0, 23)
    upmins = rng.randint(0, 59)
    ticks = ((updays * 24 * 3600) + (uphours * 3600) + (upmins * 60)) * 100
    loc_map = {
        "10.1": "Kathmandu HQ", "10.2": "Pokhara Airport",
        "10.3": "Bharatpur Airport", "10.4": "Biratnagar Airport",
        "10.5": "Janakpur Airport", "10.6": "Tumlingtar Airport",
    }
    loc = next((v for k, v in loc_map.items() if ip.startswith(k)), "Nepal NOC")
    vendors = [
        "Cisco IOS Software, Version 15.7(3)M5",
        "Cisco IOS XE Software, Version 17.9.3a",
        "Juniper Networks Junos OS 22.3R1.11",
        "Mikrotik RouterOS 7.10.2",
        "Linux 5.15.0-kali3-amd64 #1 SMP Debian",
        "Fortinet FortiOS v7.4.1 build2463",
    ]
    octets = ip.split(".")
    return {
        "sysDescr":    rng.choice(vendors),
        "sysUpTime":   f"{updays}d {uphours}h {upmins}m ({ticks} timeticks)",
        "sysName":     f"device-{octets[-1]}.aeronms.buddhaair.com.np",
        "sysLocation": loc,
        "sysContact":  "noc@buddhaair.com.np",
        "ifNumber":    str(rng.randint(4, 48)),
        "polled_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip":          ip,
        "method":      "simulated",
    }


# ─── Alert Logging ────────────────────────────────────────────────────────────
def log_alert(hostname: str, ip: str, location: str):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] ALERT: {hostname} ({ip}) @ {location} is DOWN\n"
    with open("logs/alerts.log", "a") as f:
        f.write(line)


# ─── Email Alerts ─────────────────────────────────────────────────────────────
def send_email_alert(hostname: str, ip: str, location: str, status: str = "DOWN") -> dict:
    cfg = load_email_config()
    if not cfg.get("enabled"):
        return {"success": False, "reason": "Email alerts disabled"}
    required = ["smtp_host", "smtp_port", "smtp_user", "smtp_pass", "from_addr", "to_addrs"]
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        return {"success": False, "reason": f"Missing: {', '.join(missing)}"}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"[AeroNMS] ALERT: {hostname} is {status}"
    color = "#ff3d5a" if "DOWN" in status else "#00e896"
    icon  = "🔴" if "DOWN" in status else "🟢"

    body_html = f"""<html><body style="font-family:Arial,sans-serif;background:#0d1520;color:#d4e8ff;padding:24px;">
  <div style="max-width:600px;margin:0 auto;background:#111c2b;border-radius:12px;border:1px solid #1e3050;padding:28px;">
    <div style="text-align:center;margin-bottom:20px;">
      <div style="font-size:36px;">✈️</div>
      <h2 style="color:#00aaff;margin:8px 0;">AeroNMS Network Alert</h2>
      <p style="color:#5a7a9a;font-size:12px;">Buddha Air · Nepal Network Operations Center</p>
    </div>
    <div style="background:#1a1a2e;border:1px solid {color};border-radius:8px;padding:20px;margin-bottom:20px;">
      <h3 style="color:{color};margin:0 0 14px;">{icon} Device {status}</h3>
      <table style="width:100%;font-size:14px;color:#d4e8ff;border-collapse:collapse;">
        <tr><td style="color:#5a7a9a;padding:6px 0;width:130px;">Hostname</td><td><strong>{hostname}</strong></td></tr>
        <tr><td style="color:#5a7a9a;padding:6px 0;">IP Address</td><td><code style="color:#00aaff;">{ip}</code></td></tr>
        <tr><td style="color:#5a7a9a;padding:6px 0;">Location</td><td>{location}</td></tr>
        <tr><td style="color:#5a7a9a;padding:6px 0;">Status</td><td><strong style="color:{color};">{status}</strong></td></tr>
        <tr><td style="color:#5a7a9a;padding:6px 0;">Timestamp</td><td>{now}</td></tr>
      </table>
    </div>
    <p style="color:#5a7a9a;font-size:12px;text-align:center;">
      Login to <a href="http://localhost:8000" style="color:#00aaff;">AeroNMS NOC</a> to investigate.
    </p>
  </div>
</body></html>"""

    body_text = f"AeroNMS ALERT\n\nDevice: {hostname}\nIP: {ip}\nLocation: {location}\nStatus: {status}\nTime: {now}\n"

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = cfg["from_addr"]
        to_list = cfg["to_addrs"] if isinstance(cfg["to_addrs"], list) else [cfg["to_addrs"]]
        msg["To"]      = ", ".join(to_list)
        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))
        port = int(cfg["smtp_port"])
        if port == 465:
            with smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=10) as s:
                s.login(cfg["smtp_user"], cfg["smtp_pass"])
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg["smtp_host"], port, timeout=10) as s:
                s.ehlo(); s.starttls()
                s.login(cfg["smtp_user"], cfg["smtp_pass"])
                s.send_message(msg)
        return {"success": True, "to": msg["To"]}
    except smtplib.SMTPAuthenticationError:
        return {"success": False, "reason": "SMTP auth failed — check credentials"}
    except Exception as e:
        return {"success": False, "reason": str(e)}


def test_email(cfg: dict) -> dict:
    save_email_config({**cfg, "enabled": True})
    return send_email_alert("TEST-DEVICE-01", "10.1.1.1", "Kathmandu HQ", "DOWN (Test Alert)")


# ─── CSV Export ───────────────────────────────────────────────────────────────
def export_devices_csv(devices: list) -> str:
    lines = ["ID,Hostname,IP Address,Type,Location,Status,Latency (ms),Description,Last Checked"]
    for d in devices:
        latency = f"{d.latency_ms:.1f}" if d.latency_ms else ""
        last_checked = d.last_checked.strftime("%Y-%m-%d %H:%M:%S") if d.last_checked else ""
        desc = (d.description or "").replace(",", ";").replace('"', "'")
        lines.append(
            f'{d.id},{d.hostname},{d.ip_address},{d.device_type},'
            f'"{d.location}",{d.status},{latency},"{desc}",{last_checked}'
        )
    return "\n".join(lines)


# ─── Config Backup ────────────────────────────────────────────────────────────
BACKUP_TEMPLATES = {
    "router": """\
! AeroNMS Simulated Config Backup
! Device   : {hostname}
! IP       : {ip_address}
! Type     : Router
! Location : {location}
! Backed up: {timestamp}
!
hostname {hostname}
!
interface GigabitEthernet0/0
 ip address {ip_address} 255.255.255.0
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 10.0.0.1
!
line vty 0 4
 transport input ssh
 login local
!
end
""",
    "switch": """\
! AeroNMS Simulated Config Backup
! Device   : {hostname}
! IP       : {ip_address}
! Type     : Switch
! Location : {location}
! Backed up: {timestamp}
!
hostname {hostname}
!
vlan 10
 name MGMT
vlan 20
 name STAFF
vlan 30
 name GUEST
!
interface Vlan10
 ip address {ip_address} 255.255.255.0
 no shutdown
!
spanning-tree mode rapid-pvst
!
end
""",
    "firewall": """\
# AeroNMS Simulated Config Backup
# Device   : {hostname}
# IP       : {ip_address}
# Type     : Firewall
# Location : {location}
# Backed up: {timestamp}

[interfaces]
eth0 = WAN  ip=203.0.113.1/30
eth1 = LAN  ip={ip_address}/24

[rules]
ALLOW established,related
ALLOW tcp dport=443 ACCEPT
ALLOW tcp dport=22  src=10.0.0.0/8 ACCEPT
DROP all

[vpn]
ike_version = 2
encryption  = AES-256-GCM
""",
    "server": """\
# AeroNMS Simulated Config Backup
# Device   : {hostname}
# IP       : {ip_address}
# Type     : Server
# Location : {location}
# Backed up: {timestamp}

[network]
IPADDR={ip_address}
NETMASK=255.255.255.0
GATEWAY=10.0.0.1
DNS1=8.8.8.8
DNS2=1.1.1.1

[services]
sshd=enabled
nginx=enabled
snmpd=enabled
""",
    "ap": """\
# AeroNMS Simulated Config Backup
# Device   : {hostname}
# IP       : {ip_address}
# Type     : Access Point
# Location : {location}
# Backed up: {timestamp}

[wireless]
ssid_staff  = BuddhaAir-Staff   band=5GHz  vlan=20
ssid_guest  = BuddhaAir-Guest   band=2.4GHz vlan=30
security    = WPA3-Enterprise
radius_ip   = 10.0.1.10

[management]
ip={ip_address}
channel=auto
tx_power=20dBm
""",
}

def create_backup(device) -> str:
    os.makedirs("backups", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = device.hostname.replace(" ", "_")
    filename  = f"{safe_name}_{timestamp}.txt"
    filepath  = os.path.join("backups", filename)
    template = BACKUP_TEMPLATES.get(device.device_type.lower(), BACKUP_TEMPLATES["router"])
    content  = template.format(
        hostname=device.hostname, ip_address=device.ip_address,
        location=device.location, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    with open(filepath, "w") as f:
        f.write(content)
    return filename
