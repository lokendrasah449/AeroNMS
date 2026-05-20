"""
AeroNMS - Seed Demo Data v1.3
Includes parent_id relationships for topology map
"""

from database import SessionLocal, engine, Base
import models, crud

Base.metadata.create_all(bind=engine)

# Phase 1: devices without parents
DEVICES_P1 = [
    ("KTM-Core-Router-01",  "10.1.1.1",   "router",   "Kathmandu HQ",     "Core internet gateway router"),
    ("KTM-Firewall-01",     "10.1.1.254", "firewall", "Kathmandu HQ",     "Primary perimeter firewall"),
    ("KTM-Server-NMS",      "10.1.1.50",  "server",   "Kathmandu HQ",     "NMS and monitoring server"),
    ("PKR-Router-01",       "10.2.1.1",   "router",   "Pokhara Airport",  "WAN uplink router"),
    ("PKR-Firewall-01",     "10.2.1.254", "firewall", "Pokhara Airport",  "Edge firewall"),
    ("BWA-Router-01",       "10.3.1.1",   "router",   "Bharatpur Airport","MPLS uplink router"),
    ("BWA-Firewall-01",     "10.3.1.254", "firewall", "Bharatpur Airport","Perimeter firewall"),
    ("BRT-Router-01",       "10.4.1.1",   "router",   "Biratnagar Airport","Branch WAN router"),
    ("JKP-Router-01",       "10.5.1.1",   "router",   "Janakpur Airport", "WAN router"),
    ("TMI-Router-01",       "10.6.1.1",   "router",   "Tumlingtar Airport","Remote site router"),
]

# Phase 2: devices that connect to parent by hostname
DEVICES_P2 = [
    ("KTM-Dist-Switch-01",  "10.1.1.10",  "switch",   "Kathmandu HQ",     "Distribution switch NOC",         "KTM-Core-Router-01"),
    ("KTM-Access-SW-02",    "10.1.1.11",  "switch",   "Kathmandu HQ",     "Access switch Terminal building",  "KTM-Dist-Switch-01"),
    ("KTM-AP-Terminal-01",  "10.1.1.20",  "ap",       "Kathmandu HQ",     "Wi-Fi AP Departure hall",          "KTM-Access-SW-02"),
    ("PKR-Switch-02",       "10.2.1.10",  "switch",   "Pokhara Airport",  "Core switch Pokhara terminal",     "PKR-Router-01"),
    ("PKR-AP-Lounge-01",    "10.2.1.20",  "ap",       "Pokhara Airport",  "Wi-Fi AP Passenger lounge",        "PKR-Switch-02"),
    ("BWA-Switch-01",       "10.3.1.10",  "switch",   "Bharatpur Airport","Access switch",                    "BWA-Router-01"),
    ("BRT-Switch-01",       "10.4.1.10",  "switch",   "Biratnagar Airport","Terminal access switch",          "BRT-Router-01"),
    ("BRT-AP-01",           "10.4.1.20",  "ap",       "Biratnagar Airport","Wi-Fi AP Check-in area",          "BRT-Switch-01"),
    ("JKP-Switch-01",       "10.5.1.10",  "switch",   "Janakpur Airport", "Access switch",                    "JKP-Router-01"),
    ("TMI-Switch-01",       "10.6.1.10",  "switch",   "Tumlingtar Airport","Remote access switch",            "TMI-Router-01"),
]

def seed():
    db = SessionLocal()
    existing = crud.get_all_devices(db)
    if existing:
        print(f"  Database already has {len(existing)} devices. Skipping seed.")
        db.close()
        return

    # Phase 1
    for hostname, ip, dtype, location, desc in DEVICES_P1:
        crud.create_device(db, hostname, ip, dtype, location, desc)
        print(f"  + {hostname:<30} {ip:<16} [{dtype:<8}] @ {location}")

    # Phase 2 - with parent lookups
    all_devs = crud.get_all_devices(db)
    name_map = {d.hostname: d.id for d in all_devs}
    for hostname, ip, dtype, location, desc, parent_name in DEVICES_P2:
        pid = name_map.get(parent_name)
        crud.create_device(db, hostname, ip, dtype, location, desc, parent_id=pid)
        print(f"  + {hostname:<30} {ip:<16} [{dtype:<8}] @ {location}  → {parent_name}")

    db.close()
    total = len(DEVICES_P1) + len(DEVICES_P2)
    print(f"\n✓ Seeded {total} devices with topology connections.")

if __name__ == "__main__":
    print("AeroNMS v1.3 - Seeding demo data...")
    seed()
