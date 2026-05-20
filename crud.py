"""
AeroNMS - CRUD Operations v1.3
"""

from sqlalchemy.orm import Session
from sqlalchemy import or_, func, desc
from datetime import datetime, timedelta
import models


# ─── Devices ──────────────────────────────────────────────────────────────────
def get_all_devices(db: Session):
    return db.query(models.Device).order_by(models.Device.location, models.Device.hostname).all()

def get_device(db: Session, device_id: int):
    return db.query(models.Device).filter(models.Device.id == device_id).first()

def search_devices(db: Session, query: str = ""):
    if not query:
        return get_all_devices(db)
    q = f"%{query}%"
    return db.query(models.Device).filter(
        or_(
            models.Device.hostname.ilike(q),
            models.Device.ip_address.ilike(q),
            models.Device.location.ilike(q),
            models.Device.device_type.ilike(q),
            models.Device.description.ilike(q),
        )
    ).order_by(models.Device.location, models.Device.hostname).all()

def create_device(db: Session, hostname, ip_address, device_type, location,
                  description="", notes="", parent_id=None):
    device = models.Device(
        hostname=hostname, ip_address=ip_address, device_type=device_type,
        location=location, description=description, notes=notes,
        parent_id=parent_id, status="UNKNOWN",
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device

def update_device(db: Session, device_id, hostname, ip_address, device_type,
                  location, description="", notes="", parent_id=None):
    device = get_device(db, device_id)
    if device:
        device.hostname    = hostname
        device.ip_address  = ip_address
        device.device_type = device_type
        device.location    = location
        device.description = description
        device.notes       = notes
        device.parent_id   = parent_id if parent_id else None
        db.commit()
        db.refresh(device)
    return device

def delete_device(db: Session, device_id: int):
    # Clear parent refs before deleting
    db.query(models.Device).filter(models.Device.parent_id == device_id).update({"parent_id": None})
    device = get_device(db, device_id)
    if device:
        db.delete(device)
        db.commit()

def update_device_status(db: Session, device_id: int, status: str, latency_ms=None):
    device = get_device(db, device_id)
    if device:
        device.status       = status
        device.latency_ms   = latency_ms
        device.last_checked = datetime.now()
        db.commit()
        # Record history
        add_ping_history(db, device_id, status, latency_ms)


# ─── Ping History ─────────────────────────────────────────────────────────────
def add_ping_history(db: Session, device_id: int, status: str, latency_ms=None):
    record = models.PingHistory(
        device_id=device_id, status=status, latency_ms=latency_ms,
        checked_at=datetime.now()
    )
    db.add(record)
    db.commit()
    # Keep only last 200 records per device
    old = db.query(models.PingHistory)\
            .filter(models.PingHistory.device_id == device_id)\
            .order_by(desc(models.PingHistory.checked_at))\
            .offset(200).all()
    for r in old:
        db.delete(r)
    db.commit()

def get_ping_history(db: Session, device_id: int, limit: int = 60):
    return db.query(models.PingHistory)\
             .filter(models.PingHistory.device_id == device_id)\
             .order_by(desc(models.PingHistory.checked_at))\
             .limit(limit).all()

def get_uptime_percent(db: Session, device_id: int, hours: int = 24) -> float:
    since = datetime.now() - timedelta(hours=hours)
    total = db.query(func.count(models.PingHistory.id))\
              .filter(models.PingHistory.device_id == device_id,
                      models.PingHistory.checked_at >= since).scalar()
    if not total:
        return None
    up = db.query(func.count(models.PingHistory.id))\
           .filter(models.PingHistory.device_id == device_id,
                   models.PingHistory.status == "UP",
                   models.PingHistory.checked_at >= since).scalar()
    return round((up / total) * 100, 1)

def get_avg_latency(db: Session, device_id: int, hours: int = 24):
    since = datetime.now() - timedelta(hours=hours)
    result = db.query(func.avg(models.PingHistory.latency_ms))\
               .filter(models.PingHistory.device_id == device_id,
                       models.PingHistory.status == "UP",
                       models.PingHistory.checked_at >= since).scalar()
    return round(result, 2) if result else None
