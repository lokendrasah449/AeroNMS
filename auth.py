"""
AeroNMS - Authentication & Authorization Module
RBAC: admin, noc, viewer
Password hashing with hashlib (no extra dependencies)
"""

import hashlib
import os
import secrets
from datetime import datetime
from sqlalchemy.orm import Session
import models


# ─── Password Hashing (SHA-256 + salt, no bcrypt needed) ─────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, hashed = stored.split(":", 1)
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == hashed
    except Exception:
        return False

# ─── Role Permissions ─────────────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": [
        "view_dashboard", "view_devices", "add_device", "edit_device", "delete_device",
        "view_monitor", "run_monitor", "view_topology", "view_snmp", "run_snmp",
        "view_backup", "run_backup", "view_alerts", "configure_alerts",
        "view_security", "configure_security",
        "view_admin", "manage_users", "view_audit",
        "export_csv",
    ],
    "noc": [
        "view_dashboard", "view_devices", "add_device", "edit_device",
        "view_monitor", "run_monitor", "view_topology", "view_snmp", "run_snmp",
        "view_backup", "run_backup", "view_alerts",
        "view_security", "export_csv",
    ],
    "viewer": [
        "view_dashboard", "view_devices",
        "view_monitor", "view_topology",
        "view_security",
    ],
}

ROLE_LABELS = {
    "admin": ("Admin",        "router"),
    "noc":   ("NOC Engineer", "up"),
    "viewer":("Viewer",       "unknown"),
}

def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, [])

def get_permissions(role: str) -> list:
    return ROLE_PERMISSIONS.get(role, [])

# ─── User CRUD ────────────────────────────────────────────────────────────────
def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_all_users(db: Session):
    return db.query(models.User).order_by(models.User.role, models.User.username).all()

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def create_user(db: Session, username: str, password: str, full_name: str,
                email: str, role: str) -> models.User:
    user = models.User(
        username      = username,
        password_hash = hash_password(password),
        full_name     = full_name,
        email         = email,
        role          = role,
        is_active     = True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def update_user(db: Session, user_id: int, full_name: str, email: str,
                role: str, is_active: bool):
    user = get_user_by_id(db, user_id)
    if user:
        user.full_name = full_name
        user.email     = email
        user.role      = role
        user.is_active = is_active
        db.commit()
    return user

def reset_password(db: Session, user_id: int, new_password: str):
    user = get_user_by_id(db, user_id)
    if user:
        user.password_hash = hash_password(new_password)
        db.commit()
    return user

def delete_user(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    if user:
        db.delete(user)
        db.commit()

def update_last_login(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    if user:
        user.last_login = datetime.now()
        db.commit()

# ─── Audit Logging ────────────────────────────────────────────────────────────
def log_action(db: Session, username: str, role: str,
               action: str, detail: str = "", ip: str = ""):
    entry = models.AuditLog(
        username   = username,
        role       = role,
        action     = action,
        detail     = detail,
        ip_address = ip,
    )
    db.add(entry)
    db.commit()

def get_audit_log(db: Session, limit: int = 100):
    return db.query(models.AuditLog)\
             .order_by(models.AuditLog.timestamp.desc())\
             .limit(limit).all()

# ─── Seed Default Users ───────────────────────────────────────────────────────
def seed_default_users(db: Session):
    defaults = [
        ("admin",   "aero2024",    "System Administrator", "admin@aeronms.local",   "admin"),
        ("noc",     "buddha@noc",  "NOC Engineer",         "noc@aeronms.local",     "noc"),
        ("viewer",  "viewer123",   "Dashboard Viewer",     "viewer@aeronms.local",  "viewer"),
    ]
    for username, password, full_name, email, role in defaults:
        if not get_user_by_username(db, username):
            create_user(db, username, password, full_name, email, role)
