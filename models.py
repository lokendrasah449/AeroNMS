"""
AeroNMS - Database Models v1.3
Added: PingHistory, UptimeRecord
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class Device(Base):
    __tablename__ = "devices"

    id           = Column(Integer, primary_key=True, index=True)
    hostname     = Column(String(100), nullable=False, unique=True)
    ip_address   = Column(String(45),  nullable=False)
    device_type  = Column(String(50),  nullable=False)
    location     = Column(String(100), nullable=False)
    description  = Column(String(255), default="")
    notes        = Column(String(1000), default="")
    status       = Column(String(20),  default="UNKNOWN")
    latency_ms   = Column(Float,       nullable=True)
    last_checked = Column(DateTime,    nullable=True)
    created_at   = Column(DateTime,    server_default=func.now())
    updated_at   = Column(DateTime,    onupdate=func.now())

    # Topology: parent device (e.g. switch connects to router)
    parent_id    = Column(Integer, ForeignKey("devices.id"), nullable=True)

    ping_history = relationship("PingHistory", back_populates="device",
                                cascade="all, delete-orphan", order_by="PingHistory.checked_at")


class PingHistory(Base):
    __tablename__ = "ping_history"

    id         = Column(Integer, primary_key=True, index=True)
    device_id  = Column(Integer, ForeignKey("devices.id"), nullable=False)
    status     = Column(String(10), nullable=False)   # UP / DOWN
    latency_ms = Column(Float, nullable=True)
    checked_at = Column(DateTime, server_default=func.now())

    device = relationship("Device", back_populates="ping_history")
