from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Device information
    device_fingerprint = Column(String, index=True, nullable=False)
    device_name = Column(String, nullable=True)
    device_type = Column(String, nullable=True)  # mobile, tablet, desktop, etc.
    browser = Column(String, nullable=True)
    os = Column(String, nullable=True)
    
    # Security information
    is_trusted = Column(Boolean, default=False)
    trust_expires_at = Column(DateTime, nullable=True)
    
    # Timestamps
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="devices")
    sessions = relationship("Session", back_populates="device") 