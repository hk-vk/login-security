from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime, Text
from datetime import datetime

from app.database.database import Base

class SecuritySettings(Base):
    __tablename__ = "security_settings"
    
    id = Column(Integer, primary_key=True)
    
    # Password policy
    password_min_length = Column(Integer, default=8)
    password_require_uppercase = Column(Boolean, default=True)
    password_require_lowercase = Column(Boolean, default=True)
    password_require_digits = Column(Boolean, default=True)
    password_require_special = Column(Boolean, default=True)
    password_expiry_days = Column(Integer, default=90)  # 0 means never expires
    password_history_count = Column(Integer, default=5)  # How many previous passwords to remember
    
    # Login security
    max_login_attempts = Column(Integer, default=5)
    lockout_duration_minutes = Column(Integer, default=30)
    session_timeout_minutes = Column(Integer, default=30)
    require_mfa = Column(Boolean, default=False)
    
    # IP security
    ip_whitelist_enabled = Column(Boolean, default=False)
    ip_blacklist_enabled = Column(Boolean, default=True)
    
    # Device security
    device_trust_duration_days = Column(Integer, default=30)
    
    # Time-based checks
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_updated_by = Column(String, nullable=True) 