from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    
    # Security fields
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime, nullable=True)
    account_locked_until = Column(DateTime, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)
    password_last_changed = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    risk_score = Column(Integer, default=0)
    
    # User data
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Role relationship
    role_id = Column(Integer, ForeignKey("roles.id"))
    role = relationship("Role", back_populates="users")
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    login_history = relationship("LoginHistory", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    
    # Security relationships
    login_attempts = relationship("LoginAttempt", back_populates="user", foreign_keys="[LoginAttempt.user_id]", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="user", foreign_keys="[SecurityEvent.user_id]", cascade="all, delete-orphan")
    suspicious_activities = relationship("SuspiciousActivity", back_populates="user", cascade="all, delete-orphan")
    login_locations = relationship("LoginLocation", back_populates="user", cascade="all, delete-orphan")
    
    # Acknowledged security events
    acknowledged_events = relationship("SecurityEvent", 
                                      foreign_keys="[SecurityEvent.acknowledged_by]",
                                      back_populates="acknowledged_by_user")
    
    # Risk assessment reviews
    risk_assessment_reviews = relationship("RiskAssessmentLog", 
                                          foreign_keys="[RiskAssessmentLog.reviewed_by]",
                                          back_populates="reviewer")
    
    # IP blocks
    ip_blocks = relationship("BlockedIP", 
                            foreign_keys="[BlockedIP.blocked_by]", 
                            back_populates="admin")
    
    @property
    def full_name(self):
        """Return the user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        return self.username 