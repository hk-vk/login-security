from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime, Text, Float, Enum
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime

from app.database.database import Base

def generate_uuid():
    """Generate a string UUID."""
    return str(uuid.uuid4())

class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # critical, high, medium, low
    description = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user_agent = Column(String, nullable=True)
    
    # For alert management
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    acknowledged_by_user = relationship("User", foreign_keys=[acknowledged_by])

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String, nullable=True)  # Store for failed attempts where user might not exist
    ip_address = Column(String, nullable=False)
    user_agent = Column(String, nullable=True)
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    failure_reason = Column(String, nullable=True)
    
    # Risk scoring fields
    risk_score = Column(Float, default=0.0)
    location = Column(String, nullable=True)
    device_fingerprint = Column(String, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="login_attempts")

class RiskAssessmentLog(Base):
    __tablename__ = "risk_assessment_logs"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow)
    overall_risk_score = Column(Integer, nullable=False)
    brute_force_risk = Column(Integer, nullable=True)
    account_takeover_risk = Column(Integer, nullable=True)
    data_breach_risk = Column(Integer, nullable=True)
    session_anomaly_risk = Column(Integer, nullable=True)
    geo_anomaly_risk = Column(Integer, nullable=True)
    system_health_risk = Column(Integer, nullable=True)
    
    # Associated actions
    actions_taken = Column(Text, nullable=True)
    recommended_actions = Column(Text, nullable=True)
    
    # Admin who reviewed the assessment
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    
    # Relationships
    reviewer = relationship("User", foreign_keys=[reviewed_by])

class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    ip_address = Column(String, nullable=False, unique=True)
    reason = Column(String, nullable=False)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    blocked_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # Admin who manually blocked
    automated = Column(Boolean, default=True)  # True if blocked by system
    
    # Relationships
    admin = relationship("User", foreign_keys=[blocked_by])

class SuspiciousActivity(Base):
    __tablename__ = "suspicious_activities"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    ip_address = Column(String, nullable=True)
    activity_type = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    risk_score = Column(Integer, default=0)
    
    # Flag if this was used in risk assessment
    included_in_risk_assessment = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="suspicious_activities")

class LoginLocation(Base):
    __tablename__ = "login_locations"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ip_address = Column(String, nullable=False)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Is this a common location for this user?
    is_common = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="login_locations") 