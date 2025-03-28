from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
import os
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.login_history import LoginHistory
from app.models.device import Device
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get security settings from environment variables
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", "30"))

def check_account_lockout(user: User) -> Dict[str, Any]:
    """Check if a user account is locked due to too many failed login attempts"""
    now = datetime.utcnow()
    
    # Check if the account is locked
    if user.account_locked_until and user.account_locked_until > now:
        time_remaining = user.account_locked_until - now
        minutes_remaining = int(time_remaining.total_seconds() / 60) + 1
        
        return {
            "locked": True,
            "minutes_remaining": minutes_remaining,
            "locked_until": user.account_locked_until
        }
    
    return {"locked": False}

def handle_failed_login(db: Session, user: User) -> Dict[str, Any]:
    """Handle a failed login attempt, incrementing the counter and locking account if necessary"""
    now = datetime.utcnow()
    
    # Increment the failed login counter
    user.failed_login_attempts += 1
    user.last_failed_login = now
    
    result = {"locked": False}
    
    # Check if the account should be locked
    if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
        lockout_duration = timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        user.account_locked_until = now + lockout_duration
        
        result = {
            "locked": True,
            "minutes_remaining": LOCKOUT_DURATION_MINUTES,
            "locked_until": user.account_locked_until
        }
    
    # Save changes to the database
    db.commit()
    
    return result

def handle_successful_login(db: Session, user: User) -> None:
    """Reset the failed login counter and lock status after a successful login"""
    user.failed_login_attempts = 0
    user.last_failed_login = None
    user.account_locked_until = None
    
    # Save changes to the database
    db.commit()

def detect_suspicious_login(
    db: Session, 
    user: User, 
    ip_address: Optional[str] = None, 
    user_agent: Optional[str] = None,
    location: Optional[str] = None,
    device_fingerprint: Optional[str] = None
) -> Dict[str, Any]:
    """Detect suspicious login attempts based on various factors"""
    now = datetime.utcnow()
    risk_score = 0
    risk_factors = []
    
    # Check if IP address has been used before by this user
    if ip_address:
        previous_logins = db.query(LoginHistory).filter(
            LoginHistory.user_id == user.id,
            LoginHistory.ip_address == ip_address,
            LoginHistory.success == True
        ).count()
        
        if previous_logins == 0:
            risk_score += 20
            risk_factors.append("New IP address")
    
    # Check if device has been used before by this user
    if device_fingerprint:
        device = db.query(Device).filter(
            Device.user_id == user.id,
            Device.device_fingerprint == device_fingerprint
        ).first()
        
        if not device:
            risk_score += 20
            risk_factors.append("New device")
        elif not device.is_trusted:
            risk_score += 10
            risk_factors.append("Untrusted device")
    
    # Check for location anomalies (simplified)
    if location:
        previous_locations = db.query(LoginHistory).filter(
            LoginHistory.user_id == user.id,
            LoginHistory.location == location,
            LoginHistory.success == True
        ).count()
        
        if previous_locations == 0:
            risk_score += 20
            risk_factors.append("New location")
    
    # Check for frequent failed login attempts
    recent_failures = db.query(LoginHistory).filter(
        LoginHistory.user_id == user.id,
        LoginHistory.success == False,
        LoginHistory.timestamp > now - timedelta(hours=24)
    ).count()
    
    if recent_failures > 3:
        risk_score += 20
        risk_factors.append("Recent failed login attempts")
    
    # Determine the overall risk level
    risk_level = "low"
    if risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "require_mfa": risk_level != "low"  # Require MFA for medium and high risk
    }

def check_password_expiration(user: User) -> Dict[str, Any]:
    """Check if the user's password has expired"""
    now = datetime.utcnow()
    password_expiry_days = int(os.getenv("PASSWORD_EXPIRY_DAYS", "90"))
    
    # If password_expiry_days is 0, passwords never expire
    if password_expiry_days == 0:
        return {"expired": False}
    
    # Calculate the expiration date
    expiration_date = user.password_last_changed + timedelta(days=password_expiry_days)
    
    if now > expiration_date:
        # Password has expired
        days_expired = (now - expiration_date).days
        return {
            "expired": True,
            "days_expired": days_expired
        }
    else:
        # Password has not expired yet
        days_remaining = (expiration_date - now).days
        return {
            "expired": False,
            "days_remaining": days_remaining
        } 