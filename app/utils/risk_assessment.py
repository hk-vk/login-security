from typing import Dict, Any, Optional, Tuple, List
import datetime
from sqlalchemy.orm import Session
from app.utils.geolocation import get_geolocation, calculate_location_risk
from app.models.login_history import LoginHistory
from app.models.user import User
from app.models.device import Device
from ipaddress import IPv4Address, IPv4Network
import math
from sqlalchemy import func
from app.models.location import Location

def calculate_login_risk(
    db: Session,
    user: User,
    ip_address: str,
    user_agent: str,
    location_data: Optional[Dict[str, Any]] = None,
    login_timestamp: datetime = None
) -> Tuple[int, Dict[str, int]]:
    """
    Calculate a risk score for a login attempt based on various risk factors.
    Returns a tuple of (risk_score, risk_factors) where risk_factors is a dictionary
    of individual risk scores by category.
    
    The risk score is on a scale of 0-100, with higher values indicating higher risk.
    """
    if login_timestamp is None:
        login_timestamp = datetime.datetime.utcnow()
    
    # Initialize risk factors dictionary
    risk_factors = {
        "geolocation": 0,
        "login_history": 0,
        "ip_address": 0,
        "device": 0,
        "time_based": 0
    }
    
    # 1. Geolocation risk assessment
    if location_data:
        # Get user's recent login locations
        recent_locations = get_user_login_locations(db, user.id)
        country_code = location_data.get("country_code")
        
        if recent_locations and country_code:
            # Check if this country has been used before
            if country_code not in recent_locations:
                risk_factors["geolocation"] = 25  # New country is higher risk
            
            # Calculate distance from most frequent location
            # This is a simplified approach; in a real implementation you'd use
            # proper geospatial calculations
            most_frequent_country = max(recent_locations, key=recent_locations.get)
            if country_code != most_frequent_country:
                risk_factors["geolocation"] += 15
    
    # 2. Login history patterns
    login_history_risk = assess_login_history_risk(db, user.id, login_timestamp)
    risk_factors["login_history"] = login_history_risk
    
    # 3. IP address risk assessment
    ip_risk = assess_ip_risk(db, ip_address)
    risk_factors["ip_address"] = ip_risk
    
    # 4. Device fingerprinting risk
    device_risk = assess_device_risk(db, user.id, user_agent)
    risk_factors["device"] = device_risk
    
    # 5. Time-based risk (unusual login times)
    time_risk = assess_time_based_risk(db, user.id, login_timestamp)
    risk_factors["time_based"] = time_risk
    
    # Calculate total risk score (weighted average)
    total_risk = (
        risk_factors["geolocation"] * 0.25 +
        risk_factors["login_history"] * 0.2 +
        risk_factors["ip_address"] * 0.2 +
        risk_factors["device"] * 0.2 +
        risk_factors["time_based"] * 0.15
    )
    
    # Round to nearest integer and ensure it's between 0-100
    risk_score = min(100, max(0, round(total_risk)))
    
    return risk_score, risk_factors

def should_require_additional_verification(risk_score: int, threshold: int = 70) -> bool:
    """
    Determine if additional verification should be required based on the risk score.
    """
    return risk_score >= threshold

def get_user_login_locations(db: Session, user_id: int) -> Dict[str, int]:
    """
    Get recent successful login locations for a user.
    Returns a dictionary of {country_code: count}
    """
    # Limit to last 30 days of successful logins
    cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=30)
    
    # Find login history entries with location data
    login_locations = (
        db.query(LoginHistory)
        .filter(
            LoginHistory.user_id == user_id,
            LoginHistory.success == True,
            LoginHistory.timestamp > cutoff_date
        )
        .order_by(LoginHistory.timestamp.desc())
        .limit(100)
        .all()
    )
    
    # Extract location data
    country_counts = {}
    for login in login_locations:
        # If we have a location record, use its country code
        if login.location_id:
            location = db.query(Location).filter(Location.id == login.location_id).first()
            if location and location.country_code:
                country_code = location.country_code
                country_counts[country_code] = country_counts.get(country_code, 0) + 1
    
    return country_counts

def assess_login_history_risk(db: Session, user_id: int, login_timestamp: datetime) -> int:
    """
    Assess risk based on login history patterns.
    Returns a risk score from 0-100.
    """
    # Get user's recent login history
    cutoff_date = login_timestamp - datetime.timedelta(days=30)
    login_history = (
        db.query(LoginHistory)
        .filter(
            LoginHistory.user_id == user_id,
            LoginHistory.timestamp > cutoff_date
        )
        .order_by(LoginHistory.timestamp.desc())
        .limit(100)
        .all()
    )
    
    if not login_history:
        # No login history might be a new account or suspicious
        return 50
    
    # Check for recent failed login attempts
    recent_cutoff = login_timestamp - datetime.timedelta(hours=24)
    recent_failed_attempts = sum(
        1 for login in login_history 
        if login.timestamp > recent_cutoff and not login.success
    )
    
    # Calculate risk based on failed attempts
    if recent_failed_attempts > 10:
        return 100  # Very high risk
    elif recent_failed_attempts > 5:
        return 75  # High risk
    elif recent_failed_attempts > 2:
        return 50  # Medium risk
    elif recent_failed_attempts > 0:
        return 25  # Low risk
    
    # If no recent failed attempts, low risk
    return 0

def assess_ip_risk(db: Session, ip_address: str) -> int:
    """
    Assess risk based on IP address.
    Returns a risk score from 0-100.
    """
    try:
        # Check if IP is private (RFC 1918)
        ip = IPv4Address(ip_address)
        
        private_ranges = [
            IPv4Network('10.0.0.0/8'),
            IPv4Network('172.16.0.0/12'),
            IPv4Network('192.168.0.0/16')
        ]
        
        is_private = any(ip in network for network in private_ranges)
        if is_private:
            return 0  # Private IP addresses are low risk for remote connections
        
        # Check if IP has been associated with failed logins recently
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=7)
        failed_login_count = (
            db.query(func.count(LoginHistory.id))
            .filter(
                LoginHistory.ip_address == ip_address,
                LoginHistory.success == False,
                LoginHistory.timestamp > cutoff_date
            )
            .scalar() or 0
        )
        
        # Calculate risk based on failed attempts from this IP
        if failed_login_count > 20:
            return 100  # Very high risk
        elif failed_login_count > 10:
            return 75  # High risk
        elif failed_login_count > 5:
            return 50  # Medium risk
        elif failed_login_count > 0:
            return 25  # Low risk
        
        return 0  # No recent failed attempts from this IP
        
    except Exception:
        # If we can't parse the IP or something else goes wrong, assign moderate risk
        return 50

def assess_device_risk(db: Session, user_id: int, user_agent: str) -> int:
    """
    Assess risk based on the device/user agent being used.
    Returns a risk score from 0-100.
    """
    # Implementation would depend on how you track devices
    # This is a simplified version
    
    # Check if this user agent has been used by this user before
    user_devices = (
        db.query(Device)
        .filter(
            Device.user_id == user_id,
            Device.user_agent == user_agent
        )
        .all()
    )
    
    if user_devices:
        # User has used this device before, low risk
        return 0
    
    # Check how recently the user was created
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        account_age_days = (datetime.datetime.utcnow() - user.created_at).days
        
        if account_age_days < 1:
            # Very new account with new device - higher risk
            return 75
        elif account_age_days < 7:
            # Relatively new account with new device - medium risk
            return 50
        elif account_age_days < 30:
            # Established account with new device - lower risk
            return 25
    
    # Default risk for new device
    return 50

def assess_time_based_risk(db: Session, user_id: int, login_timestamp: datetime) -> int:
    """
    Assess risk based on the time of the login.
    Returns a risk score from 0-100.
    """
    # Get user's typical login times (hour of day)
    cutoff_date = login_timestamp - datetime.timedelta(days=30)
    login_times = (
        db.query(LoginHistory)
        .filter(
            LoginHistory.user_id == user_id,
            LoginHistory.success == True,
            LoginHistory.timestamp > cutoff_date
        )
        .all()
    )
    
    if not login_times:
        # No history available
        return 30
    
    # Extract hour of day from login timestamps
    login_hours = [login.timestamp.hour for login in login_times]
    
    # Count occurrences of each hour
    hour_counts = {}
    for hour in login_hours:
        hour_counts[hour] = hour_counts.get(hour, 0) + 1
    
    # Check if current login hour has been used before
    current_hour = login_timestamp.hour
    if current_hour in hour_counts:
        # User has logged in during this hour before
        # Calculate risk inversely proportional to frequency
        frequency = hour_counts[current_hour] / len(login_times)
        if frequency > 0.2:
            return 0  # Common login time, low risk
        elif frequency > 0.1:
            return 10  # Occasional login time, slight risk
        else:
            return 25  # Rare login time, moderate risk
    else:
        # User has never logged in during this hour before
        return 50  # Unusual login time, higher risk 