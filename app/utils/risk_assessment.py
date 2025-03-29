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

def calculate_overall_risk_score(db: Session, stats: dict, security_metrics: dict):
    """
    Calculate the overall risk score based on multiple risk factors.
    The score is normalized to a scale of 0-100, where:
    0-30: Low risk
    31-60: Medium risk
    61-85: High risk
    86-100: Critical risk
    
    Risk factors include:
    - Brute force attempts
    - Failed login patterns
    - Geographic anomalies
    - Account takeover attempts
    - Suspicious IP activities
    - Rate of password changes
    - Session anomalies
    - Data access patterns
    """
    factors = {}
    risk_score = 0
    total_weight = 0
    
    # Brute force risk - weight: 25%
    brute_force_risk = calculate_brute_force_risk(db, stats, security_metrics)
    factors['brute_force_risk'] = brute_force_risk
    risk_score += brute_force_risk * 0.25
    total_weight += 0.25
    
    # Account takeover risk - weight: 20%
    account_takeover_risk = calculate_account_takeover_risk(db, stats, security_metrics)
    factors['account_takeover_risk'] = account_takeover_risk
    risk_score += account_takeover_risk * 0.20
    total_weight += 0.20
    
    # Data breach risk - weight: 20%
    data_breach_risk = calculate_data_breach_risk(db, stats, security_metrics)
    factors['data_breach_risk'] = data_breach_risk
    risk_score += data_breach_risk * 0.20
    total_weight += 0.20
    
    # Session anomaly risk - weight: 15%
    session_anomaly_risk = calculate_session_anomaly_risk(db, stats, security_metrics)
    factors['session_anomaly_risk'] = session_anomaly_risk
    risk_score += session_anomaly_risk * 0.15
    total_weight += 0.15
    
    # Geographic anomaly risk - weight: 10%
    geo_anomaly_risk = calculate_geo_anomaly_risk(db, stats, security_metrics)
    factors['geo_anomaly_risk'] = geo_anomaly_risk
    risk_score += geo_anomaly_risk * 0.10
    total_weight += 0.10
    
    # System health risk - weight: 10%
    system_health_risk = calculate_system_health_risk(db, stats, security_metrics)
    factors['system_health_risk'] = system_health_risk
    risk_score += system_health_risk * 0.10
    total_weight += 0.10
    
    # Normalize score to account for any missing factors
    if total_weight > 0:
        normalized_score = round((risk_score / total_weight) * 100)
    else:
        normalized_score = 0
    
    # Count how many factors were calculated
    risk_factors_count = sum(1 for factor in factors.values() if factor is not None)
    
    # Update security metrics with individual risk factors and overall score
    security_metrics.update(factors)
    security_metrics['overall_risk_score'] = normalized_score
    security_metrics['risk_factors_count'] = risk_factors_count
    
    return normalized_score

def calculate_brute_force_risk(db: Session, stats: dict, security_metrics: dict):
    """
    Calculate risk score for brute force attacks based on:
    - Number of failed login attempts
    - Number of unique IPs with failed attempts
    - Distribution pattern of failed attempts
    - Rate of failed attempts over time
    """
    try:
        # Extract needed metrics
        failed_logins_day = stats.get('failed_logins_day', 0)
        total_logins_day = stats.get('total_logins_day', 1)  # Avoid division by zero
        unique_failed_ips = security_metrics.get('unique_failed_ips_day', 0)
        login_failure_rate = security_metrics.get('login_failure_rate_day', 0)
        
        # Count blocked IPs (from security_metrics or get from the database)
        blocked_ips_count = security_metrics.get('blocked_ips_count', 0)
        security_metrics['blocked_ips_count'] = blocked_ips_count
        
        # Base score calculation
        if total_logins_day <= 5:  # Very low activity, base risk on absolute numbers
            base_score = min(100, failed_logins_day * 10)
        else:
            # Higher failure rate = higher risk
            base_score = min(100, login_failure_rate * 1.5)
        
        # Adjust for unique IPs (distributed attacks are more concerning)
        if unique_failed_ips > 0:
            ip_factor = min(2.0, 1 + (unique_failed_ips / 10))
            base_score = min(100, base_score * ip_factor)
        
        # Reduce score if many IPs are already blocked (threat partially mitigated)
        if blocked_ips_count > 0:
            mitigation_factor = max(0.5, 1 - (blocked_ips_count / (unique_failed_ips + blocked_ips_count + 1)) * 0.5)
            base_score *= mitigation_factor
        
        # Final normalization to 0-100 range
        return round(base_score)
    except Exception as e:
        print(f"Error calculating brute force risk: {e}")
        return 20  # Default moderate-low value in case of calculation error

def calculate_account_takeover_risk(db: Session, stats: dict, security_metrics: dict):
    """
    Calculate risk of account takeover attempts based on:
    - Unusual login locations
    - Multiple password reset attempts
    - Failed MFA verifications
    - Unusual login times
    - Unusual device changes
    """
    try:
        # Extract needed metrics
        failed_logins_day = stats.get('failed_logins_day', 0)
        suspicious_logins_count = security_metrics.get('suspicious_logins_count', 0)
        failed_mfa_count = security_metrics.get('failed_mfa_attempts', 0)
        password_reset_attempts = security_metrics.get('password_reset_attempts', 0)
        unusual_device_logins = security_metrics.get('unusual_device_logins', 0)
        
        # Update security metrics if we calculated new values
        security_metrics['suspicious_logins_count'] = suspicious_logins_count
        
        # Base risk score from suspicious activities
        base_score = 0
        
        # Weight suspicious logins heavily
        if suspicious_logins_count > 0:
            base_score += min(50, suspicious_logins_count * 10)
        
        # Failed MFA is a strong indicator
        if failed_mfa_count > 0:
            base_score += min(30, failed_mfa_count * 15)
        
        # Password reset attempts
        if password_reset_attempts > 0:
            base_score += min(20, password_reset_attempts * 10)
        
        # Unusual device logins
        if unusual_device_logins > 0:
            base_score += min(30, unusual_device_logins * 15)
        
        # Factor in general failed logins (but less weight)
        base_score += min(20, failed_logins_day * 2)
        
        # Cap and normalize the final score
        return min(100, round(base_score))
    except Exception as e:
        print(f"Error calculating account takeover risk: {e}")
        return 30  # Default moderate value in case of calculation error

def calculate_data_breach_risk(db: Session, stats: dict, security_metrics: dict):
    """
    Calculate risk of data breach based on:
    - Unusual data access patterns
    - Volume of data accessed
    - Sensitive data access attempts
    - Unusual user permissions changes
    """
    try:
        # Extract needed metrics
        unusual_access_count = security_metrics.get('unusual_access_count', 0)
        sensitive_data_requests = security_metrics.get('sensitive_data_requests', 0)
        permission_changes = security_metrics.get('permission_changes', 0)
        data_export_volume = security_metrics.get('data_export_volume', 0)
        
        # Update security metrics
        security_metrics['unusual_access_count'] = unusual_access_count
        
        # Base risk calculation
        base_score = 0
        
        # Unusual access patterns are a major indicator
        if unusual_access_count > 0:
            base_score += min(50, unusual_access_count * 10)
        
        # Sensitive data requests
        if sensitive_data_requests > 0:
            base_score += min(30, sensitive_data_requests * 15)
        
        # Permission changes (could indicate privilege escalation)
        if permission_changes > 0:
            base_score += min(40, permission_changes * 20)
        
        # Data export volume (could indicate exfiltration)
        if data_export_volume > 0:
            # Scale based on volume (e.g., in MB)
            volume_score = min(30, math.log(data_export_volume + 1, 10) * 10)
            base_score += volume_score
        
        # Cap and normalize
        return min(100, round(base_score))
    except Exception as e:
        print(f"Error calculating data breach risk: {e}")
        return 25  # Default moderate-low value in case of calculation error

def calculate_session_anomaly_risk(db: Session, stats: dict, security_metrics: dict):
    """
    Calculate risk based on session anomalies:
    - Concurrent sessions from different locations
    - Unusual session durations
    - Session hijacking attempts
    - Unusual activity within sessions
    """
    try:
        # Extract needed metrics
        active_sessions = stats.get('active_sessions', 0)
        concurrent_session_anomalies = security_metrics.get('concurrent_session_anomalies', 0)
        session_duration_anomalies = security_metrics.get('session_duration_anomalies', 0)
        session_hijack_attempts = security_metrics.get('session_hijack_attempts', 0)
        
        # Base risk calculation
        base_score = 0
        
        # Concurrent session anomalies
        if concurrent_session_anomalies > 0:
            base_score += min(50, concurrent_session_anomalies * 25)
        
        # Session duration anomalies
        if session_duration_anomalies > 0:
            base_score += min(30, session_duration_anomalies * 15)
        
        # Session hijacking attempts (high severity)
        if session_hijack_attempts > 0:
            base_score += min(70, session_hijack_attempts * 35)
        
        # Factor in total active sessions volume
        if active_sessions > 50:  # Arbitrary threshold for "high" session count
            volume_factor = min(1.5, 1 + (active_sessions - 50) / 100)
            base_score = min(100, base_score * volume_factor)
        
        # Cap and normalize
        return min(100, round(base_score))
    except Exception as e:
        print(f"Error calculating session anomaly risk: {e}")
        return 15  # Default low-moderate value in case of calculation error

def calculate_geo_anomaly_risk(db: Session, stats: dict, security_metrics: dict):
    """
    Calculate risk based on geographic anomalies:
    - Login attempts from unusual countries
    - Login velocity anomalies (impossible travel)
    - Geographic distribution of failed attempts
    """
    try:
        # Extract needed metrics
        geo_anomalies = security_metrics.get('geo_anomalies', 0)
        impossible_travel_events = security_metrics.get('impossible_travel_events', 0)
        high_risk_country_logins = security_metrics.get('high_risk_country_logins', 0)
        
        # Base risk calculation
        base_score = 0
        
        # General geographic anomalies
        if geo_anomalies > 0:
            base_score += min(40, geo_anomalies * 10)
        
        # Impossible travel is a strong indicator
        if impossible_travel_events > 0:
            base_score += min(60, impossible_travel_events * 30)
        
        # High-risk countries
        if high_risk_country_logins > 0:
            base_score += min(50, high_risk_country_logins * 25)
        
        # Cap and normalize
        return min(100, round(base_score))
    except Exception as e:
        print(f"Error calculating geographic anomaly risk: {e}")
        return 20  # Default moderate value in case of calculation error

def calculate_system_health_risk(db: Session, stats: dict, security_metrics: dict):
    """
    Calculate risk based on system health metrics:
    - CPU/Memory/Disk utilization (can affect security mechanisms)
    - Error rates in security services
    - Log storage capacity
    - System uptime (very long uptimes could indicate missing security patches)
    """
    try:
        # Extract system health metrics from security_metrics
        cpu_usage = security_metrics.get('cpu_usage', 0)
        memory_usage = security_metrics.get('memory_usage', 0)
        disk_usage = security_metrics.get('disk_usage', 0)
        system_uptime_days = security_metrics.get('system_uptime_days', 0)
        error_rate = security_metrics.get('security_service_error_rate', 0)
        
        # Base risk calculation
        base_score = 0
        
        # Resource utilization risks
        if cpu_usage > 80:
            base_score += 30  # High CPU usage can impact security services
        elif cpu_usage > 60:
            base_score += 15
            
        if memory_usage > 85:
            base_score += 25  # High memory usage can cause service failures
        elif memory_usage > 70:
            base_score += 15
            
        if disk_usage > 90:
            base_score += 40  # Critical disk usage affects logging and can cause system failure
        elif disk_usage > 75:
            base_score += 20
        
        # System uptime (high uptime may indicate missing patches)
        if system_uptime_days > 90:  # 3 months without reboot
            base_score += 35
        elif system_uptime_days > 30:  # 1 month without reboot
            base_score += 15
        
        # Error rates in security services
        if error_rate > 5:  # More than 5% error rate
            base_score += min(50, error_rate * 5)
        
        # Cap and normalize
        return min(100, round(base_score))
    except Exception as e:
        print(f"Error calculating system health risk: {e}")
        return 10  # Default low value in case of calculation error

def get_detailed_risk_assessment(db: Session, stats: dict, security_metrics: dict):
    """
    Generate a detailed risk assessment report with recommendations.
    This would typically be called after calculate_overall_risk_score.
    """
    # First ensure we have calculated all risks
    if 'overall_risk_score' not in security_metrics:
        calculate_overall_risk_score(db, stats, security_metrics)
    
    overall_score = security_metrics.get('overall_risk_score', 0)
    
    # Initialize report
    report = {
        "overall_risk_score": overall_score,
        "risk_category": get_risk_category(overall_score),
        "timestamp": datetime.now().isoformat(),
        "risk_factors": [],
        "recommendations": []
    }
    
    # Process each risk factor
    factor_details = [
        {
            "name": "Brute Force Risk", 
            "key": "brute_force_risk",
            "high_rec": "Implement progressive delays and advanced rate limiting.",
            "med_rec": "Review and strengthen rate limiting policies.",
            "low_rec": "Continue monitoring login attempt patterns."
        },
        {
            "name": "Account Takeover Risk", 
            "key": "account_takeover_risk",
            "high_rec": "Enforce MFA for all users and implement advanced behavioral analytics.",
            "med_rec": "Encourage MFA adoption and review account activity alerts.",
            "low_rec": "Monitor unusual login patterns."
        },
        {
            "name": "Data Breach Risk", 
            "key": "data_breach_risk",
            "high_rec": "Audit data access patterns and implement data loss prevention.",
            "med_rec": "Review permission models and sensitive data access controls.",
            "low_rec": "Continue monitoring data access patterns."
        },
        {
            "name": "Session Anomaly Risk", 
            "key": "session_anomaly_risk",
            "high_rec": "Implement advanced session validation and enforce strict timeouts.",
            "med_rec": "Review session management policies and concurrent session limits.",
            "low_rec": "Monitor for unusual session activities."
        },
        {
            "name": "Geographic Anomaly Risk", 
            "key": "geo_anomaly_risk",
            "high_rec": "Implement country blocking and require additional verification for unusual locations.",
            "med_rec": "Set alerts for logins from new locations and review travel patterns.",
            "low_rec": "Monitor geographic login distribution."
        },
        {
            "name": "System Health Risk", 
            "key": "system_health_risk",
            "high_rec": "Address resource constraints and schedule system maintenance immediately.",
            "med_rec": "Review system resource allocation and update schedules.",
            "low_rec": "Continue monitoring system health metrics."
        }
    ]
    
    # Generate factor-specific assessments and recommendations
    for factor in factor_details:
        score = security_metrics.get(factor["key"], 0)
        if score is None:
            continue
            
        category = get_risk_category(score)
        
        # Select appropriate recommendation based on risk level
        recommendation = factor["low_rec"]
        if category == "High" or category == "Critical":
            recommendation = factor["high_rec"]
        elif category == "Medium":
            recommendation = factor["med_rec"]
        
        # Add factor details to report
        report["risk_factors"].append({
            "name": factor["name"],
            "score": score,
            "category": category,
            "recommendation": recommendation
        })
        
        # Add to overall recommendations if medium risk or higher
        if category != "Low":
            report["recommendations"].append(f"{factor['name']}: {recommendation}")
    
    # Add general recommendations based on overall score
    if overall_score > 60:
        report["recommendations"].append("Consider initiating security incident response procedures.")
    if overall_score > 40:
        report["recommendations"].append("Schedule a comprehensive security review.")
    
    return report

def get_risk_category(score):
    """Determine risk category based on score"""
    if score >= 86:
        return "Critical"
    elif score >= 61:
        return "High"
    elif score >= 31:
        return "Medium"
    else:
        return "Low" 