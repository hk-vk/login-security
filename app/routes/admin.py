from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, List
import json
from datetime import datetime, timedelta

from ..dependencies import get_current_user, is_admin
from ..database import get_db
from ..models import User, LoginAttempt, SecurityEvent
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..utils.risk_assessment import calculate_overall_risk_score, get_detailed_risk_assessment

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(is_admin)]
)

templates = Jinja2Templates(directory="app/templates")

@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get basic stats
    total_users = db.query(func.count(User.id)).scalar()
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar()
    active_sessions = db.query(func.count(User.id)).filter(User.last_login > datetime.now() - timedelta(hours=1)).scalar()
    
    # Get login stats
    now = datetime.now()
    today = now.date()
    yesterday = today - timedelta(days=1)
    
    # Last 24 hours stats
    total_logins_day = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.timestamp > now - timedelta(hours=24)
    ).scalar()
    
    failed_logins_day = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.timestamp > now - timedelta(hours=24),
        LoginAttempt.success == False
    ).scalar()
    
    # Last hour stats
    failed_logins_hour = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.timestamp > now - timedelta(hours=1),
        LoginAttempt.success == False
    ).scalar()
    
    # Get new users today
    new_users_today = db.query(func.count(User.id)).filter(
        User.created_at > today
    ).scalar()
    
    # Get total sessions in last 24 hours
    total_sessions_day = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.timestamp > now - timedelta(hours=24),
        LoginAttempt.success == True
    ).scalar()
    
    # Get critical alerts (security events) that need attention
    critical_alerts = db.query(SecurityEvent).filter(
        SecurityEvent.severity.in_(["critical", "high"]),
    ).order_by(SecurityEvent.timestamp.desc()).limit(10).all()
    
    # Convert security events to dictionary format for the template
    critical_alerts_dicts = []
    for alert in critical_alerts:
        critical_alerts_dicts.append({
            "id": str(alert.id),
            "severity": alert.severity,
            "message": alert.description,
            "details": f"Detected from IP {alert.ip_address}" if alert.ip_address else "System generated alert",
            "timestamp": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "acknowledged": alert.acknowledged
        })
    
    # Get recent activities
    recent_activity = []
    
    # Get recent successful logins
    recent_logins = db.query(LoginAttempt).filter(
        LoginAttempt.success == True
    ).order_by(LoginAttempt.timestamp.desc()).limit(7).all()
    
    for login in recent_logins:
        user = db.query(User).filter(User.id == login.user_id).first()
        username = user.username if user else "Unknown"
        recent_activity.append({
            "action": "Successful Login",
            "user": username,
            "ip_address": login.ip_address,
            "timestamp": login.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    
    # Get security metrics
    unique_failed_ips_day = db.query(func.count(func.distinct(LoginAttempt.ip_address))).filter(
        LoginAttempt.timestamp > now - timedelta(hours=24),
        LoginAttempt.success == False
    ).scalar()
    
    # Calculate login failure rate
    login_failure_rate_day = 0
    if total_logins_day > 0:
        login_failure_rate_day = round((failed_logins_day / total_logins_day) * 100)
    
    # Get MFA adoption rate
    mfa_users = db.query(func.count(User.id)).filter(
        User.mfa_enabled == True,
        User.is_active == True
    ).scalar()
    
    mfa_adoption_rate = 0
    if active_users > 0:
        mfa_adoption_rate = round((mfa_users / active_users) * 100)
    
    # Compile security metrics
    security_metrics = {
        "unique_failed_ips_day": unique_failed_ips_day,
        "login_failure_rate_day": login_failure_rate_day,
        "mfa_adoption_rate": mfa_adoption_rate,
    }
    
    # Add system health information
    system_status = {
        "status": "Operational",
        "cpu_usage": 42,  # These would come from monitoring systems
        "memory_usage": 58,
        "disk_usage": 67,
        "api_response_time": 215,
        "api_response_time_percent": 43,
        "last_checked": now.strftime("%Y-%m-%d %H:%M:%S"),
        "db_size": "1.2 GB",
        "uptime": "7 days, 15 hours"
    }
    
    # Add system_uptime_days for risk calculation
    security_metrics["system_uptime_days"] = 7.625  # 7 days, 15 hours
    
    # Prepare stats dictionary
    stats = {
        "total_users": total_users,
        "active_users": active_users,
        "active_sessions": active_sessions,
        "total_logins_day": total_logins_day,
        "failed_logins_day": failed_logins_day,
        "failed_logins_hour": failed_logins_hour,
        "new_users_today": new_users_today,
        "total_sessions_day": total_sessions_day
    }
    
    # Calculate the overall risk score and other security metrics
    calculate_overall_risk_score(db, stats, security_metrics)
    
    # Get detailed risk assessment
    risk_assessment = get_detailed_risk_assessment(db, stats, security_metrics)
    
    # Prepare compliance status
    compliance = {
        "password_policy": {
            "compliant": True, 
            "details": "Meets requirements (12+ chars, mixed case, numbers, symbols)"
        },
        "data_retention": {
            "compliant": True, 
            "details": "Data retention policies in place and enforced"
        },
        "access_control": {
            "compliant": security_metrics.get("account_takeover_risk", 0) < 40, 
            "details": "Role-based access controls implemented"
        },
        "audit_logging": {
            "compliant": True, 
            "details": "All security events are being logged and retained"
        }
    }
    
    # Prepare vulnerability metrics
    vulnerability_metrics = {
        "critical_count": 0,
        "high_count": 2,
        "medium_count": 5,
        "low_count": 12
    }
    
    # Prepare chart data (this would be generated from actual database data)
    chart_data = {
        "userActivity": {
            "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "logins": [65, 72, 78, 69, 85, 42, 35],
            "registrations": [12, 8, 10, 7, 15, 5, 3]
        },
        "securityIncidents": {
            "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "failedLogins": [25, 18, 22, 19, 27, 15, 12],
            "blockedIPs": [5, 3, 7, 2, 8, 4, 1]
        },
        "geographicLogins": {
            "labels": ["United States", "United Kingdom", "Canada", "Germany", "France", "Other"],
            "counts": [250, 120, 85, 67, 42, 153]
        },
        "systemResources": {
            "labels": ["6:00", "9:00", "12:00", "15:00", "18:00", "21:00", "0:00"],
            "cpu": [35, 42, 65, 58, 72, 48, 30],
            "memory": [45, 52, 60, 68, 75, 62, 50]
        },
        "vulnerabilityTrends": {
            "labels": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
            "critical": [2, 1, 0, 0, 0, 0],
            "high": [8, 6, 4, 3, 2, 2],
            "medium": [15, 12, 10, 8, 7, 5],
            "low": [25, 22, 18, 15, 14, 12]
        }
    }
    
    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "admin_user": current_user,
            "stats": stats,
            "security_metrics": security_metrics,
            "system_status": system_status,
            "recent_activity": recent_activity,
            "critical_alerts": critical_alerts_dicts,
            "risk_assessment": risk_assessment,
            "compliance": compliance,
            "vulnerability_metrics": vulnerability_metrics,
            "chart_data": json.dumps(chart_data)
        }
    )

@router.get("/stats/user-activity")
async def get_user_activity(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get user activity for the last 7 days
    today = datetime.now().date()
    activity_data = []
    
    for i in range(7):
        date = today - timedelta(days=i)
        active_users = db.query(func.count(User.id)).filter(
            func.date(User.last_login) == date
        ).scalar()
        activity_data.append({
            "date": date.strftime("%Y-%m-%d"),
            "active_users": active_users
        })
    
    return activity_data

@router.get("/stats/security-incidents")
async def get_security_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get security incidents grouped by type
    incidents = db.query(
        SecurityEvent.event_type,
        func.count(SecurityEvent.id).label("count")
    ).group_by(SecurityEvent.event_type).all()
    
    return [{"type": incident[0], "count": incident[1]} for incident in incidents]

@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    users = db.query(User).all()
    return templates.TemplateResponse(
        "admin/users.html",
        {"request": request, "users": users, "current_user": current_user}
    )

@router.get("/security", response_class=HTMLResponse)
async def admin_security(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return templates.TemplateResponse(
        "admin/security.html",
        {"request": request, "current_user": current_user}
    )

@router.get("/logs", response_class=HTMLResponse)
async def admin_logs(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return templates.TemplateResponse(
        "admin/logs.html",
        {"request": request, "current_user": current_user}
    )

@router.get("/settings", response_class=HTMLResponse)
async def admin_settings(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return templates.TemplateResponse(
        "admin/settings.html",
        {"request": request, "current_user": current_user}
    )

@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(SecurityEvent).filter(SecurityEvent.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.acknowledged = True
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.now()
    db.commit()
    
    return {"status": "success", "message": "Alert acknowledged"} 