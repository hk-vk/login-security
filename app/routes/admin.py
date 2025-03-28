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
    active_sessions = db.query(func.count(User.id)).filter(User.last_login > datetime.now() - timedelta(hours=1)).scalar()
    security_events = db.query(func.count(SecurityEvent.id)).scalar()
    critical_events = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.severity == "critical").scalar()
    
    # Get login attempts
    login_attempts = db.query(func.count(LoginAttempt.id)).scalar()
    failed_logins = db.query(func.count(LoginAttempt.id)).filter(LoginAttempt.success == False).scalar()
    
    # Get new users today
    new_users = db.query(func.count(User.id)).filter(
        User.created_at > datetime.now().date()
    ).scalar()
    
    # Get total sessions in last 24 hours
    total_sessions = db.query(func.count(LoginAttempt.id)).filter(
        LoginAttempt.timestamp > datetime.now() - timedelta(hours=24),
        LoginAttempt.success == True
    ).scalar()
    
    # Get recent activities
    recent_activities = []
    
    # Get recent login attempts
    recent_logins = db.query(LoginAttempt).order_by(LoginAttempt.timestamp.desc()).limit(5).all()
    for login in recent_logins:
        status = "success" if login.success else "error"
        recent_activities.append({
            "type": "login",
            "icon": "sign-in-alt",
            "description": f"Login attempt for user {login.username}",
            "timestamp": login.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "status": status
        })
    
    # Get recent security events
    recent_events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(5).all()
    for event in recent_events:
        status = "warning" if event.severity == "warning" else "error"
        recent_activities.append({
            "type": "security",
            "icon": "shield-alt",
            "description": event.description,
            "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "status": status
        })
    
    # Sort activities by timestamp
    recent_activities.sort(key=lambda x: datetime.strptime(x["timestamp"], "%Y-%m-%d %H:%M:%S"), reverse=True)
    recent_activities = recent_activities[:10]  # Keep only 10 most recent
    
    stats = {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "security_events": security_events,
        "critical_events": critical_events,
        "login_attempts": login_attempts,
        "failed_logins": failed_logins,
        "new_users": new_users,
        "total_sessions": total_sessions
    }
    
    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "stats": stats,
            "recent_activities": recent_activities,
            "current_user": current_user
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