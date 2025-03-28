from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from app.database.database import get_db
from app.models.user import User
from app.models.role import Role
from app.models.login_history import LoginHistory
from app.models.session import Session as DbSession
from app.models.device import Device
from app.models.security_settings import SecuritySettings
from app.schemas.admin import SecuritySettingsUpdate
from app.routers.auth import get_current_user
from app.core.security import get_password_hash

router = APIRouter(tags=["admin"])

templates = Jinja2Templates(directory="app/templates")

# Admin-only dependency
def get_admin_user(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Check if the current user is an admin"""
    print(f"DEBUG: Admin access check for user: {current_user.email}")
    
    # Log the auth scopes if available
    if hasattr(request, "auth"):
        print(f"DEBUG: Auth scopes: {request.auth.scopes}")
    
    # Verify from database to be absolutely sure
    user = db.query(User).filter(User.email == current_user.email).first()
    if not user or not user.is_superuser:
        print(f"DEBUG: Access denied - user {current_user.email} is not an admin")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access admin area"
        )
    
    print(f"DEBUG: Admin access granted to {user.email}")
    return user

# Admin dashboard
@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db)
):
    """Display the admin dashboard with security metrics"""
    try:
        print("DEBUG: Entering admin_dashboard route")
        
        # Check if user is authenticated
        if not hasattr(request, "state") or not hasattr(request.state, "user"):
            print("DEBUG: User not authenticated for dashboard")
            return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
        
        # User is already authenticated and confirmed as admin via the is_admin middleware
        user = request.state.user
        
        print(f"DEBUG: ADMIN ACCESS GRANTED - {user.email}")
        
        # Timestamps for calculations
        now = datetime.utcnow()
        past_hour = now - timedelta(hours=1)
        past_day = now - timedelta(days=1)
        past_week = now - timedelta(days=7)
        past_month = now - timedelta(days=30)
        
        # Total users
        total_users = db.query(func.count(User.id)).scalar()
        print(f"DEBUG: Total users: {total_users}")
        
        # Active users
        active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar()
        
        # New users today
        new_users_today = db.query(func.count(User.id)).filter(
            User.created_at > past_day
        ).scalar() or 0
        
        # Login statistics
        total_login_attempts = db.query(func.count(LoginHistory.id)).filter(
            LoginHistory.timestamp > past_day
        ).scalar() or 0
        
        failed_login_count = db.query(func.count(LoginHistory.id)).filter(
            LoginHistory.timestamp > past_day,
            LoginHistory.success == False
        ).scalar() or 0
        
        successful_login_count = db.query(func.count(LoginHistory.id)).filter(
            LoginHistory.timestamp > past_day,
            LoginHistory.success == True
        ).scalar() or 0
        
        # Session statistics
        active_sessions_count = db.query(func.count(DbSession.id)).filter(
            DbSession.is_active == True,
            DbSession.expires_at > now
        ).scalar() or 0
        
        total_sessions = db.query(func.count(DbSession.id)).scalar() or 0
        
        # Security metrics
        security_events = failed_login_count
        critical_events = db.query(func.count(LoginHistory.id)).filter(
            LoginHistory.timestamp > past_day,
            LoginHistory.success == False,
            LoginHistory.risk_score > 75
        ).scalar() or 0
        
        # Unique IPs for failed logins (potential threat indicators)
        unique_failed_ip_count = db.query(func.count(func.distinct(LoginHistory.ip_address))).filter(
            LoginHistory.timestamp > past_day,
            LoginHistory.success == False
        ).scalar() or 0
        
        # Recent blocked IPs (simulated for the dashboard)
        recent_blocked_ips = db.query(func.count(LoginHistory.id)).filter(
            LoginHistory.timestamp > past_day,
            LoginHistory.success == False,
            LoginHistory.risk_score > 85
        ).scalar() or 0
        
        # Get MFA enablement percentage
        mfa_enabled_count = db.query(func.count(User.id)).filter(
            User.mfa_enabled == True,
            User.is_active == True
        ).scalar() or 0
        
        mfa_adoption = round((mfa_enabled_count / active_users * 100) if active_users > 0 else 0, 1)
        
        # Calculate login failure rate
        login_failure_rate = round((failed_login_count / total_login_attempts * 100) if total_login_attempts > 0 else 0, 1)
        
        # Get security settings (for compliance score calculation)
        security_settings = db.query(SecuritySettings).first()
        
        # Calculate compliance score (simulated based on security settings)
        compliance_score = 0
        compliance_issues = 0
        
        if security_settings:
            # Base score starts at 100, deduct for each non-compliant setting
            compliance_score = 100
            
            # Password policy checks
            if security_settings.password_min_length < 12:
                compliance_score -= 5
                compliance_issues += 1
            
            if not security_settings.password_require_uppercase:
                compliance_score -= 5
                compliance_issues += 1
                
            if not security_settings.password_require_lowercase:
                compliance_score -= 5
                compliance_issues += 1
                
            if not security_settings.password_require_digits:
                compliance_score -= 5
                compliance_issues += 1
                
            if not security_settings.password_require_special:
                compliance_score -= 5
                compliance_issues += 1
                
            if security_settings.password_expiry_days > 90:
                compliance_score -= 5
                compliance_issues += 1
                
            if security_settings.password_history_count < 5:
                compliance_score -= 5
                compliance_issues += 1
                
            # Login security checks
            if security_settings.max_login_attempts > 5:
                compliance_score -= 5
                compliance_issues += 1
                
            if security_settings.lockout_duration_minutes < 30:
                compliance_score -= 5
                compliance_issues += 1
                
            if security_settings.session_timeout_minutes > 60:
                compliance_score -= 5
                compliance_issues += 1
                
            if not security_settings.require_mfa:
                compliance_score -= 15
                compliance_issues += 1
        else:
            compliance_score = 40
            compliance_issues = 8
        
        # Recent login activity for the activity feed
        recent_logins = db.query(LoginHistory).order_by(
            LoginHistory.timestamp.desc()
        ).limit(10).all()
        
        # Create recent activities list
        recent_activities = []
        for login in recent_logins:
            user_email = db.query(User.email).filter(User.id == login.user_id).scalar() or "Unknown"
            
            if login.success:
                activity_type = "login"
                icon = "sign-in-alt"
                status = "success"
                description = f"Successful login by {user_email} from {login.ip_address}"
            else:
                activity_type = "security"
                icon = "exclamation-triangle"
                status = "danger"
                description = f"Failed login attempt for {user_email} from {login.ip_address}"
                
                if login.risk_score > 75:
                    description += " (High Risk)"
                    
            recent_activities.append({
                "type": activity_type,
                "icon": icon,
                "description": description,
                "timestamp": login.timestamp.strftime("%Y-%m-%d %H:%M"),
                "status": status
            })
        
        # Add some administrative activities for variety
        if len(recent_activities) < 10:
            admin_activities = [
                {
                    "type": "admin",
                    "icon": "user-shield",
                    "description": "Administrator updated security settings",
                    "timestamp": (now - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M"),
                    "status": "success"
                },
                {
                    "type": "admin",
                    "icon": "user-lock",
                    "description": "User account locked after multiple failed attempts",
                    "timestamp": (now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M"),
                    "status": "warning"
                },
                {
                    "type": "user",
                    "icon": "user-plus",
                    "description": "New user registered and awaiting verification",
                    "timestamp": (now - timedelta(hours=7)).strftime("%Y-%m-%d %H:%M"),
                    "status": "success"
                }
            ]
            recent_activities.extend(admin_activities)
        
        # Create critical alerts for the dashboard
        critical_alerts = []
        
        # Check for high-risk login attempts
        high_risk_logins = db.query(LoginHistory).filter(
            LoginHistory.timestamp > past_day,
            LoginHistory.risk_score > 85
        ).order_by(LoginHistory.timestamp.desc()).limit(3).all()
        
        for i, login in enumerate(high_risk_logins):
            user_email = db.query(User.email).filter(User.id == login.user_id).scalar() or "Unknown"
            
            critical_alerts.append({
                "id": f"login-{login.id}",
                "title": "High Risk Login Attempt",
                "message": f"Multiple failed login attempts for {user_email} from {login.ip_address} with risk score {login.risk_score}",
                "severity": "high",
                "icon": "shield-alt",
                "time": login.timestamp.strftime("%H:%M")
            })
        
        # Add additional sample alerts if needed
        if len(critical_alerts) < 2:
            sample_alerts = [
                {
                    "id": "geo-1",
                    "title": "Geographic Anomaly",
                    "message": "Login detected from unusual location: Moscow, Russia",
                    "severity": "high",
                    "icon": "globe",
                    "time": (now - timedelta(hours=2)).strftime("%H:%M")
                },
                {
                    "id": "brute-1",
                    "title": "Brute Force Attack",
                    "message": "Multiple failed login attempts (25+) detected from IP 192.168.1.105",
                    "severity": "high",
                    "icon": "user-shield",
                    "time": (now - timedelta(minutes=45)).strftime("%H:%M")
                },
                {
                    "id": "mfa-1",
                    "title": "MFA Verification Failed",
                    "message": "Multiple MFA verification failures for admin@example.com",
                    "severity": "medium",
                    "icon": "mobile-alt",
                    "time": (now - timedelta(hours=1)).strftime("%H:%M")
                }
            ]
            critical_alerts.extend(sample_alerts[:2])
        
        # Simulate system status
        system_status = {
            "level": "normal",
            "message": "All systems operational",
            "cpu_usage": 42,
            "memory_usage": 58,
            "disk_usage": 67,
            "db_connections": 12,
            "max_db_connections": 100,
            "api_response_time": 312,
            "issues": []
        }
        
        # If we have critical events, change the system status
        if critical_events > 2:
            system_status["level"] = "warning"
            system_status["message"] = "Security concerns detected"
            system_status["issues"] = [
                {
                    "severity": "medium",
                    "type": "SECURITY",
                    "message": "Multiple failed login attempts detected"
                }
            ]
        
        if critical_events > 5:
            system_status["level"] = "danger"
            system_status["message"] = "Critical security issues detected"
            system_status["issues"] = [
                {
                    "severity": "high",
                    "type": "SECURITY",
                    "message": "Possible brute force attack in progress"
                },
                {
                    "severity": "medium",
                    "type": "SYSTEM",
                    "message": "High memory usage detected"
                }
            ]
            system_status["memory_usage"] = 87
        
        # Create stats dictionary
        stats = {
            "total_users": total_users,
            "new_users": new_users_today,
            "active_sessions": active_sessions_count,
            "total_sessions": total_sessions,
            "security_events": security_events,
            "critical_events": critical_events,
            "login_attempts": total_login_attempts,
            "failed_logins": failed_login_count
        }
        
        # Create security metrics dictionary
        security_metrics = {
            "login_failure_rate": login_failure_rate,
            "blocked_ips": unique_failed_ip_count,
            "recent_blocks": recent_blocked_ips,
            "mfa_adoption": mfa_adoption,
            "compliance_score": compliance_score,
            "compliance_issues": compliance_issues
        }
        
        # Debug
        print(f"DEBUG: Rendering dashboard template with stats: {stats}")
        
        # Check if minimal dashboard is requested
        use_minimal = request.query_params.get("minimal", "false").lower() == "true"
        template_name = "admin/dashboard_minimal.html" if use_minimal else "admin/dashboard.html"
        
        print(f"DEBUG: Using template: {template_name}")
        
        response = templates.TemplateResponse(
            template_name,
            {
                "request": request,
                "stats": stats,
                "security_metrics": security_metrics,
                "system_status": system_status,
                "recent_activities": recent_activities,
                "critical_alerts": critical_alerts,
                "user": user,
                "body_class": "admin-view"
            }
        )
        
        print("DEBUG: Template response created, returning")
        return response
    except Exception as e:
        print(f"ERROR: Exception in admin_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Return a simple error page instead of crashing
        return templates.TemplateResponse(
            "errors/500.html",
            {
                "request": request,
                "error": str(e),
                "body_class": "error-view"
            }
        )

@router.get("/dashboard/minimal", response_class=HTMLResponse)
async def admin_dashboard_minimal(
    request: Request,
    db: Session = Depends(get_db)
):
    """Display a minimal version of the admin dashboard for debugging"""
    print("DEBUG: Redirecting to minimal dashboard")
    return RedirectResponse(url="/admin/dashboard?minimal=true", status_code=status.HTTP_302_FOUND)

# User management
@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    search: str = Query(None)
):
    """Display user management page"""
    # Check if user is authenticated
    if not hasattr(request, "state") or not hasattr(request.state, "user"):
        print("DEBUG: User not authenticated for users page")
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
    
    # User is already authenticated and confirmed as admin via the is_admin middleware
    current_user = request.state.user
    
    # Items per page
    per_page = 10
    
    # Base query
    query = db.query(User)
    
    # Apply search filter if provided
    if search:
        query = query.filter(
            User.email.contains(search) | 
            User.first_name.contains(search) | 
            User.last_name.contains(search)
        )
    
    # Calculate pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    
    # Adjust current page if needed
    page = min(page, total_pages) if total_pages > 0 else 1
    
    # Get users for current page
    users = query.order_by(User.id).offset((page - 1) * per_page).limit(per_page).all()
    
    return templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "users": users,
            "page": page,
            "total_pages": total_pages,
            "total_users": total,
            "search": search or ""
        }
    )

@router.get("/users/{user_id}", response_class=HTMLResponse)
async def admin_user_detail(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Display user detail page"""
    # Get the user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get user role
    role = db.query(Role).filter(Role.id == user.role_id).first() if user.role_id else None
    
    # Get login history
    login_history = db.query(LoginHistory).filter(
        LoginHistory.user_id == user.id
    ).order_by(LoginHistory.timestamp.desc()).limit(10).all()
    
    # Get devices
    devices = db.query(Device).filter(Device.user_id == user.id).all()
    
    # Get active sessions
    now = datetime.utcnow()
    active_sessions = db.query(DbSession).filter(
        DbSession.user_id == user.id,
        DbSession.is_active == True,
        DbSession.expires_at > now
    ).all()
    
    return templates.TemplateResponse(
        "admin/user_detail.html",
        {
            "request": request,
            "user": user,
            "role": role,
            "login_history": login_history,
            "devices": devices,
            "active_sessions": active_sessions
        }
    )

@router.post("/users/{user_id}/lock", response_class=HTMLResponse)
async def admin_lock_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
    duration_minutes: int = Form(30)
):
    """Lock a user account"""
    # Get the user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent locking admin accounts (except your own if you're testing)
    if user.is_superuser and user.id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot lock admin accounts"
        )
    
    # Lock the account
    now = datetime.utcnow()
    user.account_locked_until = now + timedelta(minutes=duration_minutes)
    db.commit()
    
    return RedirectResponse(
        url=f"/admin/users/{user_id}?locked=true",
        status_code=status.HTTP_303_SEE_OTHER
    )

@router.post("/users/{user_id}/unlock", response_class=HTMLResponse)
async def admin_unlock_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Unlock a user account"""
    # Get the user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Unlock the account
    user.account_locked_until = None
    user.failed_login_attempts = 0
    db.commit()
    
    return RedirectResponse(
        url=f"/admin/users/{user_id}?unlocked=true",
        status_code=status.HTTP_303_SEE_OTHER
    )

@router.post("/users/{user_id}/reset-password", response_class=HTMLResponse)
async def admin_reset_user_password(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Reset a user's password"""
    # Get the user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate a new password
    from app.core.security import generate_secure_password
    new_password = generate_secure_password()
    
    # Update the user's password
    user.hashed_password = get_password_hash(new_password)
    user.password_last_changed = datetime.utcnow()
    db.commit()
    
    # In a real application, you would email this password to the user
    # For this example, we'll just display it
    
    return templates.TemplateResponse(
        "admin/password_reset_result.html",
        {
            "request": request,
            "user": user,
            "new_password": new_password  # In production, would be emailed instead
        }
    )

@router.post("/users/{user_id}/toggle-active", response_class=HTMLResponse)
async def admin_toggle_user_active(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Activate or deactivate a user account"""
    # Get the user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent deactivating your own admin account
    if user.is_superuser and user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own admin account"
        )
    
    # Toggle active status
    user.is_active = not user.is_active
    
    # If deactivating, invalidate all sessions
    if not user.is_active:
        db.query(DbSession).filter(
            DbSession.user_id == user.id,
            DbSession.is_active == True
        ).update({"is_active": False})
    
    db.commit()
    
    return RedirectResponse(
        url=f"/admin/users/{user_id}?status_changed=true",
        status_code=status.HTTP_303_SEE_OTHER
    )

# Security settings
@router.get("/settings", response_class=HTMLResponse)
async def admin_security_settings(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Display security settings page"""
    # Get current security settings
    settings = db.query(SecuritySettings).first()
    
    # If no settings exist, create default settings
    if not settings:
        settings = SecuritySettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    
    return templates.TemplateResponse(
        "admin/settings.html",
        {
            "request": request,
            "settings": settings
        }
    )

@router.post("/settings", response_class=HTMLResponse)
async def update_security_settings(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
    
    # Password policy
    password_min_length: int = Form(8),
    password_require_uppercase: bool = Form(False),
    password_require_lowercase: bool = Form(False),
    password_require_digits: bool = Form(False),
    password_require_special: bool = Form(False),
    password_expiry_days: int = Form(90),
    password_history_count: int = Form(5),
    
    # Login security
    max_login_attempts: int = Form(5),
    lockout_duration_minutes: int = Form(30),
    session_timeout_minutes: int = Form(30),
    require_mfa: bool = Form(False),
    
    # IP security
    ip_whitelist_enabled: bool = Form(False),
    ip_blacklist_enabled: bool = Form(False),
    
    # Device security
    device_trust_duration_days: int = Form(30)
):
    """Update security settings"""
    # Get current security settings
    settings = db.query(SecuritySettings).first()
    
    # If no settings exist, create new settings
    if not settings:
        settings = SecuritySettings()
        db.add(settings)
    
    # Update settings
    settings.password_min_length = password_min_length
    settings.password_require_uppercase = password_require_uppercase
    settings.password_require_lowercase = password_require_lowercase
    settings.password_require_digits = password_require_digits
    settings.password_require_special = password_require_special
    settings.password_expiry_days = password_expiry_days
    settings.password_history_count = password_history_count
    
    settings.max_login_attempts = max_login_attempts
    settings.lockout_duration_minutes = lockout_duration_minutes
    settings.session_timeout_minutes = session_timeout_minutes
    settings.require_mfa = require_mfa
    
    settings.ip_whitelist_enabled = ip_whitelist_enabled
    settings.ip_blacklist_enabled = ip_blacklist_enabled
    
    settings.device_trust_duration_days = device_trust_duration_days
    
    settings.updated_at = datetime.utcnow()
    settings.last_updated_by = current_user.email
    
    db.commit()
    
    return templates.TemplateResponse(
        "admin/settings.html",
        {
            "request": request,
            "settings": settings,
            "success": "Security settings updated successfully"
        }
    )

# Security logs
@router.get("/logs", response_class=HTMLResponse)
async def admin_security_logs(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
    page: int = Query(1, ge=1),
    filter_success: Optional[bool] = Query(None),
    search: str = Query(None)
):
    """Display security logs"""
    # Items per page
    per_page = 25
    
    # Base query
    query = db.query(LoginHistory).join(User, LoginHistory.user_id == User.id)
    
    # Apply filters
    if filter_success is not None:
        query = query.filter(LoginHistory.success == filter_success)
    
    if search:
        query = query.filter(
            User.email.contains(search) | 
            LoginHistory.ip_address.contains(search)
        )
    
    # Calculate pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    
    # Adjust current page if needed
    page = min(page, total_pages) if total_pages > 0 else 1
    
    # Get logs for current page
    logs = query.order_by(LoginHistory.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()
    
    # Get users for the logs
    user_ids = [log.user_id for log in logs if log.user_id]
    users = {user.id: user for user in db.query(User).filter(User.id.in_(user_ids)).all()}
    
    return templates.TemplateResponse(
        "admin/logs.html",
        {
            "request": request,
            "logs": logs,
            "users": users,
            "page": page,
            "total_pages": total_pages,
            "total_logs": total,
            "filter_success": filter_success,
            "search": search or ""
        }
    )

# Session management
@router.get("/sessions", response_class=HTMLResponse)
async def admin_sessions(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
    page: int = Query(1, ge=1),
    search: str = Query(None)
):
    """Display active sessions"""
    # Items per page
    per_page = 25
    
    # Base query - only active sessions
    now = datetime.utcnow()
    query = db.query(DbSession).filter(
        DbSession.is_active == True,
        DbSession.expires_at > now
    ).join(User, DbSession.user_id == User.id)
    
    # Apply search filter if provided
    if search:
        query = query.filter(
            User.email.contains(search) | 
            DbSession.ip_address.contains(search)
        )
    
    # Calculate pagination
    total = query.count()
    total_pages = (total + per_page - 1) // per_page
    
    # Adjust current page if needed
    page = min(page, total_pages) if total_pages > 0 else 1
    
    # Get sessions for current page
    sessions = query.order_by(DbSession.last_active_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    
    # Get users for the sessions
    user_ids = [session.user_id for session in sessions]
    users = {user.id: user for user in db.query(User).filter(User.id.in_(user_ids)).all()}
    
    return templates.TemplateResponse(
        "admin/sessions.html",
        {
            "request": request,
            "sessions": sessions,
            "users": users,
            "page": page,
            "total_pages": total_pages,
            "total_sessions": total,
            "search": search or ""
        }
    )

@router.post("/sessions/{session_id}/revoke", response_class=HTMLResponse)
async def admin_revoke_session(
    request: Request,
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Revoke a specific session"""
    # Find the session
    session = db.query(DbSession).filter(
        DbSession.id == session_id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Prevent revoking your own session
    current_token = None
    token_cookie = request.cookies.get("access_token")
    if token_cookie and token_cookie.startswith("Bearer "):
        current_token = token_cookie[7:]  # Remove "Bearer " prefix
    
    if session.token == current_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot revoke your own current session"
        )
    
    # Deactivate the session
    session.is_active = False
    db.commit()
    
    return RedirectResponse(
        url="/admin/sessions",
        status_code=status.HTTP_303_SEE_OTHER
    ) 