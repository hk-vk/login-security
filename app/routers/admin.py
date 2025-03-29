from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Query, BackgroundTasks
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, StreamingResponse
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
from app.utils.export import export_logs_to_csv, export_logs_to_json, generate_security_report, fetch_filter_logs
from app.utils.maintenance import create_database_backup, perform_log_cleanup, optimize_database, get_system_health

router = APIRouter(tags=["admin"])

templates = Jinja2Templates(directory="app/templates")

# REVISED Admin-only dependency
async def get_admin_user(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Dependency that checks if the user identified by the token is an active admin.
    Relies on get_current_user to handle token decoding and initial user identification.
    Returns the validated admin user object.
    """
    print(f"DEBUG (Dependency): Admin access check starting for user ID from token: {current_user.id if current_user else 'None'}")
    
    if not current_user:
         # This case should ideally be handled by get_current_user raising an exception
         print("DEBUG (Dependency): No current_user from get_current_user dependency.")
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, # Use 401 if token is invalid/missing
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
         )

    # Verify admin status from the database using the user from the token
    user = db.query(User).filter(User.id == current_user.id).first()
    
    if not user:
        print(f"DEBUG (Dependency): User ID {current_user.id} from token not found in DB.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, # Use 403 as token was valid but user lacks permission/exists
            detail="User not found in database."
        )

    if not user.is_active:
        print(f"DEBUG (Dependency): User {user.email} is inactive.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive."
        )

    if not user.is_superuser:
        print(f"DEBUG (Dependency): Access denied - user {user.email} is NOT an admin.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access admin area."
        )
    
    print(f"DEBUG (Dependency): Admin access GRANTED to {user.email}.")
    
    # OPTIONAL: Attach the validated admin user to the request state for potential use elsewhere
    # request.state.user = user 
    
    return user # Return the validated admin user object

# Admin dashboard
@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db), # Keep DB session for dashboard data
    admin_user: User = Depends(get_admin_user) # Apply the dependency
):
    """Display the main admin dashboard with statistics and metrics"""
    # By reaching this point, admin_user is a validated admin.
    try:
        print("\n===== ADMIN DASHBOARD ROUTE (Rendering Real Template) =====")
        print(f"DEBUG: Admin user confirmed: {admin_user.email}")

        # --- Data Gathering --- 
        # (Re-implementing logic similar to previous attempts, but using admin_user)
        
        # Timeframes
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(weeks=1)
        month_ago = now - timedelta(days=30) # Approx

        # User Stats
        total_users = db.query(User).count()
        active_users = db.query(User).filter(User.is_active == True).count()
        new_users_today = db.query(User).filter(User.created_at >= day_ago).count()
        
        # Login Stats (using LoginHistory)
        total_logins_day = db.query(LoginHistory).filter(LoginHistory.timestamp >= day_ago).count()
        failed_logins_day = db.query(LoginHistory).filter(LoginHistory.timestamp >= day_ago, LoginHistory.success == False).count()
        successful_logins_day = total_logins_day - failed_logins_day
        failed_logins_hour = db.query(LoginHistory).filter(LoginHistory.timestamp >= hour_ago, LoginHistory.success == False).count()
        unique_failed_ips_day = db.query(LoginHistory.ip_address).filter(LoginHistory.timestamp >= day_ago, LoginHistory.success == False).distinct().count()
        login_failure_rate_day = (failed_logins_day / total_logins_day * 100) if total_logins_day > 0 else 0

        # Session Stats (using DbSession)
        active_sessions = db.query(DbSession).filter(DbSession.is_active == True, DbSession.expires_at > now).count()
        total_sessions_day = db.query(DbSession).filter(DbSession.created_at >= day_ago).count()

        # Security Metrics
        mfa_enabled_users = db.query(User).filter(User.mfa_enabled == True, User.is_active == True).count()
        mfa_adoption_rate = (mfa_enabled_users / active_users * 100) if active_users > 0 else 0
        # Placeholder for compliance score
        compliance_score = 85 # Example score
        # Placeholder for blocked IPs - requires a separate table/logic
        blocked_ips_count = 15 # Example count

        # Recent Activity (Mix of logins and admin actions - Placeholder)
        recent_logins = db.query(LoginHistory).order_by(LoginHistory.timestamp.desc()).limit(5).all()
        recent_activity = []
        for log in recent_logins:
            user_email = db.query(User.email).filter(User.id == log.user_id).scalar() or "Unknown User"
            status_text = "Success" if log.success else f"Failed ({log.failure_reason or '-'})"
            recent_activity.append({
                "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "user": user_email,
                "action": f"Login Attempt ({status_text})",
                "ip_address": log.ip_address
            })
        # Add some dummy admin actions for variety
        recent_activity.append({"timestamp": (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"), "user": admin_user.email, "action": "Updated Security Policy", "ip_address": request.client.host})
        recent_activity.append({"timestamp": (now - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"), "user": admin_user.email, "action": "Viewed User List", "ip_address": request.client.host})
        # Ensure list is capped and sorted if needed
        recent_activity = sorted(recent_activity, key=lambda x: x["timestamp"], reverse=True)[:7]

        # Critical Alerts (Placeholder based on recent failed logins)
        critical_alerts = []
        high_risk_logins = db.query(LoginHistory).filter(
            LoginHistory.timestamp >= hour_ago, 
            LoginHistory.success == False, 
            LoginHistory.risk_score > 70 # Example threshold
        ).order_by(LoginHistory.timestamp.desc()).limit(3).all()
        
        for alert_log in high_risk_logins:
             user_email = db.query(User.email).filter(User.id == alert_log.user_id).scalar() or "Unknown User"
             critical_alerts.append({
                 "id": alert_log.id,
                 "severity": "High",
                 "message": f"High-risk failed login detected for {user_email}",
                 "details": f"IP: {alert_log.ip_address}, Reason: {alert_log.failure_reason or 'N/A'}, Score: {alert_log.risk_score}",
                 "timestamp": alert_log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                 "acknowledged": False # Example status
             })
        if not critical_alerts: # Add a dummy if none found
             critical_alerts.append({"id": 0, "severity": "Info", "message": "No critical security events in the last hour.", "details": "System normal.", "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"), "acknowledged": True})

        # System Status (Placeholder)
        system_status = {
            "status": "Operational", # Could be "Degraded", "Outage"
            "cpu_usage": 35, # Percent
            "memory_usage": 55, # Percent
            "disk_usage": 40, # Percent
            "last_checked": now.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Chart Data (Placeholders - Replace with actual aggregation later)
        chart_data = {
            "userActivity": {
                "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                "logins": [120, 150, 110, 160, 180, 170, 190],
                "registrations": [10, 15, 8, 12, 20, 18, 22]
            },
            "securityIncidents": {
                "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                "failedLogins": [5, 8, 3, 7, 10, 6, 9],
                "blockedIPs": [1, 2, 0, 3, 2, 1, 4]
            },
            "geographicLogins": {
                "labels": ["USA", "Canada", "UK", "Germany", "India", "Other"],
                "counts": [1500, 300, 250, 180, 120, 50]
            },
            "systemResources": {
                "labels": ["-5m", "-4m", "-3m", "-2m", "-1m", "Now"],
                "cpu": [30, 32, 35, 33, 36, system_status["cpu_usage"]],
                "memory": [50, 52, 55, 54, 56, system_status["memory_usage"]]
            }
        }

        # Construct the context for the template
        context = {
            "request": request,
            "admin_user": admin_user,
            "stats": {
                "total_users": total_users,
                "active_users": active_users,
                "new_users_today": new_users_today,
                "active_sessions": active_sessions,
                "total_sessions_day": total_sessions_day,
                "total_logins_day": total_logins_day,
                "successful_logins_day": successful_logins_day,
                "failed_logins_day": failed_logins_day,
                "failed_logins_hour": failed_logins_hour,
            },
            "security_metrics": {
                "login_failure_rate_day": round(login_failure_rate_day, 2),
                "unique_failed_ips_day": unique_failed_ips_day,
                "mfa_adoption_rate": round(mfa_adoption_rate, 2),
                "compliance_score": compliance_score,
                "blocked_ips_count": blocked_ips_count,
            },
            "system_status": system_status,
            "recent_activity": recent_activity,
            "critical_alerts": critical_alerts,
            "chart_data": chart_data,
            "title": "Admin Dashboard" # Pass title to template
        }

        print("DEBUG: Rendering admin/dashboard.html template with context")
        return templates.TemplateResponse("admin/dashboard.html", context)

    except HTTPException as http_exc:
        # Re-raise HTTPExceptions to let FastAPI handle them
        print(f"ERROR: HTTPException during dashboard rendering: {http_exc.detail}")
        raise http_exc
    except Exception as e:
        print(f"ERROR: Unexpected exception in admin_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        # Render a generic error page or return an error response
        # Avoid returning raw exception details in production
        return templates.TemplateResponse(
            "errors/500.html", 
            {"request": request, "detail": "An internal error occurred while loading the dashboard."}, 
            status_code=500
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
    page: int = Query(1, ge=1),
    search: str = Query(None),
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Display the users management page with pagination and search"""
    items_per_page = 10
    query = db.query(User)
    
    # Apply search filter if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (User.email.ilike(search_term)) |
            (User.first_name.ilike(search_term)) |
            (User.last_name.ilike(search_term))
        )
    
    # Get total count for pagination
    total_items = query.count()
    total_pages = (total_items + items_per_page - 1) // items_per_page
    
    # Ensure current page is valid
    current_page = min(max(1, page), max(1, total_pages))
    
    # Get users for current page
    offset = (current_page - 1) * items_per_page
    users = query.offset(offset).limit(items_per_page).all()
    
    return templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "users": users,
            "current_page": current_page,
            "total_pages": total_pages,
            "total_items": total_items,
            "search": search,
            "admin_user": admin_user
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
    print(f"DEBUG: Admin settings page requested by {current_user.email}")
    
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
            "settings": settings,
            "current_user": current_user
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
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    search: str = Query(None)
):
    """Display security logs"""
    # Items per page
    per_page = 25
    
    # Base query - use left join to include logs without users
    query = db.query(LoginHistory).outerjoin(User, LoginHistory.user_id == User.id)
    
    # Apply filters
    if filter_success is not None:
        query = query.filter(LoginHistory.success == filter_success)
    
    if search:
        query = query.filter(
            (User.email.contains(search) if User.email is not None else False) | 
            (LoginHistory.ip_address.contains(search) if LoginHistory.ip_address is not None else False)
        )
    
    if event_type:
        query = query.filter(LoginHistory.event_type == event_type)
        
    if severity:
        if severity == 'info':
            query = query.filter(LoginHistory.success == True)
        elif severity == 'error':
            query = query.filter(LoginHistory.success == False)
    
    if user_id:
        query = query.filter(LoginHistory.user_id == user_id)
    
    try:
        # Calculate pagination
        total = query.count()
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        
        # Adjust current page if needed
        page = min(page, total_pages) if total_pages > 0 else 1
        
        # Get logs for current page
        logs = query.order_by(LoginHistory.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()
        
        # Get users for the logs - safely handle logs without user_id
        user_ids = [log.user_id for log in logs if log.user_id is not None]
        users = {}
        if user_ids:
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
                "event_type": event_type,
                "severity": severity,
                "user_id": user_id,
                "search": search or ""
            }
        )
    except Exception as e:
        print(f"Error in admin_security_logs: {str(e)}")
        # Return a basic version of the template with error information
        return templates.TemplateResponse(
            "admin/logs.html",
            {
                "request": request,
                "logs": [],
                "users": {},
                "page": 1,
                "total_pages": 1,
                "total_logs": 0,
                "filter_success": None,
                "event_type": None,
                "severity": None, 
                "user_id": None,
                "search": "",
                "error": str(e)
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

# Security settings
@router.get("/security", response_class=HTMLResponse)
async def admin_security_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Display security overview page"""
    # Get current security settings
    settings = db.query(SecuritySettings).first()
    
    # If no settings exist, create default settings
    if not settings:
        settings = SecuritySettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    
    # Get recent security events
    recent_events = db.query(LoginHistory).filter(
        LoginHistory.success == False
    ).order_by(LoginHistory.timestamp.desc()).limit(10).all()
    
    # Get statistics
    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(weeks=1)
    
    # Failed login attempts
    failed_today = db.query(LoginHistory).filter(
        LoginHistory.success == False,
        LoginHistory.timestamp >= day_ago
    ).count()
    
    failed_week = db.query(LoginHistory).filter(
        LoginHistory.success == False,
        LoginHistory.timestamp >= week_ago
    ).count()
    
    # Unique IPs with failed attempts
    unique_ips_today = db.query(LoginHistory.ip_address).filter(
        LoginHistory.success == False,
        LoginHistory.timestamp >= day_ago
    ).distinct().count()
    
    # Get blocked IPs (if you have a table for this)
    blocked_ips = 15  # Example value, replace with actual query
    
    # MFA adoption rate
    total_active_users = db.query(User).filter(User.is_active == True).count()
    mfa_users = db.query(User).filter(User.is_active == True, User.mfa_enabled == True).count()
    mfa_rate = (mfa_users / total_active_users * 100) if total_active_users > 0 else 0
    
    return templates.TemplateResponse(
        "admin/security.html",
        {
            "request": request,
            "settings": settings,
            "recent_events": recent_events,
            "stats": {
                "failed_today": failed_today,
                "failed_week": failed_week,
                "unique_ips_today": unique_ips_today,
                "blocked_ips": blocked_ips,
                "mfa_rate": round(mfa_rate, 1)
            }
        }
    )

# Export routes
@router.get("/logs/export", response_class=StreamingResponse)
async def export_logs(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
    format: str = Query("csv", regex="^(csv|json)$"),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    user_id: Optional[int] = Query(None),
    success: Optional[bool] = Query(None)
):
    """Export logs in CSV or JSON format"""
    # Set default date range to last 30 days if not specified
    if not start_date:
        start_date = datetime.now() - timedelta(days=30)
    if not end_date:
        end_date = datetime.now()
    
    # Prepare filters
    filters = {
        "start_date": start_date,
        "end_date": end_date,
        "user_id": user_id,
        "success": success
    }
    
    # Fetch logs based on filters
    logs = fetch_filter_logs(db, filters)
    
    # Get user info for the logs
    user_ids = [log.user_id for log in logs if log.user_id is not None]
    users = {user.id: user for user in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    
    # Export based on requested format
    if format == "csv":
        return export_logs_to_csv(logs, users)
    else:  # json
        return export_logs_to_json(logs, users)

@router.get("/security/report", response_class=StreamingResponse)
async def security_report(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None)
):
    """Generate a security report for the specified date range"""
    # Set default date range to last 30 days if not specified
    if not start_date:
        start_date = datetime.now() - timedelta(days=30)
    if not end_date:
        end_date = datetime.now()
    
    return generate_security_report(db, start_date, end_date)

# System maintenance routes
@router.get("/maintenance", response_class=HTMLResponse)
async def admin_maintenance(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Display system maintenance page"""
    # Get system health data
    health_data = get_system_health()
    
    # Get database stats
    user_count = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    
    now = datetime.utcnow()
    log_count = db.query(LoginHistory).count()
    log_count_30_days = db.query(LoginHistory).filter(LoginHistory.timestamp >= now - timedelta(days=30)).count()
    
    active_sessions = db.query(DbSession).filter(
        DbSession.is_active == True,
        DbSession.expires_at > now
    ).count()
    
    # Get last maintenance time (could be stored in a settings table in a real app)
    last_maintenance = now - timedelta(days=3, hours=7)  # Example value
    
    return templates.TemplateResponse(
        "admin/maintenance.html",
        {
            "request": request,
            "current_user": current_user,
            "health": health_data,
            "stats": {
                "user_count": user_count,
                "active_users": active_users,
                "log_count": log_count,
                "log_count_30_days": log_count_30_days,
                "active_sessions": active_sessions
            },
            "last_maintenance": last_maintenance
        }
    )

@router.get("/maintenance/backup", response_class=StreamingResponse)
async def backup_database(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Create a database backup and return it as a downloadable file"""
    return create_database_backup(db)

@router.post("/maintenance/cleanup", response_class=JSONResponse)
async def cleanup_logs(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
    retention_days: int = Form(90)
):
    """Clean up old logs and sessions"""
    # Run in background task to avoid timeout for large databases
    result = perform_log_cleanup(db, retention_days)
    return JSONResponse(result)

@router.post("/maintenance/optimize", response_class=JSONResponse)
async def optimize_db(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)
):
    """Optimize the database"""
    # Run in background task to avoid timeout
    result = optimize_database(db)
    return JSONResponse(result) 