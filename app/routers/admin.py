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
        print("\n===== DEBUG: ADMIN DASHBOARD ROUTE =====")
        print(f"DEBUG: Request method: {request.method}")
        print(f"DEBUG: Request URL: {request.url}")
        print(f"DEBUG: Request headers: {dict(request.headers)}")
        
        # Check if user is authenticated
        print(f"DEBUG: Checking user authentication")
        print(f"DEBUG: request.state attributes: {dir(request.state)}")
        
        if not hasattr(request, "state"):
            print("DEBUG: Request has no state attribute")
            return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
            
        if not hasattr(request.state, "user"):
            print("DEBUG: Request state has no user attribute")
            return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
        
        # Get user from request state
        user = request.state.user
        print(f"DEBUG: User from request state: {user}")
        print(f"DEBUG: User attributes: {dir(user)}")
        print(f"DEBUG: User email: {user.email if hasattr(user, 'email') else 'No email attribute'}")
        print(f"DEBUG: User is_superuser: {user.is_superuser if hasattr(user, 'is_superuser') else 'No is_superuser attribute'}")
        
        # Always return a valid HTML response with debug information
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Dashboard Debug</title>
            <style>
                body { font-family: monospace; padding: 20px; background: #f5f5f5; }
                h1 { color: #333; }
                .debug-section { background: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; }
                .debug-item { margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
                .label { font-weight: bold; color: #555; }
                pre { background: #f8f8f8; padding: 10px; border-radius: 3px; overflow: auto; }
            </style>
        </head>
        <body>
            <h1>Admin Dashboard Debug Page</h1>
            <p>This page shows debug information about your request and authentication status.</p>
            
            <div class="debug-section">
                <h2>Request Information</h2>
                <div class="debug-item">
                    <div class="label">URL:</div>
                    <div>""" + str(request.url) + """</div>
                </div>
                <div class="debug-item">
                    <div class="label">Method:</div>
                    <div>""" + request.method + """</div>
                </div>
                <div class="debug-item">
                    <div class="label">Headers:</div>
                    <pre>""" + str(dict(request.headers)) + """</pre>
                </div>
            </div>
            
            <div class="debug-section">
                <h2>Authentication Information</h2>
                <div class="debug-item">
                    <div class="label">User Email:</div>
                    <div>""" + (user.email if hasattr(user, 'email') else 'No email attribute') + """</div>
                </div>
                <div class="debug-item">
                    <div class="label">Is Admin:</div>
                    <div>""" + str(user.is_superuser if hasattr(user, 'is_superuser') else 'No is_superuser attribute') + """</div>
                </div>
                <div class="debug-item">
                    <div class="label">User Attributes:</div>
                    <pre>""" + str(dir(user)) + """</pre>
                </div>
            </div>
            
            <div class="debug-section">
                <h2>Database Check</h2>
            """
            
        # Try to get user from database
        try:
            db_user = db.query(User).filter(User.id == user.id).first()
            if db_user:
                html_content += f"""
                <div class="debug-item">
                    <div class="label">Database User Found:</div>
                    <div>Yes</div>
                </div>
                <div class="debug-item">
                    <div class="label">DB User Email:</div>
                    <div>{db_user.email}</div>
                </div>
                <div class="debug-item">
                    <div class="label">DB User Is Admin:</div>
                    <div>{db_user.is_superuser}</div>
                </div>
                """
            else:
                html_content += """
                <div class="debug-item">
                    <div class="label">Database User Found:</div>
                    <div style="color:red;">No - User not found in database</div>
                </div>
                """
        except Exception as db_error:
            html_content += f"""
            <div class="debug-item">
                <div class="label">Database Error:</div>
                <div style="color:red;">{str(db_error)}</div>
            </div>
            """
            
        # Complete the HTML
        html_content += """
            </div>
            
            <p style="margin-top: 20px;"><a href="/admin">Back to Admin</a></p>
        </body>
        </html>
        """
        
        print("DEBUG: Returning debug HTML content")
        
        # Return raw HTML with explicit content type
        return HTMLResponse(
            content=html_content,
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"}
        )
    except Exception as e:
        print(f"ERROR: Exception in admin_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Return a direct HTML error page with detailed information
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error</title>
            <style>
                body {{ font-family: monospace; padding: 20px; background: #fff0f0; }}
                h1 {{ color: #d00; }}
                .error-box {{ background: #fff; border: 1px solid #fcc; border-radius: 5px; padding: 15px; margin-bottom: 15px; }}
                pre {{ background: #f8f8f8; padding: 10px; border-radius: 3px; overflow: auto; }}
            </style>
        </head>
        <body>
            <h1>Error in Admin Dashboard</h1>
            
            <div class="error-box">
                <h2>Exception Details</h2>
                <p>{str(e)}</p>
                <pre>{traceback.format_exc()}</pre>
            </div>
            
            <p><a href="/admin">Back to Admin</a></p>
        </body>
        </html>
        """
        return HTMLResponse(content=error_html, status_code=500)

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