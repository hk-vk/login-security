from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timedelta

from app.database.database import get_db
from app.models.user import User
from app.models.device import Device
from app.models.session import Session as DbSession
from app.schemas.user import UserInfo, UserUpdate, PasswordChange
from app.routers.auth import get_current_user
from app.core.security import verify_password, get_password_hash, validate_password
from app.utils.security import check_password_expiration

router = APIRouter(tags=["users"], prefix="/users")

templates = Jinja2Templates(directory="app/templates")

# User dashboard
@router.get("/dashboard", response_class=HTMLResponse)
async def user_dashboard(request: Request, current_user: User = Depends(get_current_user)):
    """Display the user dashboard page"""
    # Get last login time from DbSession
    db = next(get_db())
    last_login = db.query(DbSession).filter(
        DbSession.user_id == current_user.id,
        DbSession.is_active == True
    ).order_by(DbSession.created_at.desc()).first()
    
    # Prepare user info for template
    user_info = {
        "username": current_user.username,
        "email": current_user.email,
        "full_name": f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or "Not provided",
        "last_login": last_login.created_at if last_login else None,
        "mfa_enabled": current_user.mfa_enabled
    }
    
    return templates.TemplateResponse(
        "dashboard.html", 
        {
            "request": request,
            "current_user": user_info
        }
    )

# Security settings
@router.get("/security", response_class=HTMLResponse)
async def security_settings(request: Request, current_user: User = Depends(get_current_user)):
    """Display the security settings page"""
    return templates.TemplateResponse(
        "users/security.html", 
        {
            "request": request,
            "user": current_user
        }
    )

# User profile
@router.get("/profile", response_class=HTMLResponse)
async def user_profile(request: Request, current_user: User = Depends(get_current_user)):
    """Display the user profile page"""
    return templates.TemplateResponse(
        "users/profile.html", 
        {
            "request": request,
            "user": current_user
        }
    )

@router.post("/profile", response_class=HTMLResponse)
async def update_profile(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    first_name: str = Form(None),
    last_name: str = Form(None)
):
    """Update user profile information"""
    # Update user fields
    current_user.first_name = first_name
    current_user.last_name = last_name
    current_user.updated_at = datetime.utcnow()
    
    # Commit changes
    db.commit()
    
    return templates.TemplateResponse(
        "users/profile.html", 
        {
            "request": request,
            "user": current_user,
            "success": "Profile updated successfully"
        }
    )

# Password change
@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, current_user: User = Depends(get_current_user)):
    """Display the change password page"""
    # Check if password has expired
    password_status = check_password_expiration(current_user)
    expired = password_status.get("expired", False)
    
    return templates.TemplateResponse(
        "users/change_password.html", 
        {
            "request": request,
            "expired": expired
        }
    )

@router.post("/change-password", response_class=HTMLResponse)
async def change_password(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Change the user's password"""
    # Check if new passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse(
            "users/change_password.html", 
            {
                "request": request,
                "error": "New passwords do not match"
            }
        )
    
    # Verify current password
    if not verify_password(current_password, current_user.hashed_password):
        return templates.TemplateResponse(
            "users/change_password.html", 
            {
                "request": request,
                "error": "Current password is incorrect"
            }
        )
    
    # Validate new password
    password_validation = validate_password(new_password)
    if not password_validation["valid"]:
        return templates.TemplateResponse(
            "users/change_password.html", 
            {
                "request": request,
                "error": password_validation["errors"][0]
            }
        )
    
    # Update password
    current_user.hashed_password = get_password_hash(new_password)
    current_user.password_last_changed = datetime.utcnow()
    db.commit()
    
    # Invalidate all sessions except the current one
    current_token = None
    token_cookie = request.cookies.get("access_token")
    if token_cookie and token_cookie.startswith("Bearer "):
        current_token = token_cookie[7:]  # Remove "Bearer " prefix
    
    if current_token:
        db.query(DbSession).filter(
            DbSession.user_id == current_user.id,
            DbSession.token != current_token,
            DbSession.is_active == True
        ).update({"is_active": False})
        db.commit()
    
    return templates.TemplateResponse(
        "users/change_password.html", 
        {
            "request": request,
            "success": "Password changed successfully"
        }
    )

# Device management
@router.get("/devices", response_class=HTMLResponse)
async def user_devices(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Display the user's devices"""
    # Get the user's devices
    devices = db.query(Device).filter(Device.user_id == current_user.id).all()
    
    return templates.TemplateResponse(
        "users/devices.html", 
        {
            "request": request,
            "devices": devices
        }
    )

@router.post("/devices/{device_id}/trust", response_class=HTMLResponse)
async def trust_device(
    request: Request,
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark a device as trusted"""
    # Find the device
    device = db.query(Device).filter(
        Device.id == device_id, 
        Device.user_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Set as trusted
    device.is_trusted = True
    device.trust_expires_at = datetime.utcnow() + timedelta(days=30)  # Trust for 30 days
    db.commit()
    
    return RedirectResponse(url="/users/devices", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/devices/{device_id}/forget", response_class=HTMLResponse)
async def forget_device(
    request: Request,
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remove a device from the trusted list"""
    # Find the device
    device = db.query(Device).filter(
        Device.id == device_id, 
        Device.user_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Delete the device and associated sessions
    db.query(DbSession).filter(DbSession.device_id == device.id).delete()
    db.delete(device)
    db.commit()
    
    return RedirectResponse(url="/users/devices", status_code=status.HTTP_303_SEE_OTHER)

# Session management
@router.get("/sessions", response_class=HTMLResponse)
async def user_sessions(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Display the user's active sessions"""
    # Get the user's active sessions
    sessions = db.query(DbSession).filter(
        DbSession.user_id == current_user.id,
        DbSession.is_active == True
    ).all()
    
    return templates.TemplateResponse(
        "users/sessions.html", 
        {
            "request": request,
            "sessions": sessions
        }
    )

@router.post("/sessions/{session_id}/revoke", response_class=HTMLResponse)
async def revoke_session(
    request: Request,
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Revoke a specific session"""
    # Find the session
    session = db.query(DbSession).filter(
        DbSession.id == session_id, 
        DbSession.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Deactivate the session
    session.is_active = False
    db.commit()
    
    return RedirectResponse(url="/users/sessions", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/sessions/revoke-all", response_class=HTMLResponse)
async def revoke_all_sessions(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Revoke all sessions except the current one"""
    # Get the current token
    current_token = None
    token_cookie = request.cookies.get("access_token")
    if token_cookie and token_cookie.startswith("Bearer "):
        current_token = token_cookie[7:]  # Remove "Bearer " prefix
    
    # Update all active sessions except the current one
    db.query(DbSession).filter(
        DbSession.user_id == current_user.id,
        DbSession.token != current_token if current_token else True,
        DbSession.is_active == True
    ).update({"is_active": False})
    
    db.commit()
    
    return RedirectResponse(url="/users/sessions", status_code=status.HTTP_303_SEE_OTHER)

# MFA management
@router.get("/mfa", response_class=HTMLResponse)
async def mfa_settings(request: Request, current_user: User = Depends(get_current_user)):
    """Display MFA settings page"""
    return templates.TemplateResponse(
        "users/mfa_settings.html", 
        {
            "request": request,
            "user": current_user
        }
    )

@router.get("/mfa/enable", response_class=HTMLResponse)
async def enable_mfa_page(request: Request, current_user: User = Depends(get_current_user)):
    """Display the page to enable MFA"""
    # Redirect to MFA setup
    request.session["mfa_user_id"] = current_user.id
    
    return RedirectResponse(url="/auth/mfa/setup", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/mfa/disable", response_class=HTMLResponse)
async def disable_mfa(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    password: str = Form(...)
):
    """Disable MFA for the user"""
    # Verify password
    if not verify_password(password, current_user.hashed_password):
        return templates.TemplateResponse(
            "users/mfa_settings.html", 
            {
                "request": request,
                "user": current_user,
                "error": "Incorrect password"
            }
        )
    
    # Disable MFA
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()
    
    return templates.TemplateResponse(
        "users/security.html",
        {
            "request": request,
            "user": current_user,
            "success": "MFA has been disabled"
        }
    ) 