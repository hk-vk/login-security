from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from datetime import datetime, timedelta
import secrets
import string

from app.database.database import get_db
from app.models.user import User
from app.models.login_history import LoginHistory
from app.schemas.auth import PasswordResetRequest, PasswordReset
from app.routers.auth import get_current_user
from app.core.security import verify_password, get_password_hash, generate_secure_password

router = APIRouter(tags=["security"], prefix="/security")

templates = Jinja2Templates(directory="app/templates")

# Password reset
@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    """Display the forgot password page"""
    return templates.TemplateResponse("security/forgot_password.html", {"request": request})

@router.post("/forgot-password", response_class=HTMLResponse)
async def request_password_reset(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...)
):
    """Handle password reset request"""
    # Find the user
    user = db.query(User).filter(User.email == email).first()
    
    # Always show success message even if user doesn't exist (security)
    if not user:
        return templates.TemplateResponse(
            "security/forgot_password_sent.html",
            {"request": request}
        )
    
    # Generate reset token (in a real app, this would be more secure)
    reset_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
    
    # Store reset token and expiry in session (in a real app, this would be stored in the database)
    request.session[f"reset_token_{reset_token}"] = {
        "user_id": user.id,
        "expires": (datetime.utcnow() + timedelta(hours=1)).isoformat()
    }
    
    # In a real application, you would send an email with a reset link
    # For this example, we'll just simulate the email was sent
    
    return templates.TemplateResponse(
        "security/forgot_password_sent.html",
        {
            "request": request,
            "reset_link": f"/security/reset-password?token={reset_token}"  # For demo only
        }
    )

@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str = None):
    """Display the reset password page"""
    if not token:
        raise HTTPException(status_code=400, detail="Missing reset token")
    
    # Check if token exists and is valid
    token_data = request.session.get(f"reset_token_{token}")
    if not token_data:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    # Check if token has expired
    expires = datetime.fromisoformat(token_data["expires"])
    if datetime.utcnow() > expires:
        # Remove expired token
        request.session.pop(f"reset_token_{token}", None)
        raise HTTPException(status_code=400, detail="Reset token has expired")
    
    return templates.TemplateResponse(
        "security/reset_password.html",
        {"request": request, "token": token}
    )

@router.post("/reset-password", response_class=HTMLResponse)
async def reset_password(
    request: Request,
    db: Session = Depends(get_db),
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Reset user password"""
    # Check if passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse(
            "security/reset_password.html",
            {
                "request": request,
                "token": token,
                "error": "Passwords do not match"
            }
        )
    
    # Check if token exists and is valid
    token_data = request.session.get(f"reset_token_{token}")
    if not token_data:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    # Check if token has expired
    expires = datetime.fromisoformat(token_data["expires"])
    if datetime.utcnow() > expires:
        # Remove expired token
        request.session.pop(f"reset_token_{token}", None)
        raise HTTPException(status_code=400, detail="Reset token has expired")
    
    # Find the user
    user_id = token_data["user_id"]
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate password
    from app.core.security import validate_password
    password_validation = validate_password(new_password)
    if not password_validation["valid"]:
        return templates.TemplateResponse(
            "security/reset_password.html",
            {
                "request": request,
                "token": token,
                "error": password_validation["errors"][0]
            }
        )
    
    # Update password
    user.hashed_password = get_password_hash(new_password)
    user.password_last_changed = datetime.utcnow()
    
    # Invalidate all sessions
    from app.models.session import Session as DbSession
    db.query(DbSession).filter(
        DbSession.user_id == user.id,
        DbSession.is_active == True
    ).update({"is_active": False})
    
    db.commit()
    
    # Remove the reset token
    request.session.pop(f"reset_token_{token}", None)
    
    return RedirectResponse(
        url="/auth/login?password_reset=true",
        status_code=status.HTTP_303_SEE_OTHER
    )

# Security logs for current user
@router.get("/activity", response_class=HTMLResponse)
async def security_activity(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Display security activity log for the current user"""
    # Get login history
    login_history = db.query(LoginHistory).filter(
        LoginHistory.user_id == current_user.id
    ).order_by(LoginHistory.timestamp.desc()).limit(50).all()
    
    return templates.TemplateResponse(
        "security/activity.html",
        {
            "request": request,
            "login_history": login_history
        }
    ) 