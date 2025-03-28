from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta
import pyotp
import qrcode
import qrcode.image.svg
import io
import base64

from app.database.database import get_db
from app.models.user import User
from app.models.login_history import LoginHistory
from app.models.device import Device
from app.models.session import Session as DbSession
from app.schemas.auth import Token, TokenData, OTPVerify, MFASetup, MFAResponse
from app.schemas.user import UserCreate, UserLogin
from app.core.security import (
    verify_password, create_access_token, get_password_hash,
    generate_totp_secret, get_totp_uri, verify_totp
)
from app.utils.security import (
    check_account_lockout, handle_failed_login, handle_successful_login,
    detect_suspicious_login
)
from app.utils.device import generate_device_fingerprint, get_device_name, parse_user_agent

router = APIRouter(tags=["authentication"], prefix="/auth")

templates = Jinja2Templates(directory="app/templates")

# NEW: Custom dependency to get token from cookie
def get_token_from_cookie(request: Request) -> Optional[str]:
    """Extracts the JWT token from the access_token cookie."""
    token = request.cookies.get("access_token")
    print(f"DEBUG (get_token_from_cookie): Cookie 'access_token' value: {token[:10] if token else 'Not found'}")
    if token and token.startswith("Bearer "):
        token = token[7:] # Remove "Bearer " prefix
        print(f"DEBUG (get_token_from_cookie): Returning token (after removing Bearer): {token[:10]}...")
        return token
    elif token:
        print(f"DEBUG (get_token_from_cookie): Returning raw token (no Bearer prefix): {token[:10]}...")
        return token # Allow raw token if Bearer prefix is missing
    else:
        print(f"DEBUG (get_token_from_cookie): Token not found in cookies.")
        return None

# Helper functions
def get_current_user(token: str = Depends(get_token_from_cookie), db: Session = Depends(get_db)):
    """Get the current user from the token provided by the cookie dependency."""
    print(f"\n--- DEBUG: get_current_user --- START (Using Cookie Dependency) ---")
    # No need to check `token is None` here, the dependency handles or returns None
    # We rely on verify_token to handle None token input if get_token_from_cookie returns None
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials from cookie",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    print(f"DEBUG: Token received from get_token_from_cookie: {'Yes' if token else 'No'}")
    if token:
        print(f"DEBUG: Token received (first 10 chars): {token[:10]}...")
    
    from app.core.security import verify_token
    
    print("DEBUG: Calling verify_token...")
    # Pass the token directly to verify_token (it should handle None if necessary)
    token_data = verify_token(token)
    print(f"DEBUG: verify_token result: {token_data}")

    if not token_data or not token_data.get("valid"):
        print("DEBUG: token_data is invalid or missing 'valid' key. Raising 401.")
        print(f"--- DEBUG: get_current_user --- END (Error) ---")
        raise credentials_exception
    
    payload = token_data.get("payload")
    if not payload:
        print("DEBUG: token_data is missing 'payload' key. Raising 401.")
        print(f"--- DEBUG: get_current_user --- END (Error) ---")
        raise credentials_exception
        
    email = payload.get("sub")
    print(f"DEBUG: Email extracted from token payload ('sub'): {email}")
    
    if email is None:
        print("DEBUG: Email ('sub') is None in payload. Raising 401.")
        print(f"--- DEBUG: get_current_user --- END (Error) ---")
        raise credentials_exception
    
    print(f"DEBUG: Querying database for user with email: {email}")
    user = db.query(User).filter(User.email == email).first()
    
    if user is None:
        print(f"DEBUG: User with email {email} not found in database. Raising 401.")
        print(f"--- DEBUG: get_current_user --- END (Error) ---")
        raise credentials_exception
        
    if not user.is_active:
        print(f"DEBUG: User {email} found but is not active. Raising 401.")
        print(f"--- DEBUG: get_current_user --- END (Error) ---")
        raise credentials_exception
    
    print(f"DEBUG: User {email} found and is active. Returning user object.")
    print(f"--- DEBUG: get_current_user --- END (Success) ---")
    return user

def create_login_history(
    db: Session, 
    user: User, 
    success: bool, 
    request: Request, 
    failure_reason: Optional[str] = None,
    risk_score: int = 0
):
    """Create a new login history entry"""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    device_fingerprint = generate_device_fingerprint(ip_address, user_agent)
    
    # Create login history
    login_history = LoginHistory(
        user_id=user.id,
        success=success,
        ip_address=ip_address,
        user_agent=user_agent,
        device_fingerprint=device_fingerprint,
        failure_reason=failure_reason,
        risk_score=risk_score
    )
    
    db.add(login_history)
    db.commit()
    
    return login_history

def get_or_create_device(db: Session, user: User, request: Request):
    """Get or create a device for the user"""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    device_fingerprint = generate_device_fingerprint(ip_address, user_agent)
    
    # Check if device already exists
    device = db.query(Device).filter(
        Device.user_id == user.id,
        Device.device_fingerprint == device_fingerprint
    ).first()
    
    if not device:
        # Parse user agent
        parsed_ua = parse_user_agent(user_agent) if user_agent else {}
        
        # Create device
        device = Device(
            user_id=user.id,
            device_fingerprint=device_fingerprint,
            device_name=get_device_name(user_agent),
            device_type=parsed_ua.get("device_type", "desktop"),
            browser=parsed_ua.get("browser", "Unknown"),
            os=parsed_ua.get("os", "Unknown"),
            is_trusted=False,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        
        db.add(device)
        db.commit()
        db.refresh(device)
    else:
        # Update last seen
        device.last_seen = datetime.utcnow()
        db.commit()
    
    return device

def create_session(db: Session, user: User, request: Request):
    """Create a new session for the user"""
    # Get or create device
    device = get_or_create_device(db, user, request)
    
    # Create token
    access_token_expires = timedelta(minutes=30)
    token_data = {"sub": user.email}
    token = create_access_token(data=token_data, expires_delta=access_token_expires)
    
    # Create session
    session = DbSession(
        user_id=user.id,
        token=token,
        expires_at=datetime.utcnow() + access_token_expires,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        device_id=device.id,
        is_active=True,
        created_at=datetime.utcnow(),
        last_active_at=datetime.utcnow()
    )
    
    db.add(session)
    db.commit()
    
    return token, session

# Auth routes
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the login page"""
    return templates.TemplateResponse("auth/login.html", {"request": request})

@router.post("/login")
async def login(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False),
    captcha_code: str = Form(None),
    device_fingerprint: str = Form(None),
    geo_location: str = Form(None),
    redirect: str = Form(None)
):
    """Handle the login form submission"""
    
    # Debug info
    print(f"DEBUG: Login attempt for: {email}")
    print(f"DEBUG: Redirect parameter: {redirect}")
    
    # Find the user
    user = db.query(User).filter(User.email == email).first()
    
    # Prepare response data for template
    template_data = {
        "request": request,
        "email": email
    }
    
    # Check if the user exists
    if not user:
        print(f"DEBUG: User not found: {email}")
        template_data["error"] = "Invalid email or password"
        return templates.TemplateResponse("auth/login.html", template_data)
    
    # Verify the password
    if not verify_password(password, user.hashed_password):
        print(f"DEBUG: Invalid password for user: {email}")
        template_data["error"] = "Invalid email or password"
        return templates.TemplateResponse("auth/login.html", template_data)
    
    print(f"DEBUG: Successful login for {email}, superuser: {user.is_superuser}")
    
    # Create login history entry
    history = create_login_history(
        db=db,
        user=user,
        success=True,
        request=request
    )
    
    # Create user session
    token, session = create_session(db, user, request)
    
    # Store token in cookies or session
    redirect_url = redirect if redirect else "/"
    print(f"DEBUG: Redirecting after login to: {redirect_url}")
    
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True)
    
    return response

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Render the registration page"""
    return templates.TemplateResponse("auth/register.html", {"request": request})

@router.post("/register")
async def register(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    first_name: str = Form(None),
    last_name: str = Form(None)
):
    """Handle the registration form submission"""
    # Check if passwords match
    if password != password_confirm:
        return templates.TemplateResponse(
            "auth/register.html", 
            {
                "request": request,
                "error": "Passwords do not match",
                "email": email,
                "first_name": first_name,
                "last_name": last_name
            }
        )
    
    # Check if the email is already registered
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return templates.TemplateResponse(
            "auth/register.html", 
            {
                "request": request,
                "error": "Email already registered",
                "email": email,
                "first_name": first_name,
                "last_name": last_name
            }
        )
    
    # Validate password
    from app.core.security import validate_password
    password_validation = validate_password(password)
    if not password_validation["valid"]:
        return templates.TemplateResponse(
            "auth/register.html", 
            {
                "request": request,
                "error": password_validation["errors"][0],
                "email": email,
                "first_name": first_name,
                "last_name": last_name
            }
        )
    
    # Get the user role
    from app.models.role import Role
    user_role = db.query(Role).filter(Role.name == "user").first()
    
    # Create the user
    hashed_password = get_password_hash(password)
    user = User(
        email=email,
        hashed_password=hashed_password,
        is_active=True,
        is_superuser=False,
        first_name=first_name,
        last_name=last_name,
        role_id=user_role.id if user_role else None
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Redirect to login page
    return RedirectResponse(url="/auth/login?registered=true", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Handle user logout"""
    # Get the token from the cookie
    token = request.cookies.get("access_token")
    if token and token.startswith("Bearer "):
        token = token[7:]  # Remove "Bearer " prefix
        
        # Find the session
        session = db.query(DbSession).filter(DbSession.token == token).first()
        if session:
            # Deactivate the session
            session.is_active = False
            db.commit()
    
    # Clear cookie and redirect to login
    response = RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="access_token")
    
    return response

@router.get("/captcha")
async def generate_captcha(request: Request):
    """Generate a new CAPTCHA for the session"""
    # Generate a random captcha code
    import random
    import string
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    
    # Store the captcha text in the session
    request.session["captcha_text"] = captcha_text
    
    # Return the captcha text (in a real implementation, would return an image)
    return JSONResponse({"captcha": captcha_text})

@router.get("/mfa/setup", response_class=HTMLResponse)
async def mfa_setup_page(request: Request, db: Session = Depends(get_db)):
    """Render the MFA setup page"""
    # Check if user is authenticated for setup
    user_id = request.session.get("mfa_user_id")
    if not user_id:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Generate TOTP secret if not already set up
    secret = user.mfa_secret
    if not secret:
        secret = generate_totp_secret()
        user.mfa_secret = secret
        db.commit()
    
    # Generate QR code
    totp_uri = get_totp_uri(secret, user.email)
    qr = qrcode.make(totp_uri, image_factory=qrcode.image.svg.SvgImage)
    qr_buffer = io.BytesIO()
    qr.save(qr_buffer)
    qr_base64 = base64.b64encode(qr_buffer.getvalue()).decode()
    
    return templates.TemplateResponse(
        "auth/mfa_setup.html", 
        {
            "request": request,
            "qr_code": f"data:image/svg+xml;base64,{qr_base64}",
            "secret": secret
        }
    )

@router.post("/mfa/setup")
async def complete_mfa_setup(
    request: Request,
    db: Session = Depends(get_db),
    code: str = Form(...)
):
    """Complete MFA setup by verifying the first code"""
    # Check if user is authenticated for setup
    user_id = request.session.get("mfa_user_id")
    if not user_id:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.mfa_secret:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify the code
    if not verify_totp(user.mfa_secret, code):
        return templates.TemplateResponse(
            "auth/mfa_setup.html", 
            {
                "request": request,
                "error": "Invalid verification code",
                "qr_code": "data:image/svg+xml;base64,", # This would be regenerated in a real app
                "secret": user.mfa_secret
            }
        )
    
    # Enable MFA
    user.mfa_enabled = True
    db.commit()
    
    # If MFA was required due to suspicious login, proceed to login
    if request.session.get("mfa_required"):
        # Create user session
        token, session = create_session(db, user, request)
        
        # Clear session data
        request.session.pop("mfa_user_id", None)
        request.session.pop("mfa_required", None)
        
        # Store token in cookies
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True)
        
        return response
    
    # Otherwise redirect to profile page or login
    return RedirectResponse(url="/auth/login?mfa_setup=true", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/mfa/verify", response_class=HTMLResponse)
async def mfa_verify_page(request: Request, db: Session = Depends(get_db)):
    """Render the MFA verification page"""
    # Check if user is authenticated for verification
    user_id = request.session.get("mfa_user_id")
    if not user_id:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.mfa_enabled:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse("auth/mfa_verify.html", {"request": request})

@router.post("/mfa/verify")
async def verify_mfa(
    request: Request,
    db: Session = Depends(get_db),
    code: str = Form(...)
):
    """Verify MFA code during login"""
    # Check if user is authenticated for verification
    user_id = request.session.get("mfa_user_id")
    if not user_id:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.mfa_secret:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify the code
    if not verify_totp(user.mfa_secret, code):
        return templates.TemplateResponse(
            "auth/mfa_verify.html", 
            {
                "request": request,
                "error": "Invalid verification code"
            }
        )
    
    # Create user session
    token, session = create_session(db, user, request)
    
    # Clear session data
    request.session.pop("mfa_user_id", None)
    request.session.pop("mfa_required", None)
    
    # Store token in cookies
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True)
    
    return response

# API token endpoint for OAuth2
@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    request: Request = None
):
    """API endpoint for token-based authentication"""
    # Find the user
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if the account is locked
    lockout_status = check_account_lockout(user)
    if lockout_status["locked"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Account is locked. Try again in {lockout_status['minutes_remaining']} minutes.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Handle successful login
    handle_successful_login(db, user)
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    
    # Create login history if request is available
    if request:
        history = create_login_history(
            db=db,
            user=user,
            success=True,
            request=request
        )
    
    # Return the token
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": datetime.utcnow() + access_token_expires
    } 