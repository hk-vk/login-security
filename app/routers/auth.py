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
import json
import uuid
import time
from fastapi import BackgroundTasks

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
from app.utils.email import send_verification_email, verify_code

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
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False),
    captcha_code: str = Form(None),
    device_fingerprint: str = Form(None),
    geo_location: str = Form(None),
    redirect: str = Form(None)
):
    """Login user"""
    # Check if CAPTCHA is required and validate
    if captcha_code:
        print(f"DEBUG: CAPTCHA code submitted: {captcha_code}")
        captcha_valid = False
        
        # Get CAPTCHA token from cookie and validate
        captcha_cookie = request.cookies.get("captcha_token")
        if captcha_cookie:
            print(f"DEBUG: CAPTCHA token cookie found")
            try:
                # Decode the token
                token_data = json.loads(captcha_cookie)
                expected_code = token_data.get("code")
                expiry = token_data.get("expiry")
                print(f"DEBUG: Expected CAPTCHA: {expected_code}, Expiry: {expiry}")
                
                # Check if code matches and not expired
                if expected_code == captcha_code and expiry > time.time():
                    captcha_valid = True
                    print("DEBUG: CAPTCHA validation successful")
                else:
                    print("DEBUG: CAPTCHA validation failed: wrong code or expired")
            except:
                print("DEBUG: Error decoding CAPTCHA token")
        
        if not captcha_valid:
            return templates.TemplateResponse(
                "auth/login.html",
                {
                    "request": request,
                    "error": "Invalid CAPTCHA code",
                    "email": email,
                    "show_captcha": True
                }
            )
    
    # Check if user exists
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Add code to increment failed login counter for IP
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": "Invalid email or password",
                "email": email,
                "show_captcha": True  # Show CAPTCHA after failed login
            }
        )
    
    # Check if account is locked
    if check_account_lockout(user):
        print(f"DEBUG: Account locked: {user.email}")
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": f"Account locked. Please try again later or contact support.",
                "email": email,
                "show_captcha": True
            }
        )
    
    # Verify password
    if not verify_password(password, user.hashed_password):
        # Handle failed login
        handle_failed_login(db, user, request)
        
        # Create login history entry
        create_login_history(
            db, user, False, request, 
            failure_reason="Invalid password"
        )
        
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": "Invalid email or password",
                "email": email,
                "show_captcha": True
            }
        )
    
    # Handle successful login
    handle_successful_login(db, user)
    
    # Check for MFA
    if user.mfa_enabled:
        # Create a temporary session to track the MFA verification
        session_id = str(uuid.uuid4())
        
        # Store session data in Redis or database in a real app
        # For this example, we'll set a cookie with limited data
        response = RedirectResponse(
            url="/auth/mfa/verify",
            status_code=status.HTTP_303_SEE_OTHER
        )
        
        # Store user ID and session ID in cookie
        response.set_cookie(
            key="mfa_session",
            value=json.dumps({
                "session_id": session_id,
                "email": user.email,
                "user_id": user.id,
                "remember": remember,
                "redirect": redirect
            }),
            httponly=True,
            max_age=900,  # 15 minutes
            path="/"
        )
        
        # Send verification email
        send_verification_email(background_tasks, user.email)
        
        return response
    
    # If no MFA, complete login
    # Create login history entry
    create_login_history(db, user, True, request)
    
    # Create user session
    device = get_or_create_device(db, user, request)
    
    # Create access token
    access_token_expires = timedelta(days=30 if remember else 1)
    token_data = {"sub": user.email}
    access_token = create_access_token(data=token_data, expires_delta=access_token_expires)
    
    # Create DB session
    db_session = DbSession(
        user_id=user.id,
        device_id=device.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        token=access_token,
        is_active=True,
        expires_at=datetime.utcnow() + access_token_expires
    )
    
    db.add(db_session)
    db.commit()
    
    # Update user's last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Create response with token cookie
    response = RedirectResponse(
        url=redirect or "/dashboard",  # Redirect to dashboard or specified URL
        status_code=status.HTTP_303_SEE_OTHER
    )
    
    # Set token cookie
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=30 * 24 * 60 * 60 if remember else 24 * 60 * 60,  # 30 days if remember, otherwise 24 hours
        path="/"
    )
    
    return response

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Render the registration page"""
    return templates.TemplateResponse("auth/register.html", {"request": request})

@router.post("/register")
async def register(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    first_name: str = Form(None),
    last_name: str = Form(None),
    enable_mfa: bool = Form(False)
):
    """Register a new user"""
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
    
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "error": "User with this email already exists",
                "email": email,
                "first_name": first_name,
                "last_name": last_name
            }
        )
    
    # Create new user
    try:
        # Hash password
        hashed_password = get_password_hash(password)
        
        # Create user
        user = User(
            email=email,
            hashed_password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            mfa_enabled=enable_mfa
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # If MFA is enabled, send verification email
        if enable_mfa:
            # Create session without completing login
            # Create a temporary session to track the MFA verification
            session_id = str(uuid.uuid4())
            
            # Store session data in Redis or database in a real app
            # For this example, we'll set a cookie with limited data
            response = RedirectResponse(
                url="/auth/mfa/verify",
                status_code=status.HTTP_303_SEE_OTHER
            )
            
            # Store email in session
            response.set_cookie(
                key="mfa_session",
                value=json.dumps({
                    "session_id": session_id,
                    "email": email,
                    "registration": True  # Flag to indicate this is a new registration
                }),
                httponly=True,
                max_age=900,  # 15 minutes
                path="/"
            )
            
            # Send verification email
            send_verification_email(background_tasks, email)
            
            return response
        
        # If MFA is not enabled, redirect to login page
        return RedirectResponse(
            url="/auth/login?registered=true",
            status_code=status.HTTP_303_SEE_OTHER
        )
    
    except Exception as e:
        db.rollback()
        print(f"Error during registration: {str(e)}")
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "error": "An error occurred during registration",
                "email": email,
                "first_name": first_name,
                "last_name": last_name
            }
        )

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
async def mfa_verify_page(request: Request):
    """MFA verification page"""
    # Get MFA session from cookie
    mfa_session = request.cookies.get("mfa_session")
    if not mfa_session:
        return RedirectResponse(
            url="/auth/login",
            status_code=status.HTTP_303_SEE_OTHER
        )
    
    try:
        session_data = json.loads(mfa_session)
        user_email = session_data.get("email")
        session_id = session_data.get("session_id")
        
        return templates.TemplateResponse(
            "auth/mfa_verify.html",
            {
                "request": request,
                "user_email": user_email,
                "session_id": session_id
            }
        )
    except:
        # Invalid session data
        return RedirectResponse(
            url="/auth/login",
            status_code=status.HTTP_303_SEE_OTHER
        )

@router.post("/mfa/verify")
async def verify_mfa(
    request: Request,
    db: Session = Depends(get_db),
    verification_code: str = Form(...),
    email: str = Form(...),
    session_id: str = Form(...)
):
    """Verify MFA code"""
    # Verify the code
    if not verify_code(email, verification_code):
        return templates.TemplateResponse(
            "auth/mfa_verify.html",
            {
                "request": request,
                "error": "Invalid or expired verification code",
                "user_email": email,
                "session_id": session_id
            }
        )
    
    # Get MFA session from cookie
    mfa_session = request.cookies.get("mfa_session")
    if not mfa_session:
        return RedirectResponse(
            url="/auth/login",
            status_code=status.HTTP_303_SEE_OTHER
        )
    
    try:
        session_data = json.loads(mfa_session)
        user_id = session_data.get("user_id")
        remember = session_data.get("remember", False)
        redirect_url = session_data.get("redirect")
        is_registration = session_data.get("registration", False)
        
        # For new registrations, just redirect to login
        if is_registration:
            response = RedirectResponse(
                url="/auth/login?registered=true&mfa_setup=true",
                status_code=status.HTTP_303_SEE_OTHER
            )
            # Clear MFA session
            response.delete_cookie(key="mfa_session", path="/")
            return response
        
        # For login, complete the login process
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return RedirectResponse(
                url="/auth/login",
                status_code=status.HTTP_303_SEE_OTHER
            )
        
        # Create login history entry
        create_login_history(db, user, True, request)
        
        # Create user session
        device = get_or_create_device(db, user, request)
        
        # Create access token
        access_token_expires = timedelta(days=30 if remember else 1)
        token_data = {"sub": user.email}
        access_token = create_access_token(data=token_data, expires_delta=access_token_expires)
        
        # Create DB session
        db_session = DbSession(
            user_id=user.id,
            device_id=device.id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            token=access_token,
            is_active=True,
            expires_at=datetime.utcnow() + access_token_expires
        )
        
        db.add(db_session)
        db.commit()
        
        # Update user's last login
        user.last_login = datetime.utcnow()
        db.commit()
        
        # Create response with token cookie
        response = RedirectResponse(
            url=redirect_url or "/dashboard",
            status_code=status.HTTP_303_SEE_OTHER
        )
        
        # Set token cookie
        response.set_cookie(
            key="access_token",
            value=f"Bearer {access_token}",
            httponly=True,
            max_age=30 * 24 * 60 * 60 if remember else 24 * 60 * 60,
            path="/"
        )
        
        # Clear MFA session
        response.delete_cookie(key="mfa_session", path="/")
        
        return response
    
    except Exception as e:
        print(f"Error during MFA verification: {str(e)}")
        return templates.TemplateResponse(
            "auth/mfa_verify.html",
            {
                "request": request,
                "error": "An error occurred during verification",
                "user_email": email,
                "session_id": session_id
            }
        )

@router.post("/mfa/resend")
async def resend_mfa_code(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str
):
    """Resend MFA verification code"""
    try:
        # Send verification email
        send_verification_email(background_tasks, email)
        
        return JSONResponse({
            "success": True,
            "message": "Verification code resent"
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "message": str(e)
        }, status_code=400)

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