from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn
from starlette.authentication import requires, AuthCredentials, AuthenticationBackend
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send
from typing import Optional, Callable
import importlib
import os
import logging
import base64
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from app.database.database import get_db

# Import custom user class
from app.starlette.authentication import CustomUser

# Import database
from app.database.database import engine, Base
from app.database.init_db import init_db

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Create tables
Base.metadata.create_all(bind=engine)

# Define TokenAuthBackend here instead of importing it
class TokenAuthBackend(AuthenticationBackend):
    async def authenticate(self, request):
        from sqlalchemy.orm import Session
        from app.database.database import SessionLocal
        from app.models.user import User
        from app.models.session import Session as DbSession
        from app.core.security import verify_token
        from datetime import datetime

        if "access_token" not in request.cookies:
            return AuthCredentials(["unauthenticated"]), None
        
        token = request.cookies["access_token"]
        if token and token.startswith("Bearer "):
            token = token[7:]  # Remove "Bearer " prefix
            print(f"DEBUG: AUTH - Verifying token: {token[:10]}...")
            
            # Get a database session
            db = SessionLocal()
            try:
                # Look up the token in the sessions table
                session = db.query(DbSession).filter(
                    DbSession.token == token,
                    DbSession.is_active == True,
                    DbSession.expires_at > datetime.utcnow()
                ).first()
                
                if not session:
                    print("DEBUG: AUTH - No valid session found for token")
                    return AuthCredentials(["unauthenticated"]), None
                
                # Get the user
                user = db.query(User).filter(User.id == session.user_id).first()
                if not user:
                    print("DEBUG: AUTH - User not found")
                    return AuthCredentials(["unauthenticated"]), None
                if not user.is_active:
                    print(f"DEBUG: AUTH - User {user.email} is not active")
                    return AuthCredentials(["unauthenticated"]), None
                
                print(f"DEBUG: AUTH - Found user: {user.email}, superuser: {user.is_superuser}")
                
                # Update session last active time
                session.last_active_at = datetime.utcnow()
                db.commit()
                
                # Return user credentials
                scopes = ["authenticated"]
                if user.is_superuser:
                    scopes.append("admin")
                    print(f"DEBUG: AUTH - Adding admin scope for {user.email}")
                
                print(f"DEBUG: AUTH - Creating authentication with scopes: {scopes}")
                return AuthCredentials(scopes), CustomUser(
                    username=user.email,
                    display_name=f"{user.first_name} {user.last_name}".strip(),
                    user_id=user.id,
                    is_superuser=user.is_superuser
                )
            finally:
                db.close()
        
        return AuthCredentials(["unauthenticated"]), None

# Initialize the FastAPI app
app = FastAPI(
    title="Adaptive Login Security System",
    description="A security system that adapts to the user's behavior and environment",
    version="1.0.0",
)

# Templates directory
templates = Jinja2Templates(directory="app/templates")

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Add middleware in the correct order
app.add_middleware(
    AuthenticationMiddleware,
    backend=TokenAuthBackend()
)

app.add_middleware(
    SessionMiddleware,
    secret_key="your-secret-key-here-make-sure-to-change-in-production"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Admin middleware as a function
@app.middleware("http")
async def admin_auth_middleware(request: Request, call_next):
    try:
        if request.url.path.startswith("/admin"):
            # Check if user is authenticated
            if not request.user.is_authenticated:
                return templates.TemplateResponse(
                    "admin/login.html",
                    {"request": request, "redirect_url": request.url.path}
                )

            # Check admin status
            from app.models.user import User
            from app.database.database import get_db
            
            db = next(get_db())
            try:
                db_user = db.query(User).filter(User.email == request.user.username).first()
                
                if not db_user or not db_user.is_superuser:
                    return HTMLResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content="Access denied. You must be an admin to access this page."
                    )
                
                if request.url.path in ["/admin", "/admin/"]:
                    return RedirectResponse(url="/admin/dashboard")
            finally:
                db.close()

    except AssertionError as e:
        if str(e) == "AuthenticationMiddleware must be installed to access request.user":
            logger.error("Authentication middleware not properly initialized")
            return HTMLResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content="Server configuration error. Please try again later."
            )
        raise

    response = await call_next(request)
    return response

# Now import routers after middleware is set up
from app.routers import auth, admin, users, security

# Include routers AFTER middleware setup
app.include_router(auth)              # Auth router
app.include_router(admin, prefix="/admin")  # Admin router
app.include_router(users)             # Users router
app.include_router(security)          # Security router

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    # For admin routes, render admin login if not authenticated
    if request.url.path.startswith("/admin/"):
        try:
            if not request.user or not request.user.is_authenticated:
                return templates.TemplateResponse(
                    "admin/login.html", 
                    {"request": request, "redirect_url": request.url.path}
                )
        except AssertionError:
            # If authentication middleware is not available, redirect to login
            return templates.TemplateResponse(
                "admin/login.html", 
                {"request": request, "redirect_url": request.url.path}
            )
    
    return templates.TemplateResponse(
        "errors/404.html", 
        {"request": request, "path": request.url.path}
    )

@app.get("/", response_class=HTMLResponse)
@app.head("/")
async def read_root(request: Request):
    """Handle both GET and HEAD requests for the root path"""
    if request.method == "HEAD":
        return HTMLResponse("")
    return templates.TemplateResponse("home.html", {"request": request})

@app.on_event("startup")
async def startup_event():
    """Initialize the database on startup"""
    init_db()

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True) 