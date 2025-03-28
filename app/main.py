from fastapi import FastAPI, Request, Depends, HTTPException, status, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn
from starlette.middleware.sessions import SessionMiddleware
from typing import Optional, Callable
import importlib
import os
import logging
import base64
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from app.database.database import get_db

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

# Helper function to check if user is authenticated and admin
async def is_admin(request: Request, access_token: Optional[str] = Cookie(None)):
    from app.database.database import SessionLocal
    from app.models.user import User
    from app.models.session import Session as DbSession
    from datetime import datetime
    
    # No token, not authenticated
    if not access_token:
        return False
    
    if access_token.startswith("Bearer "):
        access_token = access_token[7:]  # Remove "Bearer " prefix
    
    # Get a database session
    db = SessionLocal()
    try:
        # Look up the token in the sessions table
        session = db.query(DbSession).filter(
            DbSession.token == access_token,
            DbSession.is_active == True,
            DbSession.expires_at > datetime.utcnow()
        ).first()
        
        if not session:
            return False
        
        # Get the user
        user = db.query(User).filter(User.id == session.user_id).first()
        if not user or not user.is_active or not user.is_superuser:
            return False
        
        # Update session last active time
        session.last_active_at = datetime.utcnow()
        db.commit()
        
        # Store user in request state for later use
        request.state.user = user
        return True
    finally:
        db.close()

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

# Add middleware in the simplified order
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

# Now import routers
from app.routers import auth, admin, users, security

# Add specific admin routes to handle authentication
@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/", response_class=HTMLResponse)
async def admin_root(request: Request, access_token: Optional[str] = Cookie(None)):
    # Check if user is authenticated and admin
    if await is_admin(request, access_token):
        return RedirectResponse(url="/admin/dashboard")
    
    # If not authenticated or not admin, render admin login page
    return templates.TemplateResponse(
        "admin/login.html", 
        {"request": request, "redirect_url": "/admin/dashboard"}
    )

@app.get("/admin/{path:path}", response_class=HTMLResponse)
async def admin_pages(path: str, request: Request, access_token: Optional[str] = Cookie(None)):
    # Check if user is authenticated and admin
    if await is_admin(request, access_token):
        # Continue to the admin route
        pass
    else:
        # If not authenticated or not admin, render admin login page
        return templates.TemplateResponse(
            "admin/login.html", 
            {"request": request, "redirect_url": f"/admin/{path}"}
        )

# Include routers
app.include_router(auth)              # Auth router
app.include_router(admin, prefix="/admin")  # Admin router
app.include_router(users)             # Users router
app.include_router(security)          # Security router

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    # For admin routes, check authentication
    if request.url.path.startswith("/admin/"):
        if not await is_admin(request, request.cookies.get("access_token")):
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