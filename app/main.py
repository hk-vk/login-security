from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.responses import HTMLResponse, RedirectResponse
import os
from dotenv import load_dotenv
from starlette import status
from sqlalchemy.orm import Session
from app.database.database import get_db

# Import custom user class
from app.starlette.authentication import CustomUser

# Import database
from app.database.database import engine, Base
from app.database.init_db import init_db

# Import routers
from app.routers.auth import router as auth_router
from app.routers.users import router as users_router
from app.routers.security import router as security_router
from app.routers.admin import router as admin_router

# Load environment variables
load_dotenv()

# Create tables
Base.metadata.create_all(bind=engine)

class TokenAuthBackend(AuthenticationBackend):
    async def authenticate(self, request):
        from sqlalchemy.orm import Session
        from app.database.database import SessionLocal
        from app.models.user import User
        from app.models.session import Session as DbSession
        from app.core.security import verify_token
        from datetime import datetime

        if "access_token" not in request.cookies:
            return None
        
        token = request.cookies["access_token"]
        if token and token.startswith("Bearer "):
            token = token[7:]  # Remove "Bearer " prefix
            
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
                    return None
                
                # Get the user
                user = db.query(User).filter(User.id == session.user_id).first()
                if not user or not user.is_active:
                    return None
                
                # Update session last active time
                session.last_active_at = datetime.utcnow()
                db.commit()
                
                # Return user credentials
                scopes = ["authenticated"]
                if user.is_superuser:
                    scopes.append("admin")
                
                return AuthCredentials(scopes), CustomUser(
                    username=user.email,
                    display_name=f"{user.first_name} {user.last_name}".strip(),
                    user_id=user.id,
                    is_superuser=user.is_superuser
                )
            finally:
                db.close()
        
        return None

# Initialize the FastAPI app
app = FastAPI(
    title="Adaptive Login Security System",
    description="A secure authentication system with adaptive security features",
    version="1.0.0"
)

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7")
)

# Add authentication middleware
app.add_middleware(
    AuthenticationMiddleware,
    backend=TokenAuthBackend()
)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

# Include routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(security_router)

# Admin routes are handled separately to allow for the login intercept
# Admin login intercept
@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/", response_class=HTMLResponse)
async def admin_login_intercept(request: Request, db: Session = Depends(get_db)):
    """Intercept requests to /admin and redirect non-authenticated users to admin login"""
    from app.models.user import User
    
    # Check if user is authenticated
    if not hasattr(request, "user") or not request.user.is_authenticated:
        # User is not authenticated, render admin login page
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "is_admin_login": True,
                "admin_redirect": True
            }
        )
    
    # Get actual user from database for superuser check
    user_email = request.user.username
    user = db.query(User).filter(User.email == user_email).first()
    
    # Check if user is admin
    if not user or not user.is_superuser:
        # User is authenticated but not an admin
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "is_admin_login": True,
                "admin_redirect": True,
                "error": "This area is restricted to administrators only."
            }
        )
    
    # For authenticated admin users, redirect to admin dashboard
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

# Include admin router
app.include_router(admin_router, prefix="/admin")

@app.get("/", response_class=HTMLResponse)
@app.head("/")
@app.options("/")
async def root(request: Request):
    """Render the home page"""
    if request.method == "OPTIONS":
        # Return CORS headers for OPTIONS request
        headers = {
            "Allow": "GET, HEAD, OPTIONS",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }
        return HTMLResponse(content="", headers=headers)
    
    # For GET and HEAD requests
    return templates.TemplateResponse(
        "index.html", 
        {
            "request": request,
            "user": request.user if hasattr(request, "user") else None
        }
    )

@app.on_event("startup")
async def startup_event():
    """Initialize the database on startup"""
    init_db()

# Add 404 exception handler
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    """Handle 404 errors gracefully"""
    if request.url.path.startswith("/admin"):
        # For admin routes, redirect to admin login
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "is_admin_login": True,
                "admin_redirect": True,
                "error": "The requested admin page was not found."
            }
        )
    return templates.TemplateResponse(
        "errors/404.html", 
        {
            "request": request,
            "path": request.url.path
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True) 