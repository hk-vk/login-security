from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.authentication import AuthenticationBackend, SimpleUser, AuthCredentials
import os
from dotenv import load_dotenv

# Import database
from app.database.database import engine, Base
from app.database.init_db import init_db

# Import routers
from app.routers import auth, users, security, admin

# Load environment variables
load_dotenv()

# Create tables
Base.metadata.create_all(bind=engine)

class TokenAuthBackend(AuthenticationBackend):
    async def authenticate(self, request):
        if "access_token" not in request.cookies:
            return None
        
        token = request.cookies["access_token"]
        if token and token.startswith("Bearer "):
            token = token[7:]  # Remove "Bearer " prefix
            
            # You can add token validation here if needed
            # For now, just create a simple user
            return AuthCredentials(["authenticated"]), SimpleUser("user")
        
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
app.include_router(auth)
app.include_router(users)
app.include_router(security)
app.include_router(admin, prefix="/admin")

@app.get("/")
async def root(request: Request):
    """Render the home page"""
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True) 