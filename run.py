import os
import sys
import subprocess
import importlib.util
from pathlib import Path

def check_module_installed(module_name):
    """Check if a Python module is installed."""
    return importlib.util.find_spec(module_name) is not None

def install_requirements():
    """Install required packages from requirements.txt if needed."""
    print("Checking and installing requirements...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        print("Requirements installation completed.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing requirements: {e}")
        sys.exit(1)

def check_database():
    """Check if the database exists and has tables."""
    db_path = Path("app.db")
    if not db_path.exists():
        print("Database does not exist. Initializing database...")
        init_database()
        return
    
    # If database exists, check if it has tables
    try:
        import sqlite3
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        
        # Query sqlite_master to see if user table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            print("Database exists but tables are not initialized. Initializing tables...")
            init_database()
        else:
            print("Database already initialized.")
        
        conn.close()
    except Exception as e:
        print(f"Error checking database: {e}")
        init_database()

def init_database():
    """Initialize the database with tables."""
    try:
        print("Creating database tables...")
        from app.database.database import Base, engine
        from app.models import User, Role, Session, LoginHistory, Device, SecuritySettings
        from app.models.security import (
            SecurityEvent, LoginAttempt, RiskAssessmentLog, 
            BlockedIP, SuspiciousActivity, LoginLocation
        )
        
        # Create tables
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully.")
        
        # Check if we need to create initial admin user and roles
        create_initial_data()
    except Exception as e:
        print(f"Error initializing database: {e}")
        sys.exit(1)

def create_initial_data():
    """Create initial roles and admin user if not exists."""
    try:
        from app.database.database import SessionLocal
        from app.models import User, Role
        from sqlalchemy.orm import Session
        from sqlalchemy import select
        from passlib.context import CryptContext
        
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        db = SessionLocal()
        
        # Check if roles exist
        if db.query(Role).count() == 0:
            print("Creating default roles...")
            admin_role = Role(name="admin", description="Administrator")
            user_role = Role(name="user", description="Regular user")
            db.add(admin_role)
            db.add(user_role)
            db.commit()
        
        # Check if admin user exists
        if db.query(User).filter(User.email == "admin@example.com").count() == 0:
            print("Creating default admin user...")
            admin_role = db.query(Role).filter(Role.name == "admin").first()
            if admin_role:
                admin_user = User(
                    email="admin@example.com",
                    username="admin",
                    hashed_password=pwd_context.hash("Admin123!"),
                    is_active=True,
                    is_superuser=True,
                    first_name="Admin",
                    last_name="User",
                    role_id=admin_role.id
                )
                db.add(admin_user)
                db.commit()
                print("Default admin user created: admin@example.com / Admin123!")
            else:
                print("Admin role not found, cannot create admin user.")
        
        db.close()
    except Exception as e:
        print(f"Error creating initial data: {e}")

def main():
    """Run the FastAPI application using uvicorn"""
    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn", "app.main:app", "--reload"
        ], check=True)
    except KeyboardInterrupt:
        print("\nShutting down server...")
    except Exception as e:
        print(f"Error running server: {e}")
        return 1
    return 0

if __name__ == "__main__":
    # Ensure all requirements are installed
    if not check_module_installed("fastapi") or not check_module_installed("uvicorn"):
        install_requirements()
    
    # Check and initialize database if needed
    check_database()
    
    # Run the application
    sys.exit(main()) 