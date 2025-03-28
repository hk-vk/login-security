import os
import sys
from pathlib import Path

# Add the parent directory to sys.path
sys.path.append(str(Path(__file__).parent.parent.parent))

from dotenv import load_dotenv
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from app.database.database import engine, Base, SessionLocal
from app.models.user import User
from app.models.role import Role

# Load environment variables
load_dotenv()

# Create password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize database
def init_db():
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    # Create a DB session
    db = SessionLocal()
    
    try:
        # Check if admin role exists
        admin_role = db.query(Role).filter(Role.name == "admin").first()
        if not admin_role:
            admin_role = Role(name="admin", description="Administrator role with all permissions")
            db.add(admin_role)
            db.commit()
            db.refresh(admin_role)
        
        # Check if user role exists
        user_role = db.query(Role).filter(Role.name == "user").first()
        if not user_role:
            user_role = Role(name="user", description="Regular user role with limited permissions")
            db.add(user_role)
            db.commit()
            db.refresh(user_role)
        
        # Check if admin user exists
        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
        admin_user = db.query(User).filter(User.email == admin_email).first()
        
        if not admin_user:
            # Create admin user
            admin_password = os.getenv("ADMIN_PASSWORD", "Admin@Secure123!")
            hashed_password = pwd_context.hash(admin_password)
            
            admin_user = User(
                email=admin_email,
                hashed_password=hashed_password,
                is_active=True,
                is_superuser=True,
                role_id=admin_role.id
            )
            
            db.add(admin_user)
            db.commit()
            
            print(f"Admin user created: {admin_email}")
        else:
            print(f"Admin user already exists: {admin_email}")
    
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    print("Database initialization completed.") 