from datetime import datetime, timedelta
from typing import Optional, Any, Dict, List
import os
import re
from jose import jwt
from passlib.context import CryptContext
import pyotp
import secrets
import string
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get security settings from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Password validation
def validate_password(password: str) -> Dict[str, Any]:
    """Validate password against security policy"""
    min_length = int(os.getenv("PASSWORD_MIN_LENGTH", "8"))
    require_uppercase = os.getenv("PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true"
    require_lowercase = os.getenv("PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true"
    require_digits = os.getenv("PASSWORD_REQUIRE_DIGITS", "true").lower() == "true"
    require_special = os.getenv("PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true"
    
    errors = []
    
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")
    
    if require_uppercase and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if require_lowercase and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if require_digits and not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    if require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors
    }

# Password hashing and verification
def get_password_hash(password: str) -> str:
    """Hash a password for storing"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a stored password against a provided password"""
    return pwd_context.verify(plain_password, hashed_password)

# Token functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new JWT token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Dict[str, Any]:
    """Verify a JWT token and return its payload"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"valid": True, "payload": payload}
    except Exception as e:
        return {"valid": False, "error": str(e)}

# MFA functions
def generate_totp_secret() -> str:
    """Generate a new TOTP secret"""
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str) -> str:
    """Get the TOTP URI for QR code generation"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="Adaptive Login Security System")

def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

# MFA code generation and session handling
def create_mfa_code(length: int = 6) -> str:
    """Generate a random MFA code (digits only)."""
    return "".join(secrets.choice(string.digits) for _ in range(length))

def set_mfa_code_in_session(request, user_id: int, code: str, expire_minutes: int = 5):
    """Store the MFA code and its expiry in the session."""
    expiry = datetime.utcnow() + timedelta(minutes=expire_minutes)
    request.session[f"mfa_code_{user_id}"] = {"code": code, "expires": expiry.isoformat()}
    print(f"DEBUG: Stored MFA code for user {user_id} in session. Expires at {expiry.isoformat()}")

def get_mfa_code_from_session(request, user_id: int) -> Optional[str]:
    """Retrieve a valid MFA code from the session, checking expiry."""
    mfa_data = request.session.get(f"mfa_code_{user_id}")
    if mfa_data:
        expiry = datetime.fromisoformat(mfa_data.get("expires"))
        if datetime.utcnow() < expiry:
            print(f"DEBUG: Retrieved valid MFA code {mfa_data.get('code')} for user {user_id} from session.")
            return mfa_data.get("code")
        else:
            print(f"DEBUG: MFA code for user {user_id} expired at {expiry.isoformat()}.")
            # Clear expired code
            request.session.pop(f"mfa_code_{user_id}", None)
    else:
        print(f"DEBUG: No MFA code found in session for user {user_id}.")
    return None

# Generate secure random password
def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length)) 