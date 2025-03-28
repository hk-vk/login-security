from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, EmailStr

# Token schema
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_at: datetime
    
# Token data schema
class TokenData(BaseModel):
    email: Optional[str] = None
    user_id: Optional[int] = None

# OTP verification schema
class OTPVerify(BaseModel):
    otp_code: str

# MFA setup schema
class MFASetup(BaseModel):
    password: str
    
# MFA response schema
class MFAResponse(BaseModel):
    secret: str
    qr_code: str
    
# Password reset request schema
class PasswordResetRequest(BaseModel):
    email: EmailStr
    
# Password reset schema
class PasswordReset(BaseModel):
    token: str
    new_password: str
    confirm_password: str 