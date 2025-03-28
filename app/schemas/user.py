from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, validator, Field

# Base User schema
class UserBase(BaseModel):
    email: EmailStr
    is_active: bool = True
    first_name: Optional[str] = None
    last_name: Optional[str] = None

# Schema for creating a user
class UserCreate(UserBase):
    password: str
    password_confirm: str
    
    @validator('password')
    def passwords_match(cls, v, values):
        if 'password_confirm' in values and v != values['password_confirm']:
            raise ValueError('Passwords do not match')
        return v

# Schema for updating a user
class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role_id: Optional[int] = None

# Schema for user login
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# Schema for changing password
class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

# Schema for user information (response)
class UserInfo(UserBase):
    id: int
    role_id: Optional[int] = None
    is_superuser: bool
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True

# Schema for detailed user information (admin)
class UserDetail(UserInfo):
    failed_login_attempts: int
    last_failed_login: Optional[datetime] = None
    account_locked_until: Optional[datetime] = None
    password_last_changed: datetime
    
    class Config:
        orm_mode = True 