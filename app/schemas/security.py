from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel

# Session schema
class SessionBase(BaseModel):
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

class SessionCreate(SessionBase):
    user_id: int
    token: str
    expires_at: datetime
    device_id: Optional[int] = None

class Session(SessionBase):
    id: int
    user_id: int
    token: str
    expires_at: datetime
    device_id: Optional[int] = None
    is_active: bool
    created_at: datetime
    last_active_at: datetime
    
    class Config:
        orm_mode = True

# Login History schema
class LoginHistoryBase(BaseModel):
    success: bool
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[str] = None
    device_fingerprint: Optional[str] = None
    failure_reason: Optional[str] = None
    risk_score: int = 0

class LoginHistoryCreate(LoginHistoryBase):
    user_id: int

class LoginHistory(LoginHistoryBase):
    id: int
    user_id: int
    timestamp: datetime
    
    class Config:
        orm_mode = True

# Device schema
class DeviceBase(BaseModel):
    device_fingerprint: str
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    browser: Optional[str] = None
    os: Optional[str] = None
    is_trusted: bool = False

class DeviceCreate(DeviceBase):
    user_id: int

class DeviceUpdate(BaseModel):
    device_name: Optional[str] = None
    is_trusted: Optional[bool] = None
    trust_expires_at: Optional[datetime] = None

class Device(DeviceBase):
    id: int
    user_id: int
    trust_expires_at: Optional[datetime] = None
    first_seen: datetime
    last_seen: datetime
    
    class Config:
        orm_mode = True 