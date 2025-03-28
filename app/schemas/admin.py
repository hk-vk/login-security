from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

# Security settings schema
class SecuritySettingsBase(BaseModel):
    # Password policy
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digits: bool = True
    password_require_special: bool = True
    password_expiry_days: int = 90
    password_history_count: int = 5
    
    # Login security
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    session_timeout_minutes: int = 30
    require_mfa: bool = False
    
    # IP security
    ip_whitelist_enabled: bool = False
    ip_blacklist_enabled: bool = True
    
    # Device security
    device_trust_duration_days: int = 30

class SecuritySettingsCreate(SecuritySettingsBase):
    pass

class SecuritySettingsUpdate(SecuritySettingsBase):
    pass

class SecuritySettings(SecuritySettingsBase):
    id: int
    created_at: datetime
    updated_at: datetime
    last_updated_by: Optional[str] = None
    
    class Config:
        orm_mode = True

# IP whitelist/blacklist schema
class IPListEntry(BaseModel):
    ip_address: str
    description: Optional[str] = None
    is_range: bool = False

# Security metrics schema
class SecurityMetrics(BaseModel):
    total_users: int
    active_users: int
    locked_accounts: int
    mfa_enabled_count: int
    mfa_enabled_percentage: float
    failed_login_count_24h: int
    successful_login_count_24h: int
    average_risk_score: float

# System health schema
class SystemHealth(BaseModel):
    status: str
    uptime: str
    database_connection: bool
    total_sessions: int
    active_sessions: int 