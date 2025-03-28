# Import all routers and make them available
from app.routers.auth import router as auth
from app.routers.users import router as users
from app.routers.security import router as security
from app.routers.admin import router as admin

__all__ = [
    "auth",
    "users",
    "security",
    "admin"
] 