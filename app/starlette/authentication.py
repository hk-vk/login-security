from starlette.authentication import AuthCredentials
from typing import List, Optional

class CustomUser:
    def __init__(self, username: str, display_name: str = "", user_id: Optional[int] = None, is_superuser: bool = False):
        self.username = username
        self.display_name = display_name
        self.user_id = user_id
        self.is_superuser = is_superuser
        self.is_authenticated = True
        print(f"DEBUG: CustomUser created - {username}, is_superuser: {is_superuser}")

    @property
    def identity(self) -> str:
        return self.username
        
    @property
    def email(self) -> str:
        return self.username 