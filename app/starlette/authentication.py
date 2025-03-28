from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from typing import List, Optional

class CustomUser(BaseUser):
    """Custom user class for authentication"""
    
    def __init__(self, username: str, display_name: str, user_id: Optional[int], is_superuser: bool = False):
        self.username = username
        self.display_name = display_name
        self.user_id = user_id
        self.is_superuser = is_superuser
        self._is_authenticated = bool(username)  # User is authenticated if username is provided
    
    @property
    def is_authenticated(self) -> bool:
        return self._is_authenticated
    
    @property
    def display_name(self) -> str:
        return self._display_name
    
    @display_name.setter
    def display_name(self, value: str):
        self._display_name = value

    @property
    def identity(self) -> str:
        return self.username

    @property
    def email(self) -> str:
        return self.username 