from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database.database import Base

class Role(Base):
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    
    # Relationships
    users = relationship("User", back_populates="role") 