from sqlalchemy import Column, Integer, String, Boolean
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    is_valid = Column(Boolean, default=False)  # New column for validity status
    verification_code = Column(String, nullable=True)
    api_key = Column(String, unique=True, nullable=True)  # New column for API key
    secret_key = Column(String, nullable=True)  # New column for secret key
    exchange = Column(String)  # New column for exchange
