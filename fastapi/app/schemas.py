from pydantic import BaseModel

class UserBase(BaseModel):
    email: str
    username: str

class UserCreate(UserBase):
    password: str

class Verification(BaseModel):
    email: str
    verification_code: str

class UserKeysUpdate(BaseModel):
    email: str
    exchange: str
    api_key: str
    secret_key: str

class UserKeysValidate(BaseModel):
    exchange: str
    api_key: str
    secret_key: str

class User(UserBase):
    id: int

    class Config:
        orm_mode = True

class UserUpdate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: str
    password: str
