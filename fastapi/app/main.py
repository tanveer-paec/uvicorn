from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from . import schemas, models, database, auth
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

database.Base.metadata.create_all(bind=database.engine)

origins = ['*']
#fetch('http://localhost:8000').then(res=>res.json()).then(console.log) -- COMMAND TO RUN ON CONSOLE OF INSPECT
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    return auth.create_user(db, user)

@app.post("/verify/")
def verify_user(verfication: schemas.Verification, db: Session = Depends(get_db)):
    return auth.verfication(verfication, db)

@app.post("/keys/", response_model=schemas.User)
def update_user_keys(keys: schemas.UserKeysUpdate, db: Session = Depends(get_db)):
    return auth.update_user_keys(db, keys)

@app.post("/validate_keys/")
def validate_keys(keys: schemas.UserKeysValidate):
    return auth.validate_keys(keys)

@app.post("/login/")
def login_user(user: schemas.UserLogin, db: Session = Depends(get_db)):
    return auth.login_user(db, user)

@app.post("/dashboard/")
def dashboard(user: schemas.UserBase, db: Session = Depends(get_db)):
    return auth.dashboard(db, user)

@app.get("/users/{user_id}", response_model=schemas.User)
def get_user(user_id: int, db: Session = Depends(get_db)):
    return auth.get_user(db, user_id)

@app.get("/users/", response_model=list[schemas.User])
def get_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    return auth.get_users(db, skip=skip, limit=limit)

@app.put("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user: schemas.UserUpdate, db: Session = Depends(get_db)):
    return auth.update_user(db, user_id, user)

@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    return auth.delete_user(db, user_id)

@app.get("/verify_t/{token}", response_model=schemas.User)
def get_current_user(token: str, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return auth.verify_token(token, db)