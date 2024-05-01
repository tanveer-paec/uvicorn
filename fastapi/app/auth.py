from sqlalchemy.orm import Session
from . import models, schemas, ssh
from .database import SessionLocal, engine
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, status
import random
import string
from .email_service import send_verification_email
import json

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_user(db: Session, user: schemas.UserCreate):
    # Check if email already exists
    db_user_email = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

    # Check if username already exists
    db_user_username = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

    verification_code = generate_verification_code()
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(email=user.email, username=user.username, password=hashed_password, verification_code=verification_code)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    send_verification_email(user.email, verification_code)  # Send verification email

    ssh_client, server_ip, username, private_key = ssh.main()
    try:
        # Connect to the server
        ssh_client.connect(server_ip, username=username, pkey=private_key)

        # Execute the command
        stdin, stdout, stderr = ssh_client.exec_command(f'cd botcode\npython3 userconfigmanager.py --add_user -a {user.username}')
    finally:
        # Close the SSH connection
        ssh_client.close()

    return db_user

def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def verfication(verification: schemas.Verification, db: Session):
    user = db.query(models.User).filter(models.User.email == verification.email,
                                        models.User.verification_code == verification.verification_code).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found or verification code incorrect")
    user.is_valid = True
    db.commit()
    return {"message": "User verified successfully"}

def update_user_keys(db: Session, keys: schemas.UserKeysUpdate):
    db_user = db.query(models.User).filter(models.User.email == keys.email).first()
    if db_user:
        db_user.exchange = keys.exchange
        db_user.api_key = keys.api_key
        db_user.secret_key = keys.secret_key
        db.commit()
        db.refresh(db_user)
        return db_user
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

def validate_keys(keys: schemas.UserKeysValidate):
    ssh_client, server_ip, username, private_key = ssh.main()
    try:
        # Connect to the server
        ssh_client.connect(server_ip, username=username, pkey=private_key)

        # Execute the command
        stdin, stdout, stderr = ssh_client.exec_command(f'cd botcode\npython3 validate_api.py -k {keys.api_key} -s {keys.secret_key} -x {keys.exchange}')

        # Read the output of the command
        output = stdout.read().decode().strip()

        # Parse the output and handle accordingly
        if "Error" in output:
            # Error occurred, handle it
            error_response = {"error": output}
            # print(type(json.dumps(error_response)))
            return (error_response)
        else:
            # Output is not an error, parse it as JSON
            try:
                data = json.loads(output)
                return output
            except json.JSONDecodeError:
                # Output is not valid JSON, handle it
                error_response = {"error": "Received non-JSON output"}
                return json.dumps(error_response)
    except Exception as e:
        print("An error occurred:", str(e))
    finally:
        # Close the SSH connection
        ssh_client.close()

    # return output


def get_user(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        return db_user
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_users(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.User).offset(skip).limit(limit).all()

def update_user(db: Session, user_id: int, user: schemas.UserUpdate):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db_user.email = user.email
        db_user.username = user.username
        db_user.password = pwd_context.hash(user.password)
        db.commit()
        db.refresh(db_user)
        return db_user
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

def delete_user(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db.delete(db_user)
        db.commit()
        return {"message": "User deleted successfully"}
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

def login_user(db: Session, user: schemas.UserLogin):
    db_user = get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incorrect email")
    if not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect password")
    if not db_user.is_valid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not verified")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def dashboard(db: Session, user: schemas.UserBase):
    db_user = get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incorrect email")
    if not db_user.is_valid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not verified")
    db_username = db_user.username
    
    ssh_client, server_ip, username, private_key = ssh.main()
    try:
        # Connect to the server
        ssh_client.connect(server_ip, username=username, pkey=private_key)

        # Execute the command
        stdin, stdout, stderr = ssh_client.exec_command(f'cd botcode\nsqlite3 website_data.db "SELECT * FROM account_data WHERE account_name = \'{db_username}\'"')
        # Read the output of the command
        output = stdout.read().decode().strip()

        # Split the output by the pipe character
        columns = output.split('|')

        # Extract values from the columns
        _, account_name, value1, value2, value3 = columns

        # Convert values to appropriate types if necessary
        value1 = float(value1)
        value2 = float(value2)
        value3 = float(value3)
    except Exception as e:
        print("An error occurred:", str(e))
    finally:
        # Close the SSH connection
        ssh_client.close()

    try:
        # Connect to the server
        ssh_client.connect(server_ip, username=username, pkey=private_key)

        # Execute the command to read the JSON file and print its content
        stdin, stdout, stderr = ssh_client.exec_command(f'cd botcode\ncat {db_username}_account_coins.json')
        # # Read the output of the command
        json_content = stdout.read().decode().strip()

        # # Parse the JSON content
        json_data = json.loads(json_content)

    except Exception as e:
        print("An error occurred:", str(e))
    finally:
        # Close the SSH connection
        ssh_client.close()


    return value1, value2, value3, json_data

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = db.query(models.User).filter(models.User.email == email).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")