from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Dict
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Configurações
SECRET_KEY = "mysecretkey"  # Alterar para uma chave segura em produção
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Inicialização
app = FastAPI()

# Simulação de banco de dados em memória
fake_db: Dict[str, Dict] = {}

# Configuração do hash de senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Modelos
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Funções auxiliares
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def authenticate_user(email: str, password: str):
    user = fake_db.get(email)
    if not user or not verify_password(password, user["password"]):
        return False
    return user

# Rotas
@app.post("/register", response_model=dict)
async def register(user: UserRegister):
    if user.email in fake_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    fake_db[user.email] = {"email": user.email, "password": hash_password(user.password)}
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
async def login(user: UserLogin):
    user_data = authenticate_user(user.email, user.password)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected")
async def protected_route(token: str = Depends(lambda: "user_token")): # Simulação de token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email not in fake_db:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"message": "You have access to the protected route"}
