#

from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List
from bs4 import BeautifulSoup
import requests
import jwt
import motor.motor_asyncio
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from datetime import datetime, timedelta

# ----------------- Config ------------------

SECRET_KEY = "YOUR_JWT_SECRET_KEY"  # Change this to your secure secret!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

AES_KEY = os.urandom(32)  # 256-bit key for AES, store securely!

MONGO_DETAILS = "mongodb://localhost:27017"
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DETAILS)
db = client.scraper_db
users_collection = db.get_collection("users")
data_collection = db.get_collection("user_data")

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# -------------- Models ---------------------

class UserIn(BaseModel):
    username: str
    password: str

class UserInDB(UserIn):
    encrypted_password: bytes  # Store encrypted password (optional, demo)

class Token(BaseModel):
    access_token: str
    token_type: str

class DataItem(BaseModel):
    title: str
    content: str

# ------------- AES Encryption Utils ----------------

def encrypt_data(plaintext: str) -> bytes:
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  # prepend IV for decryption

def decrypt_data(ciphertext: bytes) -> str:
    backend = default_backend()
    iv = ciphertext[:16]
    encrypted = ciphertext[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

# -------------- JWT Utils ---------------------

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = await users_collection.find_one({"username": username})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# -------------- User Registration/Login -----------------

@app.post("/register", status_code=201)
async def register(user: UserIn):
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    encrypted_password = encrypt_data(user.password)
    user_doc = {"username": user.username, "password": encrypted_password}
    await users_collection.insert_one(user_doc)
    return {"msg": "User registered successfully"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await users_collection.find_one({"username": form_data.username})
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    decrypted_password = decrypt_data(user["password"])
    if form_data.password != decrypted_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# -------------- Scraper Function ---------------------

def scrape_user_account(username: str, password: str) -> List[dict]:
    """
    Example scrape function, adjust selectors to target site.
    You will likely need session management, csrf tokens, etc.
    """

    with requests.Session() as session:
        login_url = "https://app.mulearn.org/login"
        data_url = "https://example.com/user/data"

        # Step 1: Get login page (for csrf token if needed)
        login_page = session.get(login_url)
        soup = BeautifulSoup(login_page.text, "html.parser")

        # Assume we get CSRF token here if needed
        # csrf_token = soup.find("input", {"name":"csrf_token"})['value']

        # Step 2: Post login form
        payload = {
            "username": username,
            "password": password,
            # "csrf_token": csrf_token
        }
        response = session.post(login_url, data=payload)
        if response.url == login_url:  # Login failed if redirected back
            raise Exception("Login failed")

        # Step 3: Access data page
        data_page = session.get(data_url)
        soup = BeautifulSoup(data_page.text, "html.parser")

        # Parse data - example extracting articles
        data = []
        for item in soup.select(".data-item"):
            title = item.select_one(".title").text.strip()
            content = item.select_one(".content").text.strip()
            data.append({"title": title, "content": content})

        return data

# -------------- API Endpoint to trigger scraping ---------------------

@app.post("/scrape", response_model=List[DataItem])
async def scrape_and_store(current_user: dict = Depends(get_current_user)):
    try:
        username = current_user["username"]
        password = decrypt_data(current_user["password"])

        # Scrape
        scraped_data = scrape_user_account(username, password)

        # Store scraped data in MongoDB
        await data_collection.delete_many({"username": username})  # Clear old data
        for item in scraped_data:
            await data_collection.insert_one({"username": username, **item})

        return scraped_data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -------------- Endpoint to get scraped data ----------------------

@app.get("/data", response_model=List[DataItem])
async def get_user_data(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    data_cursor = data_collection.find({"username": username})
    data = []
    async for item in data_cursor:
        data.append(DataItem(title=item["title"], content=item["content"]))
    return data
