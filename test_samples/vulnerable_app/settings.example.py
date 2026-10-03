import os
import bcrypt
import secrets

# Good practice: load from environment, not hardcoded
DATABASE_URL = os.environ.get("DATABASE_URL")
API_KEY = os.environ.get("API_KEY", "your_api_key_here")  # placeholder example

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def gen_token():
    return secrets.token_urlsafe(32)
