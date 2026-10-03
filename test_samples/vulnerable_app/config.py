import hashlib
import random
from Crypto.Cipher import DES

# --- Hardcoded credentials (BAD) ---
DATABASE_URL = "postgres://admin:SuperSecret123!@db.prod.internal:5432/appdb"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_live_51H8xyzABCDEFGHIJKLMNOPQRSTUV1234567890abcd"
API_KEY = "8f14e45fceea167a5a36dedd4bea2543a938a5c8c9d6b2f"

SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# --- Weak crypto (BAD) ---
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def legacy_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def gen_session_token():
    return str(random.random())

IV = "0000000000000000"

# --- Private key committed directly ---
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJK
-----END RSA PRIVATE KEY-----"""
