import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

def generate_key():
    """Generate and save a random Fernet key."""
    key = Fernet.generate_key()
    with open(os.path.join(KEY_DIR, "secret.key"), "wb") as f:
        f.write(key)
    return key

def load_key():
    """Load the Fernet key from file."""
    with open(os.path.join(KEY_DIR, "secret.key"), "rb") as f:
        return f.read()

def derive_key_from_password(password: str):
    """Derive a Fernet key from a password using PBKDF2-HMAC-SHA256."""
    salt_path = os.path.join(KEY_DIR, "pwd.salt")
    if os.path.exists(salt_path):
        salt = open(salt_path, "rb").read()
    else:
        salt = os.urandom(16)
        open(salt_path, "wb").write(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_text(text: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(text.encode())

def decrypt_text(token: bytes, key: bytes) -> str:
    return Fernet(key).decrypt(token).decode()

def encrypt_file(filename: str, key: bytes):
    fernet = Fernet(key)
    with open(filename, "rb") as f:
        data = f.read()
    enc = fernet.encrypt(data)
    with open(filename + ".enc", "wb") as f:
        f.write(enc)

def decrypt_file(filename: str, key: bytes):
    fernet = Fernet(key)
    with open(filename, "rb") as f:
        data = f.read()
    dec = fernet.decrypt(data)
    out_file = filename.replace(".enc", ".dec")
    with open(out_file, "wb") as f:
        f.write(dec)
