import os, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(os.path.join(KEY_DIR, "rsa_private.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(os.path.join(KEY_DIR, "rsa_public.pem"), "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_keys():
    with open(os.path.join(KEY_DIR, "rsa_private.pem"), "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(KEY_DIR, "rsa_public.pem"), "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def rsa_encrypt_text(message: str, public_key) -> str:
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt_text(ciphertext_b64: str, private_key) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plaintext.decode()
