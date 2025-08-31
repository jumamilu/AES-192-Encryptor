from argon2.low_level import hash_secret_raw, Type
from base64 import b64encode
import os
import string

def is_valid_password(password: str) -> bool:
    """
    Validates that the password:
    - Has at least 8 characters
    - Contains letters, digits, and punctuation
    """
    if len(password) < 8:
        return False
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_punct = any(c in string.punctuation for c in password)
    return has_letter and has_digit and has_punct

def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derives a 24-byte key using Argon2i from the password.
    Generates a secure 16-byte salt.
    """
    if salt is None:
        salt = os.urandom(16)  # Always generate random salt

    password_bytes = password.encode('utf-8')

    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=3,          # Recommended iteration count
        memory_cost=65536,    # 64 MB memory usage
        parallelism=1,        # One thread
        hash_len=24,          # AES-192 requires 24 bytes
        type=Type.I,          # Use Argon2i
        version=0x13          # Argon2 version 1.3
    )

    return key, salt

if __name__ == "__main__":
    pwd = input("Enter a secure password: ")

    if not is_valid_password(pwd):
        print("❌ Password must be at least 8 characters long and include letters, digits, and punctuation marks.")
    else:
        key, salt = derive_key(pwd)
        print("✅ Derived Key (Base64):", b64encode(key).decode())
        print("🔑 Salt (Base64):", b64encode(salt).decode())
