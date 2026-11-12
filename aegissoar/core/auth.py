from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    try:
        # Check if it's already argon2 hashed
        if hashed.startswith("$argon2"):
            return ph.verify(hashed, password)
        # Check if legacy SHA-256
        elif len(hashed) == 64:
            import hashlib
            if hashlib.sha256(password.encode()).hexdigest() == hashed:
                return True
        return False
    except VerifyMismatchError:
        return False

def needs_rehash(hashed: str) -> bool:
    return not hashed.startswith("$argon2")
