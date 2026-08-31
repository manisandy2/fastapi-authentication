from pwdlib import PasswordHash


# Password hashing configuration
password_hash = PasswordHash.recommended()


# Hash a plain-text password
def hash_password(password: str) -> str:
    return password_hash.hash(password)


# Verify a password against its hash
def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(password, hashed_password)
