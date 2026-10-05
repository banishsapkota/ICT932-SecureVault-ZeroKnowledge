from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(password):
    return ph.hash(password)


def verify_password(password, password_hash):
    try:
        return ph.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False
