import secrets
import string


def generate_password(length: int = 18, include_symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if include_symbols:
        alphabet += string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def analyze_password_strength(password: str) -> dict:
    score = 0
    if len(password) >= 12:
        score += 1
    if any(ch.islower() for ch in password):
        score += 1
    if any(ch.isupper() for ch in password):
        score += 1
    if any(ch.isdigit() for ch in password):
        score += 1
    if any(ch in string.punctuation for ch in password):
        score += 1
    entropy = len(password) * 4
    return {
        "score": score,
        "entropy": entropy,
        "strong": score >= 4 and entropy >= 48,
    }
