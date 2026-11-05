"""No authentication secrets shipped with production deployments."""
import hashlib, hmac, os, secrets, time

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    iterations = 310_000
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return f'pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}'

def verify_password(password: str, stored: str) -> bool:
    try:
        alg, rounds, salt, value = stored.split('$')
        if alg != 'pbkdf2_sha256': return False
        candidate = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(candidate, bytes.fromhex(value))
    except (ValueError, TypeError):
        # The original dump has legacy unsalted SHA256 hashes; accept only after
        # a user knows their actual password, then migrate it on successful login.
        if len(stored or '') == 64:
            return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)
        return False

def make_session(secret: str, uid: int = 0) -> str:
    value = f'{uid}.{int(time.time()) + 86400}.{secrets.token_hex(12)}'
    sig = hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f'{value}.{sig}'

def parse_session(secret: str, token: str | None):
    if not token: return None
    try:
        value, signature = token.rsplit('.', 1)
        expected = hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()
        uid, exp, _nonce = value.split('.')
        if not hmac.compare_digest(signature, expected) or int(exp) < time.time(): return None
        return int(uid)
    except (ValueError, TypeError): return None

def csrf_for(secret: str, token: str) -> str:
    return hmac.new(secret.encode(), ('csrf:' + token).encode(), hashlib.sha256).hexdigest()

def check_csrf(secret: str, token: str | None, posted: str | None) -> bool:
    return bool(token and posted and hmac.compare_digest(csrf_for(secret, token), posted))
