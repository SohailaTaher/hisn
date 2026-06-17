"""Authentication helpers: password hashing + JWT tokens."""
import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session

from hisn.api.db import get_session
from hisn.api.models import User

# --- Configuration ---

SECRET_KEY = os.environ.get(
    "HISN_SECRET_KEY",
    "dev-secret-CHANGE-IN-PRODUCTION-this-is-not-safe",
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# OAuth2 scheme: FastAPI reads "Authorization: Bearer <token>" headers
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# --- Password hashing ---

def hash_password(plain: str) -> str:
    """Hash a password with bcrypt. Returns a hash string safe to store."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Check a plain password against a stored hash. Returns True if match."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# --- JWT tokens ---

def create_access_token(user_id: int) -> str:
    """Create a JWT for the given user, valid for ACCESS_TOKEN_EXPIRE_HOURS."""
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode a JWT. Raises jwt.PyJWTError on invalid/expired tokens."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


# --- FastAPI dependency: extract current user from JWT ---

def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    """
    FastAPI dependency that resolves the authenticated user from the Authorization header.
    Add as a parameter to any route you want to protect:
        def some_route(user: User = Depends(get_current_user)): ...
    """
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise credentials_error

    user = session.get(User, user_id)
    if not user or not user.is_active:
        raise credentials_error
    return user