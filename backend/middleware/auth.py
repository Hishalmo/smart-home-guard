"""JWT verification using Supabase's JWKS endpoint (asymmetric signing)."""

from __future__ import annotations

import os
import threading
import time

import requests
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

_JWKS_TTL = 3600
_jwks_cache: dict = {"keys": None, "fetched_at": 0.0}
_jwks_lock = threading.Lock()


def _fetch_jwks(force: bool = False) -> list[dict]:
    """Return Supabase's JWKS, cached in-memory for 1 hour."""
    now = time.time()
    if (
        not force
        and _jwks_cache["keys"]
        and now - _jwks_cache["fetched_at"] < _JWKS_TTL
    ):
        return _jwks_cache["keys"]

    supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
    if not supabase_url:
        raise RuntimeError("SUPABASE_URL not configured")

    url = f"{supabase_url}/auth/v1/.well-known/jwks.json"

    with _jwks_lock:
        now = time.time()
        if (
            force
            or not _jwks_cache["keys"]
            or now - _jwks_cache["fetched_at"] >= _JWKS_TTL
        ):
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            _jwks_cache["keys"] = response.json()["keys"]
            _jwks_cache["fetched_at"] = now

    return _jwks_cache["keys"]


def _find_key(keys: list[dict], kid: str) -> dict | None:
    return next((k for k in keys if k.get("kid") == kid), None)


async def verify_token(token: str = Depends(oauth2_scheme)) -> dict:
    """Validate a Supabase JWT against the project's JWKS and return the claims."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not os.getenv("SUPABASE_URL"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SUPABASE_URL not configured",
        )

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg", "ES256")
        if not kid:
            raise credentials_exception

        keys = _fetch_jwks()
        signing_key = _find_key(keys, kid)
        if signing_key is None:
            keys = _fetch_jwks(force=True)
            signing_key = _find_key(keys, kid)
        if signing_key is None:
            raise credentials_exception

        payload = jwt.decode(
            token,
            signing_key,
            algorithms=[alg],
            options={"verify_aud": False},
        )
    except JWTError:
        raise credentials_exception

    if payload.get("sub") is None:
        raise credentials_exception

    return payload
