import hashlib
import hmac
from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader
from starlette.status import HTTP_401_UNAUTHORIZED

from shared.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def validate_api_key(api_key: str = Depends(api_key_header)) -> str:
    if not api_key:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    incoming_hash = _hash_key(api_key)
    for valid_key in settings.api_keys:
        # Compare hashes to avoid timing attacks and avoid holding plaintext keys in memory
        if hmac.compare_digest(incoming_hash, _hash_key(valid_key)):
            return api_key

    raise HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


