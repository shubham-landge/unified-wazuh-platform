import hashlib
import hmac
from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from app.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def validate_api_key(api_key: str = Depends(api_key_header)) -> str:
    if not api_key:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    for valid_key in settings.api_keys:
        if hmac.compare_digest(api_key, valid_key):
            return api_key

    raise HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


async def get_tenant_id(request: Request) -> str:
    api_key = request.headers.get("X-API-Key", "")
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
    return key_hash
