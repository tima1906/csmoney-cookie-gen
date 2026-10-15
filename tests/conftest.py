import base64
import json
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from csmoney_auth.store import SecretBox, SessionStore

STEAM_ID = "76561198000000001"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(sub: str = STEAM_ID, *, refresh: bool = False, exp_in: int = 3600, iat_offset: int = -10) -> str:
    """Unsigned Steam-like JWT (aiosteampy parses tokens without verifying signatures)."""
    now = int(time.time())
    audience = ["web", "derive"] if refresh else ["web", "web:community"]
    claims = {
        "iss": "r:0000" if not refresh else "steam",
        "sub": sub,
        "aud": audience,
        "exp": now + exp_in,
        "nbf": now + iat_offset,
        "iat": now + iat_offset,
        "jti": "test",
        "oat": now + iat_offset,
        "rt_exp": now + 10_000_000,
        "per": 0,
        "ip_subject": "1.1.1.1",
        "ip_confirmer": "1.1.1.1",
    }
    header = {"typ": "JWT", "alg": "EdDSA"}
    return f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}.{_b64(b'signature')}"


@pytest.fixture
def box() -> SecretBox:
    return SecretBox(Fernet.generate_key())


@pytest.fixture
async def store(tmp_path: Path, box: SecretBox):
    async with SessionStore(tmp_path / "sessions.db", box) as s:
        yield s
