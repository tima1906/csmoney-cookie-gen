"""CS.MONEY sessions through Steam OpenID in Camoufox, stored together with their proxy.

Components:
  * ``steam.SteamAuthProvider``      — Steam web cookies via aiosteampy 1.x (state, config, refresh token, login)
  * ``browser.CamoufoxAuthenticator`` — the CS.MONEY "Sign in with Steam" flow in an isolated Camoufox context
  * ``store.SessionStore``            — encrypted SQLite store of cookies + proxy + metadata
  * ``client.CsMoneyHttpClient``       — requests with a stored session (aiohttp or httpx), re-auth on rejection
  * ``manager.SessionManager``        — orchestration, verification, retries and cooldowns
"""

from .client import CsMoneyHttpClient
from .core import Account, CsMoneyAuthError, CsMoneySession, SessionStatus, Settings, load_config
from .manager import SessionManager

__all__ = [
    "Account",
    "CsMoneyAuthError",
    "CsMoneyHttpClient",
    "CsMoneySession",
    "SessionManager",
    "SessionStatus",
    "Settings",
    "load_config",
]
