"""Steam side of the flow, built on aiosteampy 1.x (``SteamSession``).

aiosteampy does not know anything about CS.MONEY. Its job here is to produce a valid set of Steam web
cookies (``steamLoginSecure`` + ``sessionid`` for steamcommunity.com, plus ``steamRefresh_steam`` for
login.steampowered.com when available). The browser then uses them on the Steam OpenID page.

Sources, in order of preference:
  1. Steam state persisted by a previous run (tokens refreshed by aiosteampy or seen in the browser);
  2. cookies / access token from the account config, if the access token is not about to expire;
  3. a refresh token (config, maFile, ``steamRefresh_steam`` cookie, persisted state) →
     ``SteamSession.obtain_cookies()`` — the regular Steam "finalize login" with transfers;
  4. username + password → ``SteamSession.with_credentials()`` with the confirmation Steam asks for:
     a code from the account's own ``shared_secret``, or — in manual mode — a code typed by the
     user / approval in the Steam mobile app. Nothing here bypasses Steam Guard.
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from aiosteampy.guard import SharedSecret
from aiosteampy.session import (
    BadCredentials,
    EResultError,
    GuardConfirmationRequired,
    LoginError,
    RateLimitExceeded,
    SteamError,
    SteamJWT,
    SteamSession,
    TooManyAttempts,
    TransportError,
    generate_session_id,
)
from aiosteampy.session import NetworkError as SteamNetworkError
from aiosteampy.session import ProxyError as SteamProxyError
from aiosteampy.transport import Cookie as SteamCookie

from .core import Account, NetworkError, ProxyError, SteamAuthError, SteamGuardRequired, StoredCookie
from .store import SessionStore

logger = logging.getLogger(__name__)

ACCESS_COOKIE = "steamLoginSecure"
REFRESH_COOKIE = "steamRefresh_steam"
SESSION_ID_COOKIE = "sessionid"
STEAM_AUTH_COOKIES = (ACCESS_COOKIE, REFRESH_COOKIE, SESSION_ID_COOKIE)

COMMUNITY_HOST = "steamcommunity.com"
LOGIN_HOST = "login.steampowered.com"
STEAM_HOSTS = (
    COMMUNITY_HOST,
    LOGIN_HOST,
    "store.steampowered.com",
    "help.steampowered.com",
    "checkout.steampowered.com",
    "steam.tv",
)

COOKIE_SEP = "%7C%7C"


@dataclass(slots=True)
class SteamWebSession:
    steam_id: str
    cookies: list[StoredCookie] = field(repr=False)
    source: str  # stored | config | refresh_token | credentials


def _parse_token(value: str) -> SteamJWT:
    value = value.strip().replace("||", COOKIE_SEP)
    return SteamJWT.from_cookie_value(value) if COOKIE_SEP in value else SteamJWT.parse(value)


def _steam_cookie(
    name: str, value: str, host: str, expires: float | None = None, *, http_only: bool = True
) -> StoredCookie:
    return StoredCookie(name, value, host, "/", expires, http_only=http_only, secure=True, same_site="None")


def is_steam_cookie(c: StoredCookie) -> bool:
    host = c.domain.lstrip(".").lower()
    return c.name in STEAM_AUTH_COOKIES and any(host == h or host.endswith("." + h) for h in STEAM_HOSTS)


class SteamAuthProvider:
    def __init__(
        self,
        store: SessionStore,
        *,
        token_margin: float = 900,
        guard_timeout: float = 180,
        interactive: bool = False,
        prompt: Callable[[str], Awaitable[str]] | None = None,
    ):
        self._store = store
        self._margin = token_margin
        self._guard_timeout = guard_timeout
        self._interactive = interactive
        self._prompt = prompt or _console_prompt
        self._prompt_lock = asyncio.Lock()

    def _usable(self, token: SteamJWT) -> bool:
        return token.is_access_token and token.expires_at.timestamp() - time.time() > self._margin

    @staticmethod
    def _proxy_url(account: Account) -> str | None:
        return account.proxy.socks_client_url() if account.proxy else None

    async def web_session(self, account: Account, *, force_refresh: bool = False) -> SteamWebSession:
        """Return Steam web cookies for ``account``. ``force_refresh`` skips cached access tokens."""
        state = await self._store.get_steam_state(account.account_id)
        reasons: list[str] = []

        if not force_refresh:
            if state and (ws := await self._from_state(account, state)):
                return ws
            if ws := self._from_config(account):
                return ws

        for label, raw in self._refresh_tokens(account, state):
            try:
                return await self._via_refresh_token(account, raw)
            except SteamAuthError as e:
                reasons.append(f"{label}: {e}")
                logger.warning("[%s] Steam refresh token from %s is not usable: %s", account.account_id, label, e)

        if account.steam.username and account.steam.password:
            return await self._via_credentials(account)

        reasons = reasons or ["no non-expired steamLoginSecure, refresh token or username/password"]
        raise SteamAuthError("Cannot obtain a Steam web session - " + "; ".join(reasons))

    # ── sources ───────────────────────────────────────────────────────────────

    async def _from_state(self, account: Account, state: dict) -> SteamWebSession | None:
        try:
            session = SteamSession.deserialize(state, proxy=self._proxy_url(account))
        except (ValueError, KeyError) as e:
            logger.warning("[%s] stored Steam state is unusable (%s) - ignoring it", account.account_id, e)
            return None
        try:
            if session.access_token is None or not self._usable(session.access_token):
                return None
            cookies = self._collect(session)
            if not any(c.name == ACCESS_COOKIE and c.domain.lstrip(".") == COMMUNITY_HOST for c in cookies):
                return None
            logger.debug("[%s] using stored Steam access token", account.account_id)
            return self._checked(account, SteamWebSession(str(session.steam_id), cookies, "stored"))
        finally:
            await session.transport.close()

    def _from_config(self, account: Account) -> SteamWebSession | None:
        steam = account.steam
        raw = steam.cookies.get(ACCESS_COOKIE) or steam.access_token
        if not raw:
            return None
        try:
            token = _parse_token(raw)
        except ValueError as e:
            raise SteamAuthError(f"steamLoginSecure / access_token in the config is malformed: {e}") from None
        if not self._usable(token):
            logger.info("[%s] Steam access token from the config is expired or about to expire", account.account_id)
            return None
        session_id = steam.cookies.get(SESSION_ID_COOKIE) or generate_session_id()
        cookies = [
            _steam_cookie(ACCESS_COOKIE, token.cookie_value, COMMUNITY_HOST, token.expires_at.timestamp()),
            _steam_cookie(SESSION_ID_COOKIE, session_id, COMMUNITY_HOST, http_only=False),
        ]
        if refresh := steam.cookies.get(REFRESH_COOKIE):
            cookies.append(_steam_cookie(REFRESH_COOKIE, refresh, LOGIN_HOST))
        return self._checked(account, SteamWebSession(str(token.subject), cookies, "config"))

    def _refresh_tokens(self, account: Account, state: dict | None) -> list[tuple[str, str]]:
        candidates = [
            ("stored state", (state or {}).get("refresh_token")),
            ("config", account.steam.refresh_token),
            ("config cookie", account.steam.cookies.get(REFRESH_COOKIE)),
        ]
        seen: set[str] = set()
        out = []
        for label, raw in candidates:
            if raw and raw not in seen:
                seen.add(raw)
                out.append((label, raw))
        return out

    async def _via_refresh_token(self, account: Account, raw: str) -> SteamWebSession:
        try:
            token = _parse_token(raw)
        except ValueError as e:
            raise SteamAuthError(f"malformed refresh token: {e}") from None
        if not token.is_refresh_token:
            raise SteamAuthError("the token is not a refresh token")
        if token.expired:
            raise SteamAuthError(f"refresh token expired at {token.expires_at:%Y-%m-%d}")

        session = SteamSession(refresh_token=token, proxy=self._proxy_url(account))
        try:
            await self._call(account, session.obtain_cookies())
            logger.info("[%s] Steam web cookies obtained with the refresh token", account.account_id)
            return await self._persist(account, session, "refresh_token")
        finally:
            await session.transport.close()

    async def _via_credentials(self, account: Account) -> SteamWebSession:
        steam = account.steam
        session = SteamSession(proxy=self._proxy_url(account))
        try:
            finalize_timeout = 0.0
            try:
                await self._call(account, session.with_credentials(steam.username, steam.password))
            except GuardConfirmationRequired as e:
                finalize_timeout = await self._confirm(account, session, e)
            await self._call(account, session.finalize(timeout=finalize_timeout))
            await self._call(account, session.obtain_cookies())
            logger.info("[%s] signed in to Steam with credentials", account.account_id)
            return await self._persist(account, session, "credentials")
        finally:
            await session.transport.close()

    async def _confirm(self, account: Account, session: SteamSession, e: GuardConfirmationRequired) -> float:
        """Complete the confirmation Steam asked for. Returns the polling timeout for ``finalize``."""
        aid = account.account_id
        if e.device_code and account.steam.shared_secret:
            code = SharedSecret(account.steam.shared_secret).generate_auth_code()
            await self._call(account, session.submit_auth_code(code, "device"))
            return 0.0
        options = (
            ("device code", e.device_code),
            ("email code", e.email_code),
            ("mobile app approval", e.device_conf),
            ("email approval", e.email_conf),
        )
        kinds = [name for name, required in options if required]
        if not self._interactive:
            raise SteamGuardRequired(
                f"Steam requires {' / '.join(kinds)}; add shared_secret (maFile) or run with --manual"
            )
        if e.device_conf or e.email_conf:
            where = "the Steam mobile app" if e.device_conf else "the confirmation email"
            logger.warning("[%s] approve the Steam sign-in in %s (waiting up to %ds)", aid, where, self._guard_timeout)
            return self._guard_timeout
        code_type = "device" if e.device_code else "email"
        async with self._prompt_lock:
            code = (await self._prompt(f"[{aid}] Steam Guard {code_type} code: ")).strip()
        if not code:
            raise SteamGuardRequired("no Steam Guard code entered")
        await self._call(account, session.submit_auth_code(code, code_type))
        return 0.0

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _call(self, account: Account, coro: Awaitable):
        """Translate aiosteampy errors into package errors."""
        try:
            return await coro
        except (GuardConfirmationRequired, SteamAuthError):
            raise
        except BadCredentials:
            raise SteamAuthError("Steam rejected the credentials / Steam Guard code") from None
        except TooManyAttempts:
            raise SteamAuthError("Steam: too many login attempts, try again later") from None
        except (LoginError, EResultError) as e:
            raise SteamAuthError(f"Steam login error: {e!r}") from None
        except SteamProxyError as e:
            raise ProxyError(f"proxy {account.proxy} failed for Steam: {e.__cause__ or e}") from None
        except SteamNetworkError as e:
            raise NetworkError(f"network error talking to Steam: {e.__cause__ or e}") from None
        except RateLimitExceeded:
            raise SteamAuthError("Steam rate limit exceeded, try again later") from None
        except TransportError as e:
            raise SteamAuthError(f"Steam request failed{e}") from None
        except SteamError as e:
            raise SteamAuthError(f"Steam error: {e!r}") from None

    @staticmethod
    def _collect(session: SteamSession) -> list[StoredCookie]:
        cookies = [StoredCookie.from_steam(c) for c in session.transport.get_cookies()]
        return [c for c in cookies if is_steam_cookie(c)]

    @staticmethod
    def _checked(account: Account, ws: SteamWebSession) -> SteamWebSession:
        if account.steam_id and ws.steam_id != account.steam_id:
            raise SteamAuthError(f"Steam credentials belong to {ws.steam_id}, expected {account.steam_id}")
        return ws

    async def _persist(self, account: Account, session: SteamSession, source: str) -> SteamWebSession:
        await self._store.save_steam_state(account.account_id, str(session.steam_id), session.serialize())
        return self._checked(account, SteamWebSession(str(session.steam_id), self._collect(session), source))

    async def remember_browser_cookies(self, account: Account, cookies: list[StoredCookie]) -> None:
        """Persist a Steam session seen in the browser if it is newer than the stored one.

        Covers a manual Steam sign-in in the window (the browser then holds a fresh access token and,
        with "remember me", a refresh token) and Steam-side token refreshes during the flow.
        """
        by_name = {
            c.name: c for c in cookies if is_steam_cookie(c) and c.domain.lstrip(".") in (COMMUNITY_HOST, LOGIN_HOST)
        }
        access = by_name.get(ACCESS_COOKIE)
        if access is None:
            return
        try:
            access_token = _parse_token(access.value)
            refresh_token = _parse_token(by_name[REFRESH_COOKIE].value) if REFRESH_COOKIE in by_name else None
        except ValueError:
            return
        if access_token.expired:
            return

        state = await self._store.get_steam_state(account.account_id)
        if state and state.get("access_token"):
            try:
                if _parse_token(state["access_token"]).issued_at >= access_token.issued_at:
                    return  # nothing newer
            except ValueError:
                pass
            if refresh_token is None and state.get("refresh_token"):
                refresh_token = _parse_token(state["refresh_token"])

        try:
            session = SteamSession(access_token, refresh_token, proxy=self._proxy_url(account))
        except ValueError as e:
            logger.debug("[%s] browser Steam tokens not stored: %s", account.account_id, e)
            return
        try:
            for c in cookies:
                if is_steam_cookie(c):
                    session.transport.add_cookie(SteamCookie(c.name, c.value, c.domain.lstrip("."), c.path))
            data = session.serialize()
            data["session_id"] = by_name[SESSION_ID_COOKIE].value if SESSION_ID_COOKIE in by_name else None
            await self._store.save_steam_state(account.account_id, str(session.steam_id), data)
            logger.info("[%s] stored the Steam session seen in the browser", account.account_id)
        finally:
            await session.transport.close()


async def _console_prompt(message: str) -> str:
    return await asyncio.to_thread(input, message)
