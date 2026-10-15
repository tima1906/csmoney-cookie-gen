"""Orchestration: reuse a stored session while it is valid, otherwise sign in through the browser.

Guard rails against request loops:
  * one browser login at a time per account (per-account lock);
  * a bounded number of attempts per login, with backoff, retrying only transient failures;
  * after a failed login, new attempts are refused for a cooldown that doubles with each consecutive
    failure (persisted in the store, so it also survives restarts);
  * the HTTP client re-authorizes at most once per request.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import time
from collections.abc import AsyncIterator, Callable, Iterable
from typing import TYPE_CHECKING

from .client import CsMoneyHttpClient, backoff_delay
from .core import (
    Account,
    BrowserTimeoutError,
    CaptchaRequiredError,
    CloudflareChallengeError,
    ConfigError,
    CsMoneyAuthError,
    CsMoneySession,
    NetworkError,
    ReauthNotAllowed,
    RegistrationRequired,
    ResponseKind,
    ServiceUnavailableError,
    SessionInvalidError,
    SessionStatus,
    Settings,
    SteamAuthError,
    SteamCredentialsRejected,
    SteamGuardRequired,
    SteamOpenIdRejected,
    SteamSessionRejected,
    WrongSteamAccount,
    redact,
    session_expiry,
)
from .store import SecretBox, SessionStore

if TYPE_CHECKING:
    from .browser import CamoufoxAuthenticator
    from .steam import SteamAuthProvider, SteamWebSession

logger = logging.getLogger(__name__)

# failures worth another attempt within the same login (ProxyError is a NetworkError)
_TRANSIENT = (
    BrowserTimeoutError,
    CaptchaRequiredError,
    CloudflareChallengeError,
    NetworkError,
    ServiceUnavailableError,
    SteamSessionRejected,
)

# failures that retrying as-is cannot fix: the account is blocked until its credentials/proxy change or --force.
# Steam's own rate limit stays out of this list - it is temporary and handled by the normal cooldown.
_PERMANENT = (
    SteamOpenIdRejected,
    SteamCredentialsRejected,
    SteamGuardRequired,
    WrongSteamAccount,
    RegistrationRequired,
    ConfigError,
)

_EXPIRY_MARGIN = 60.0


def _account_fingerprint(account: Account) -> str:
    """A stable hash of the account's Steam credentials and proxy, so a change clears a permanent block.

    Taken from the config (not from the stored Steam state, which rotates on its own), so it is stable
    across runs until the operator edits the account.
    """
    s = account.steam
    material = "\x00".join(
        [
            s.username or "",
            s.password or "",
            s.shared_secret or "",
            s.refresh_token or "",
            s.access_token or "",
            s.cookies.get("steamLoginSecure", ""),
            s.cookies.get("steamRefresh_steam", ""),
            account.proxy.url if account.proxy else "",
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()[:32]


class SessionManager:
    def __init__(
        self,
        settings: Settings,
        accounts: Iterable[Account],
        store: SessionStore,
        steam: SteamAuthProvider | None = None,
        browser: CamoufoxAuthenticator | None = None,
    ):
        self._settings = settings
        self._accounts = {a.account_id: a for a in accounts}
        self._store = store
        self._steam = steam
        self._browser = browser
        self._locks: dict[str, asyncio.Lock] = {}

    @classmethod
    @contextlib.asynccontextmanager
    async def open(cls, settings: Settings, accounts: Iterable[Account]) -> AsyncIterator[SessionManager]:
        """Open the store; load login dependencies only when a browser login is needed."""
        box = SecretBox.load(settings.key_path)
        async with SessionStore(settings.db_path, box) as store:
            manager = cls(settings, accounts, store)
            try:
                yield manager
            finally:
                if manager._browser is not None:
                    await manager._browser.close()

    @property
    def store(self) -> SessionStore:
        return self._store

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def account_ids(self) -> list[str]:
        return list(self._accounts)

    def account(self, account_id: str) -> Account:
        try:
            return self._accounts[account_id]
        except KeyError:
            raise ConfigError(f"Unknown account {account_id!r}") from None

    def _lock(self, account_id: str) -> asyncio.Lock:
        return self._locks.setdefault(account_id, asyncio.Lock())

    # ── public API ────────────────────────────────────────────────────────────

    async def ensure_session(self, account_id: str, *, force: bool = False) -> CsMoneySession:
        """A verified session for the account: the stored one if still valid, otherwise a new browser login.

        ``force`` skips reuse and the failure cooldown (explicit operator request).
        """
        account = self.account(account_id)
        async with self._lock(account_id):
            if not force and (session := await self._reuse(account)) is not None:
                return session
            return await self._login(account, ignore_cooldown=force)

    async def ensure_all(
        self,
        account_ids: Iterable[str] | None = None,
        *,
        force: bool = False,
        on_result: Callable[[str, CsMoneySession | BaseException], None] | None = None,
    ) -> dict[str, CsMoneySession | BaseException]:
        """Ensure sessions for every account. ``on_result`` (if given) is called as each account finishes.

        Two phases: stored sessions are checked over HTTP widely in parallel first, then only the accounts
        that still need one go through a browser login, capped at ``browser_concurrency`` (each browser login
        also signs in to Steam, and dozens of simultaneous Steam sign-ins from one machine are rate-limited).
        """
        ids = list(account_ids or self._accounts)
        results: dict[str, CsMoneySession | BaseException] = {}

        def record(account_id: str, outcome: CsMoneySession | BaseException) -> None:
            results[account_id] = outcome
            if on_result is not None:
                on_result(account_id, outcome)

        pending: list[str] = list(ids)
        if not force:
            reuse_limit = asyncio.Semaphore(max(self._settings.browser_concurrency, self._settings.verify_jobs))

            async def reuse_one(account_id: str) -> str | None:
                try:
                    async with reuse_limit, self._lock(account_id):
                        outcome = await self._reuse(self.account(account_id))
                except Exception as e:  # reported per account, like the browser phase
                    outcome = e
                if outcome is None:
                    return account_id  # no valid stored session -> needs a browser login
                record(account_id, outcome)
                return None

            needs_login = await asyncio.gather(*(reuse_one(a) for a in ids))
            pending = [aid for aid in needs_login if aid is not None]

        login_limit = asyncio.Semaphore(self._settings.browser_concurrency)

        async def login_one(account_id: str) -> None:
            try:
                async with login_limit, self._lock(account_id):
                    outcome = await self._login(self.account(account_id), ignore_cooldown=force)
            except Exception as e:  # keep going for the other accounts; the caller inspects each result
                outcome = e
            record(account_id, outcome)

        await asyncio.gather(*(login_one(a) for a in pending))
        return {aid: results[aid] for aid in ids}

    async def verify(self, account_id: str) -> SessionStatus | None:
        """HTTP-only check of the stored session (no browser). None if nothing is stored."""
        session = await self._store.get(account_id)
        if session is None:
            return None
        status, error = await self._check(session)
        await self._store.mark(
            account_id, status, verified_at=time.time() if status is SessionStatus.ACTIVE else None, error=error
        )
        return status

    async def reauth(self, stale: CsMoneySession, reason: str) -> CsMoneySession:
        """Called by ``CsMoneyHttpClient`` when CS.MONEY rejects ``stale``."""
        account = self.account(stale.account_id)
        async with self._lock(stale.account_id):
            current = await self._store.get(stale.account_id)
            if current is not None and current.created_at > stale.created_at and current.status is SessionStatus.ACTIVE:
                logger.info("[%s] session was already renewed by another task", stale.account_id)
                return current
            status = SessionStatus.CHALLENGED if "cloudflare" in reason else SessionStatus.EXPIRED
            await self._store.mark(stale.account_id, status, error=reason)
            return await self._login(account)

    @contextlib.asynccontextmanager
    async def client(self, account_id: str) -> AsyncIterator[CsMoneyHttpClient]:
        """HTTP client bound to the account's session, with automatic re-authorization."""
        session = await self.ensure_session(account_id)
        async with self._http_client(session, reauth=True) as client:
            yield client

    # ── internals ─────────────────────────────────────────────────────────────

    def _http_client(self, session: CsMoneySession, *, reauth: bool) -> CsMoneyHttpClient:
        s = self._settings
        return CsMoneyHttpClient(
            session,
            backend=s.http_backend,
            timeout=s.http_timeout,
            max_retries=s.http_retries,
            backoff_base=s.backoff_base,
            backoff_max=s.backoff_max,
            reauth=self.reauth if reauth else None,
            persist=self._persist_cookies,
        )

    async def _persist_cookies(self, session: CsMoneySession) -> None:
        await self._store.update_cookies(session.account_id, session.cookies, session.expires_at)

    async def _check(self, session: CsMoneySession) -> tuple[SessionStatus, str | None]:
        async with self._http_client(session, reauth=False) as client:
            kind = await client.check_session(self._settings.check_paths)
        if kind is ResponseKind.OK:
            return SessionStatus.ACTIVE, None
        if kind is ResponseKind.CAPTCHA:
            return SessionStatus.CHALLENGED, "captcha required (code 4030) on the check request"
        if kind is ResponseKind.CHALLENGE:
            return SessionStatus.CHALLENGED, "Cloudflare challenged the HTTP check"
        return SessionStatus.EXPIRED, "cs.money rejected the cookies"

    async def _reuse(self, account: Account) -> CsMoneySession | None:
        aid = account.account_id
        session = await self._store.get(aid)
        if session is None:
            logger.info("[%s] no stored session", aid)
            return None
        wanted_proxy = account.proxy.url if account.proxy else None
        if session.proxy != wanted_proxy:
            logger.info("[%s] proxy changed since the session was obtained - a new login is needed", aid)
            return None
        if session.is_expired(_EXPIRY_MARGIN):
            logger.info("[%s] stored session has expired", aid)
            await self._store.mark(aid, SessionStatus.EXPIRED, error="expired")
            return None
        now = time.time()
        if (
            session.status is SessionStatus.ACTIVE
            and session.last_verified_at is not None
            and now - session.last_verified_at < self._settings.verify_interval
        ):
            logger.info("[%s] reusing the session verified %.0fs ago", aid, now - session.last_verified_at)
            return session

        status, error = await self._check(session)  # network / proxy / 5xx errors propagate
        if status is SessionStatus.ACTIVE:
            await self._store.mark(aid, status, verified_at=now)
            session.status, session.last_verified_at, session.last_error = status, now, None
            logger.info("[%s] stored session is valid", aid)
            return session
        await self._store.mark(aid, status, error=error)
        logger.info("[%s] stored session is no longer valid (%s)", aid, status)
        return None

    async def _check_login_allowed(self, account: Account) -> None:
        attempts = await self._store.get_login_attempts(account.account_id)
        if attempts is None or attempts.consecutive_failures == 0:
            return
        if attempts.permanent:
            # a change to the account's credentials or proxy lifts the block; otherwise skip it entirely
            if attempts.fingerprint == _account_fingerprint(account):
                raise ReauthNotAllowed(
                    f"login blocked after {attempts.consecutive_failures} failure(s) (last error: "
                    f"{attempts.last_error}); change the account's credentials/proxy or use --force to retry"
                )
            return
        s = self._settings
        cooldown = min(s.reauth_cooldown_max, s.reauth_cooldown * 2 ** (attempts.consecutive_failures - 1))
        remaining = attempts.last_attempt_at + cooldown - time.time()
        if remaining > 0:
            raise ReauthNotAllowed(
                f"{attempts.consecutive_failures} failed login(s) in a row, next attempt allowed in {remaining:.0f}s "
                f"(last error: {attempts.last_error}); use --force to override"
            )

    async def _steam_session(self, account: Account, *, force_refresh: bool) -> SteamWebSession:
        if self._browser is None:
            from .browser import CamoufoxAuthenticator

            self._browser = CamoufoxAuthenticator(self._settings)
        if self._steam is None:
            from .steam import SteamAuthProvider

            self._steam = SteamAuthProvider(
                self._store,
                token_margin=self._settings.steam_token_margin,
                guard_timeout=self._settings.guard_timeout,
                interactive=self._settings.manual,
            )
        try:
            steam = await self._steam.web_session(account, force_refresh=force_refresh)
        except SteamGuardRequired:
            raise
        except SteamAuthError as e:
            if not self._settings.manual:
                raise
            # A human signs in to Steam in the window; the browser's Steam session is stored afterwards.
            logger.warning(
                "[%s] no automatic Steam session (%s) - sign in to Steam in the browser", account.account_id, e
            )
            from .steam import SteamWebSession

            return SteamWebSession(account.steam_id or "", [], "manual")
        logger.info(
            "[%s] Steam web session ready (source=%s, steam_id=%s)", account.account_id, steam.source, steam.steam_id
        )
        return steam

    @staticmethod
    def _new_session(account: Account, result) -> CsMoneySession:
        now = time.time()
        return CsMoneySession(
            account_id=account.account_id,
            steam_id=result.steam_id or None,
            cookies=result.csmoney_cookies,
            proxy=account.proxy.url if account.proxy else None,
            user_agent=result.user_agent,
            created_at=now,
            expires_at=session_expiry(result.csmoney_cookies),
            status=SessionStatus.ACTIVE,
            last_verified_at=now,
        )

    async def _verify_new(self, session: CsMoneySession) -> None:
        """A fresh session must pass the check request over plain HTTP (same proxy and UA) before it is saved."""
        status, error = await self._check(session)
        if status is SessionStatus.ACTIVE:
            return
        url = self._settings.check_paths[0]
        if status is SessionStatus.CHALLENGED:
            raise CaptchaRequiredError(
                f"the new session fails the check request: {error}", status=403, url=url, codes=[4030]
            )
        raise SessionInvalidError(f"the new session is rejected by the check request: {error}", status=401, url=url)

    async def _login(self, account: Account, *, ignore_cooldown: bool = False) -> CsMoneySession:
        aid = account.account_id
        if not ignore_cooldown:
            await self._check_login_allowed(account)
        attempts = self._settings.login_attempts
        last_error: CsMoneyAuthError | None = None
        for attempt in range(1, attempts + 1):
            # After Steam rejected the cookies, ask aiosteampy for fresh ones instead of reusing them.
            force_steam = isinstance(last_error, SteamSessionRejected)
            try:
                logger.info(
                    "[%s] browser login attempt %d/%d (proxy=%s)", aid, attempt, attempts, account.proxy or "direct"
                )
                steam = await self._steam_session(account, force_refresh=force_steam)
                result = await self._browser.login(account, steam)
                session = self._new_session(account, result)
                await self._verify_new(session)
            except _TRANSIENT as e:
                last_error = e
                logger.warning("[%s] attempt %d/%d failed: %s: %s", aid, attempt, attempts, type(e).__name__, e)
                if attempt < attempts:
                    await asyncio.sleep(backoff_delay(attempt, self._settings.backoff_base, self._settings.backoff_max))
                continue
            except CsMoneyAuthError as e:
                if force_steam and isinstance(e, SteamAuthError):
                    e = SteamAuthError(f"Steam rejected the injected cookies and no fresh ones are available ({e})")
                last_error = e
                logger.error("[%s] login failed: %s: %s", aid, type(e).__name__, e)
                break

            await self._store.save(session)
            await self._store.record_login_attempt(aid, ok=True)
            with contextlib.suppress(CsMoneyAuthError):
                await self._steam.remember_browser_cookies(account, result.steam_cookies)
            logger.info(
                "[%s] cs.money session saved: steam_id=%s, %d cookies, expires_at=%s",
                aid,
                session.steam_id,
                len(session.cookies),
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(session.expires_at))
                if session.expires_at
                else "unknown",
            )
            return session

        assert last_error is not None
        message = redact(f"{type(last_error).__name__}: {last_error}")[:500]
        permanent = isinstance(last_error, _PERMANENT)
        await self._store.record_login_attempt(
            aid,
            ok=False,
            error=message,
            permanent=permanent,
            fingerprint=_account_fingerprint(account) if permanent else None,
        )
        if permanent:
            logger.warning(
                "[%s] login blocked (%s); skipped until credentials/proxy change or --force",
                aid,
                type(last_error).__name__,
            )
        if await self._store.get(aid) is not None:
            await self._store.mark(aid, SessionStatus.ERROR, error=message)
        raise last_error
