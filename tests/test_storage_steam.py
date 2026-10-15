"""Encrypted store and the aiosteampy-based Steam provider (no network)."""

import sqlite3
import time

import pytest
from aiosteampy.session import SteamSession
from aiosteampy.transport import Cookie as SteamCookie
from cryptography.fernet import Fernet

from csmoney_auth.core import (
    Account,
    CsMoneySession,
    ProxyConfig,
    SessionStatus,
    SteamAuthError,
    SteamCredentials,
    SteamGuardRequired,
    StorageError,
    StoredCookie,
)
from csmoney_auth.steam import SteamAuthProvider
from csmoney_auth.store import SecretBox, SessionStore

from .conftest import STEAM_ID, make_jwt


def _session(**overrides) -> CsMoneySession:
    data = dict(
        account_id="acc",
        steam_id=STEAM_ID,
        cookies=[StoredCookie("csgo_ses", "TOPSECRETCOOKIE", "cs.money", http_only=True, secure=True)],
        proxy="http://user:PROXYPASSWORD@1.2.3.4:8080",
        user_agent="UA/1.0",
        created_at=time.time(),
        expires_at=None,
        status=SessionStatus.ACTIVE,
        last_verified_at=time.time(),
    )
    data.update(overrides)
    return CsMoneySession(**data)


# ── store ──────────────────────────────────────────────────────────────────────


async def test_store_round_trip_and_encryption(store, tmp_path):
    s = _session()
    await store.save(s)
    loaded = await store.get("acc")
    assert loaded == s
    overview = await store.list_overview()
    assert overview[0]["proxy_masked"] == "http://***@1.2.3.4:8080"

    raw = (tmp_path / "sessions.db").read_bytes()
    wal = tmp_path / "sessions.db-wal"
    raw += wal.read_bytes() if wal.exists() else b""
    assert b"TOPSECRETCOOKIE" not in raw and b"PROXYPASSWORD" not in raw

    await store.mark("acc", SessionStatus.EXPIRED, error="rejected")
    loaded = await store.get("acc")
    assert loaded.status is SessionStatus.EXPIRED and loaded.last_error == "rejected"
    assert loaded.last_verified_at == s.last_verified_at  # kept when not given

    new_cookies = [StoredCookie("csgo_ses", "rotated", "cs.money")]
    await store.update_cookies("acc", new_cookies, 123.0)
    loaded = await store.get("acc")
    assert loaded.cookies == new_cookies and loaded.expires_at == 123.0

    assert await store.delete("acc") and await store.get("acc") is None


async def test_store_wrong_key(tmp_path, box):
    async with SessionStore(tmp_path / "db.sqlite", box) as s:
        await s.save(_session())
    async with SessionStore(tmp_path / "db.sqlite", SecretBox(Fernet.generate_key())) as s:
        with pytest.raises(StorageError):
            await s.get("acc")


async def test_login_attempts_counter(store):
    await store.record_login_attempt("acc", ok=False, error="e1")
    await store.record_login_attempt("acc", ok=False, error="e2")
    attempts = await store.get_login_attempts("acc")
    assert attempts.consecutive_failures == 2 and attempts.last_error == "e2"
    await store.record_login_attempt("acc", ok=True)
    assert (await store.get_login_attempts("acc")).consecutive_failures == 0


async def test_login_attempts_permanent_flag_and_fingerprint(store):
    await store.record_login_attempt("acc", ok=False, error="blocked", permanent=True, fingerprint="fp1")
    attempts = await store.get_login_attempts("acc")
    assert attempts.permanent is True and attempts.fingerprint == "fp1"
    await store.record_login_attempt("acc", ok=True)  # a success clears the block and the fingerprint
    cleared = await store.get_login_attempts("acc")
    assert cleared.permanent is False and cleared.fingerprint is None


def test_key_file_created_once(tmp_path, monkeypatch):
    monkeypatch.delenv("CSMONEY_STORE_KEY", raising=False)
    key_file = tmp_path / "k" / "store.key"
    a = SecretBox.load(key_file)
    b = SecretBox.load(key_file)
    assert b.decrypt(a.encrypt({"x": 1})) == {"x": 1}


def test_db_is_plain_sqlite(tmp_path, box):
    """The non-secret columns stay queryable with plain sqlite tools."""
    import asyncio

    async def go():
        async with SessionStore(tmp_path / "db.sqlite", box) as s:
            await s.save(_session())

    asyncio.run(go())
    conn = sqlite3.connect(tmp_path / "db.sqlite")
    try:
        assert conn.execute("SELECT account_id, status FROM sessions").fetchall() == [("acc", "active")]
    finally:
        conn.close()


# ── Steam provider ─────────────────────────────────────────────────────────────


def _account(**steam) -> Account:
    return Account("acc", None, SteamCredentials(**steam), steam_id=None)


async def test_steam_cookies_from_config(store):
    access = make_jwt()
    provider = SteamAuthProvider(store)
    ws = await provider.web_session(_account(cookies={"steamLoginSecure": f"{STEAM_ID}||{access}", "sessionid": "sid"}))
    assert ws.source == "config" and ws.steam_id == STEAM_ID
    by_name = {c.name: c for c in ws.cookies}
    assert by_name["steamLoginSecure"].value == f"{STEAM_ID}%7C%7C{access}"
    assert by_name["steamLoginSecure"].domain == "steamcommunity.com"
    assert by_name["sessionid"].value == "sid"


async def test_steam_expiring_token_without_alternatives_fails(store):
    provider = SteamAuthProvider(store, token_margin=900)
    with pytest.raises(SteamAuthError):
        await provider.web_session(_account(access_token=make_jwt(exp_in=60)))


async def test_steam_wrong_account_detected(store):
    provider = SteamAuthProvider(store)
    account = _account(access_token=make_jwt())
    account.steam_id = "76561198999999999"
    with pytest.raises(SteamAuthError, match="belong"):
        await provider.web_session(account)


async def test_steam_refresh_token_path_persists_state(store, monkeypatch):
    access = make_jwt()

    async def fake_obtain_cookies(self):  # what aiosteampy does after finalizelogin + transfers
        self._set_access_token(access)
        self._session_id = "generated"
        self.transport.add_cookie(SteamCookie("steamLoginSecure", f"{STEAM_ID}%7C%7C{access}", "steamcommunity.com"))
        self.transport.add_cookie(SteamCookie("sessionid", "generated", "steamcommunity.com", http_only=False))
        return []

    monkeypatch.setattr(SteamSession, "obtain_cookies", fake_obtain_cookies)
    provider = SteamAuthProvider(store)
    account = _account(refresh_token=make_jwt(refresh=True, exp_in=10_000_000))
    ws = await provider.web_session(account)
    assert ws.source == "refresh_token"
    assert {c.name for c in ws.cookies} >= {"steamLoginSecure", "sessionid", "steamRefresh_steam"}

    state = await store.get_steam_state("acc")
    assert state["access_token"] == access
    # next call reuses the stored access token without contacting Steam
    monkeypatch.setattr(SteamSession, "obtain_cookies", None)
    assert (await provider.web_session(account)).source == "stored"


async def test_steam_force_refresh_skips_cached_tokens(store, monkeypatch):
    calls = []

    async def fake_obtain_cookies(self):
        calls.append(1)
        token = make_jwt()
        self._set_access_token(token)
        self.transport.add_cookie(SteamCookie("steamLoginSecure", f"{STEAM_ID}%7C%7C{token}", "steamcommunity.com"))
        return []

    monkeypatch.setattr(SteamSession, "obtain_cookies", fake_obtain_cookies)
    provider = SteamAuthProvider(store)
    account = _account(access_token=make_jwt(), refresh_token=make_jwt(refresh=True, exp_in=10_000_000))
    assert (await provider.web_session(account)).source == "config"
    assert (await provider.web_session(account, force_refresh=True)).source == "refresh_token"
    assert calls == [1]


async def test_steam_guard_without_secret_in_automatic_mode(store, monkeypatch):
    from aiosteampy.session import GuardConfirmationRequired
    from aiosteampy.webapi.protobufs.auth import EAuthSessionGuardType

    async def fake_with_credentials(self, *a, **kw):
        raise GuardConfirmationRequired([], (EAuthSessionGuardType.k_EAuthSessionGuardType_EmailCode,))

    monkeypatch.setattr(SteamSession, "with_credentials", fake_with_credentials)
    provider = SteamAuthProvider(store, interactive=False)
    with pytest.raises(SteamGuardRequired, match="email code"):
        await provider.web_session(_account(username="u", password="p"))


async def test_remember_browser_cookies(store):
    provider = SteamAuthProvider(store)
    account = _account()
    access, refresh = make_jwt(), make_jwt(refresh=True, exp_in=10_000_000)
    await provider.remember_browser_cookies(
        account,
        [
            StoredCookie("steamLoginSecure", f"{STEAM_ID}%7C%7C{access}", "steamcommunity.com"),
            StoredCookie("sessionid", "sid", "steamcommunity.com"),
            StoredCookie("steamRefresh_steam", f"{STEAM_ID}%7C%7C{refresh}", "login.steampowered.com"),
        ],
    )
    state = await store.get_steam_state("acc")
    assert state["access_token"] == access and state["refresh_token"] == refresh and state["session_id"] == "sid"
    ws = await provider.web_session(account)
    assert ws.source == "stored" and ws.steam_id == STEAM_ID


async def test_proxy_is_passed_to_aiosteampy(store, monkeypatch):
    seen = {}
    original_init = SteamSession.__init__

    def spy_init(self, *args, **kwargs):
        seen["proxy"] = kwargs.get("proxy")
        original_init(self, *args, **kwargs)

    async def fake_obtain_cookies(self):
        token = make_jwt()
        self._set_access_token(token)
        self.transport.add_cookie(SteamCookie("steamLoginSecure", f"{STEAM_ID}%7C%7C{token}", "steamcommunity.com"))
        return []

    monkeypatch.setattr(SteamSession, "__init__", spy_init)
    monkeypatch.setattr(SteamSession, "obtain_cookies", fake_obtain_cookies)
    account = _account(refresh_token=make_jwt(refresh=True, exp_in=10_000_000))
    account.proxy = ProxyConfig.parse("socks5h://u:p@10.0.0.1:1080")
    await SteamAuthProvider(store).web_session(account)
    assert seen["proxy"] == "socks5://u:p@10.0.0.1:1080"
