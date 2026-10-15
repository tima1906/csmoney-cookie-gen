"""SessionManager orchestration with a fake browser / Steam provider and a real encrypted store."""

import time

import pytest

from csmoney_auth.browser import BrowserLoginResult
from csmoney_auth.core import (
    Account,
    BrowserTimeoutError,
    ProxyConfig,
    ReauthNotAllowed,
    SessionStatus,
    Settings,
    SteamCredentials,
    SteamSessionRejected,
    StoredCookie,
    WrongSteamAccount,
)
from csmoney_auth.manager import SessionManager
from csmoney_auth.steam import SteamWebSession

from .conftest import STEAM_ID, make_jwt


class FakeSteam:
    def __init__(self):
        self.force_flags: list[bool] = []
        self.remembered = 0

    async def web_session(self, account, *, force_refresh=False):
        self.force_flags.append(force_refresh)
        return SteamWebSession(STEAM_ID, [StoredCookie("steamLoginSecure", "x", "steamcommunity.com")], "config")

    async def remember_browser_cookies(self, account, cookies):
        self.remembered += 1


class FakeBrowser:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)  # exceptions to raise before succeeding
        self.calls = 0

    async def login(self, account, steam):
        self.calls += 1
        if self.outcomes:
            raise self.outcomes.pop(0)
        session_cookie = make_jwt(exp_in=86400)
        return BrowserLoginResult(
            steam_id=STEAM_ID,
            csmoney_cookies=[
                StoredCookie("csgo_ses", session_cookie, "cs.money", http_only=True, secure=True),
                StoredCookie("cf_clearance", "cf", ".cs.money", expires=time.time() + 3600),
            ],
            steam_cookies=[],
            user_agent="Mozilla/5.0 Firefox/156.0",
        )


ACCOUNT = Account("acc", ProxyConfig.parse("http://u:p@1.2.3.4:8080"), SteamCredentials(), STEAM_ID)


async def _skip_verify(session) -> None:
    return None


def make_manager(store, browser, *, check=None, verify_new=True, **settings) -> tuple[SessionManager, FakeSteam]:
    """``verify_new=False`` keeps the real post-login check (which then uses ``check``)."""
    opts = {"login_attempts": 2, "backoff_base": 0.01, "reauth_cooldown": 60} | settings
    steam = FakeSteam()
    manager = SessionManager(Settings(**opts), [ACCOUNT], store, steam, browser)
    if check is not None:
        manager._check = check
    if verify_new:
        manager._verify_new = _skip_verify
    return manager, steam


def checker(*statuses):
    calls = []

    async def _check(session):
        calls.append(session.account_id)
        status = statuses[min(len(calls), len(statuses)) - 1]
        return status, None if status is SessionStatus.ACTIVE else "rejected"

    _check.calls = calls
    return _check


async def test_first_login_saves_bundle(store):
    browser = FakeBrowser()
    manager, steam = make_manager(store, browser)
    session = await manager.ensure_session("acc")
    assert browser.calls == 1 and steam.remembered == 1
    stored = await store.get("acc")
    assert stored.proxy == ACCOUNT.proxy.url and stored.user_agent.startswith("Mozilla")
    assert stored.status is SessionStatus.ACTIVE and stored.steam_id == STEAM_ID
    assert stored.expires_at == pytest.approx(time.time() + 86400, abs=5)  # from the csgo_ses JWT
    assert {c.name for c in stored.cookies} == {"csgo_ses", "cf_clearance"}
    assert session.cookies == stored.cookies


async def test_recently_verified_session_is_reused_without_requests(store):
    browser = FakeBrowser()
    check = checker(SessionStatus.ACTIVE)
    manager, _ = make_manager(store, browser, check=check)
    await manager.ensure_session("acc")
    await manager.ensure_session("acc")
    assert browser.calls == 1 and check.calls == []


async def test_stale_verification_triggers_http_check_then_reuse(store):
    browser = FakeBrowser()
    check = checker(SessionStatus.ACTIVE)
    manager, _ = make_manager(store, browser, check=check, verify_interval=0)
    await manager.ensure_session("acc")
    await manager.ensure_session("acc")
    assert browser.calls == 1 and check.calls == ["acc"]


async def test_rejected_session_triggers_browser_login(store):
    browser = FakeBrowser()
    manager, _ = make_manager(store, browser, check=checker(SessionStatus.EXPIRED), verify_interval=0)
    first = await manager.ensure_session("acc")
    second = await manager.ensure_session("acc")
    assert browser.calls == 2 and second.created_at >= first.created_at


async def test_proxy_change_forces_new_login(store):
    browser = FakeBrowser()
    manager, _ = make_manager(store, browser, check=checker(SessionStatus.ACTIVE))
    await manager.ensure_session("acc")
    manager._accounts["acc"] = Account("acc", ProxyConfig.parse("http://1.1.1.1:3128"), SteamCredentials(), STEAM_ID)
    await manager.ensure_session("acc")
    assert browser.calls == 2
    assert (await store.get("acc")).proxy == "http://1.1.1.1:3128"


async def test_transient_failure_is_retried(store):
    browser = FakeBrowser(BrowserTimeoutError("slow"))
    manager, _ = make_manager(store, browser)
    await manager.ensure_session("acc")
    assert browser.calls == 2


async def test_steam_rejection_requests_fresh_steam_cookies(store):
    browser = FakeBrowser(SteamSessionRejected("login form"))
    manager, steam = make_manager(store, browser)
    await manager.ensure_session("acc")
    assert steam.force_flags == [False, True]


async def test_permanent_failure_stops_and_sets_cooldown(store):
    browser = FakeBrowser(WrongSteamAccount("other account"), WrongSteamAccount("other account"))
    manager, _ = make_manager(store, browser)
    with pytest.raises(WrongSteamAccount):
        await manager.ensure_session("acc")
    assert browser.calls == 1  # not retried
    with pytest.raises(ReauthNotAllowed):
        await manager.ensure_session("acc")
    assert browser.calls == 1  # cooldown: browser not started again
    with pytest.raises(WrongSteamAccount):
        await manager.ensure_session("acc", force=True)  # explicit override
    assert browser.calls == 2


async def test_failed_relogin_marks_existing_session(store):
    browser = FakeBrowser()
    manager, _ = make_manager(store, browser, login_attempts=1)
    await manager.ensure_session("acc")
    browser.outcomes = [BrowserTimeoutError("slow")]
    with pytest.raises(BrowserTimeoutError):
        await manager.ensure_session("acc", force=True)
    stored = await store.get("acc")
    assert stored.status is SessionStatus.ERROR and "BrowserTimeoutError" in stored.last_error


async def test_reauth_reuses_session_renewed_by_another_task(store):
    browser = FakeBrowser()
    manager, _ = make_manager(store, browser)
    stale = await manager.ensure_session("acc")
    stale.created_at -= 100  # pretend the client holds an older session
    fresh = await manager.reauth(stale, "HTTP 400 codes=[6]")
    assert browser.calls == 1 and fresh.created_at > stale.created_at


async def test_reauth_logs_in_again(store):
    browser = FakeBrowser()
    manager, _ = make_manager(store, browser)
    stale = await manager.ensure_session("acc")
    await manager.reauth(stale, "cloudflare challenge")
    assert browser.calls == 2


async def test_ensure_all_collects_errors(store):
    browser = FakeBrowser(WrongSteamAccount("x"))
    manager, _ = make_manager(store, browser, login_attempts=1)
    results = await manager.ensure_all()
    assert isinstance(results["acc"], WrongSteamAccount)


class NoSteam(FakeSteam):
    async def web_session(self, account, *, force_refresh=False):
        from csmoney_auth.core import SteamAuthError

        raise SteamAuthError("nothing configured")


@pytest.mark.parametrize("manual", [False, True])
async def test_manual_mode_lets_a_human_sign_in_to_steam(store, manual):
    from csmoney_auth.core import SteamAuthError

    browser = FakeBrowser()
    manager = SessionManager(Settings(manual=manual, login_attempts=1), [ACCOUNT], store, NoSteam(), browser)
    manager._verify_new = _skip_verify
    if manual:
        await manager.ensure_session("acc")  # browser opened without Steam cookies
        assert browser.calls == 1
    else:
        with pytest.raises(SteamAuthError):
            await manager.ensure_session("acc")
        assert browser.calls == 0


async def test_new_session_must_pass_the_check_request_or_login_is_retried(store):
    """cs.money answers 4030 until the market page was scrolled: a session failing the check is not saved."""
    browser = FakeBrowser()
    check = checker(SessionStatus.CHALLENGED, SessionStatus.ACTIVE)
    manager, _ = make_manager(store, browser, check=check, verify_new=False)
    session = await manager.ensure_session("acc")
    assert browser.calls == 2 and check.calls == ["acc", "acc"]
    assert (await store.get("acc")).status is SessionStatus.ACTIVE and session.status is SessionStatus.ACTIVE


async def test_session_failing_the_check_every_time_is_not_saved(store):
    from csmoney_auth.core import CaptchaRequiredError

    browser = FakeBrowser()
    manager, _ = make_manager(store, browser, check=checker(SessionStatus.CHALLENGED), verify_new=False)
    with pytest.raises(CaptchaRequiredError):
        await manager.ensure_session("acc")
    assert browser.calls == 2 and await store.get("acc") is None
    with pytest.raises(ReauthNotAllowed):  # cooldown after the failed login
        await manager.ensure_session("acc")


async def test_rejected_new_session_is_a_permanent_failure(store):
    from csmoney_auth.core import SessionInvalidError

    browser = FakeBrowser()
    manager, _ = make_manager(store, browser, check=checker(SessionStatus.EXPIRED), verify_new=False)
    with pytest.raises(SessionInvalidError):
        await manager.ensure_session("acc")
    assert browser.calls == 1


async def test_ensure_all_limits_parallel_logins(store):
    import asyncio

    running = peak = 0

    class SlowBrowser(FakeBrowser):
        async def login(self, account, steam):
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0.05)
            running -= 1
            return await super().login(account, steam)

    accounts = [Account(f"a{i}", None, SteamCredentials(), None) for i in range(6)]
    manager = SessionManager(Settings(browser_concurrency=2), accounts, store, FakeSteam(), SlowBrowser())
    manager._verify_new = _skip_verify
    results = await manager.ensure_all()
    assert all(not isinstance(r, BaseException) for r in results.values()) and len(results) == 6
    assert peak == 2
