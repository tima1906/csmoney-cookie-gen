"""CS.MONEY sign-in through Steam OpenID in Camoufox.

One Camoufox browser process is shared; every login runs in its own ``AsyncNewContext`` — a separate
cookie jar / storage / cache with its own fingerprint and its own proxy — which is closed afterwards.

Stages (each one is checked before moving on):
  1. open cs.money through the account's proxy and wait until no Cloudflare interstitial is shown;
  2. open the URL of the site's "Sign in with Steam" button → redirect chain to Steam OpenID;
  3. on Steam: the injected Steam cookies must make the page show the approval form for the expected
     Steam ID; press "Sign In" (in manual mode a human may sign in to Steam in the window instead);
  4. back on cs.money: the page must report ``isLogged`` with the same Steam ID and
     ``/api/public/v3/user-info`` must answer 200 without errors;
  5. collect the cs.money cookies (all attributes) and the browser's User-Agent.

Captchas / interactive Cloudflare checks are never solved automatically: in manual mode the flow
waits for a human, otherwise it fails with ``CloudflareChallengeError``.
"""

import asyncio
import contextlib
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from camoufox import AsyncCamoufox, AsyncNewContext
from camoufox.exceptions import CamoufoxNotInstalled, InvalidIP, InvalidProxy
from playwright.async_api import Browser, BrowserContext, Locator, Page, Response
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from . import core as csmoney
from .core import (
    Account,
    BrowserError,
    BrowserTimeoutError,
    CloudflareChallengeError,
    ConfigError,
    CsMoneyAuthError,
    CsMoneyLoginFailed,
    NetworkError,
    ProxyConfig,
    ProxyError,
    RegistrationRequired,
    Settings,
    SteamOpenIdRejected,
    SteamSessionRejected,
    StoredCookie,
    UnexpectedPageError,
    WrongSteamAccount,
    browser_proxy,
    redact,
)
from .steam import COMMUNITY_HOST, SteamWebSession, is_steam_cookie

logger = logging.getLogger(__name__)

_G_STEAM_ID = re.compile(r"g_steamID\s*=\s*\"(\d{17})\"")
_APPROVAL_FORM = 'form:has(input[name="openidparams"])'
# error boxes of Steam's OpenID / generic error pages; falls back to the page title
_STEAM_ERROR_JS = """() => {
    const sel = '#error_display, .error_ctn, #error_box, .profile_fatalerror_message, .openid_error, .error';
    for (const el of document.querySelectorAll(sel)) {
        const text = (el.innerText || '').trim();
        if (text && el.offsetParent !== null) return text;
    }
    return document.title;
}"""
_PROXY_FAILURES = ("NS_ERROR_PROXY", "NS_ERROR_UNKNOWN_PROXY_HOST", "PROXY_CONNECTION")
_NETWORK_FAILURES = (
    "NS_ERROR_NET_",
    "NS_ERROR_CONNECTION_REFUSED",
    "NS_ERROR_UNKNOWN_HOST",
    "NS_ERROR_OFFLINE",
    "NS_ERROR_ABORT",
    "SSL_ERROR",
    "PR_CONNECT_RESET",
    "PR_END_OF_FILE",
)


@dataclass(slots=True)
class BrowserLoginResult:
    steam_id: str
    csmoney_cookies: list[StoredCookie] = field(repr=False)
    steam_cookies: list[StoredCookie] = field(repr=False)
    user_agent: str


@dataclass(slots=True)
class _OpenIdPage:
    logged_in: bool
    steam_id: str | None
    submit: Locator | None


def _map_playwright_error(e: PlaywrightError, stage: str) -> CsMoneyAuthError:
    message = str(e)
    first_line = redact(message.strip().splitlines()[0] if message.strip() else type(e).__name__)
    if any(code in message for code in _PROXY_FAILURES):
        return ProxyError(f"{stage}: proxy failure ({first_line})")
    if any(code in message for code in _NETWORK_FAILURES):
        return NetworkError(f"{stage}: network failure ({first_line})")
    return BrowserError(f"{stage}: {first_line}")


def _short(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.path}?{parts.query[:60]}" if parts.query else parts.path


def _wait_enter() -> None:
    try:
        input()
    except EOFError:  # no console attached: wait for the window to be closed instead
        threading.Event().wait()


async def accept_cookie_banner(page: Page) -> bool:
    """Click "Принять все" / "Accept all" on cs.money's cookie banner, if it is shown."""
    banner = page.get_by_role("button", name=re.compile("^(Принять все|Accept all)$", re.I))
    try:
        await banner.first.wait_for(state="visible", timeout=3000)
    except PlaywrightTimeoutError:
        return False
    try:
        await banner.first.click(timeout=5000)
    except PlaywrightError:
        await banner.first.evaluate("el => el.click()")  # the banner animates; a normal click may never settle
    await page.wait_for_timeout(500)
    return True


_PERSONAL_URL = "https://cs.money/ru/personal-info/"
_TRADE_URL = re.compile(r"https://steamcommunity\.com/tradeoffer/new/\?partner=\d+&token=[\w-]+$")


class CamoufoxAuthenticator:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._camoufox: AsyncCamoufox | None = None
        self._browser: Browser | None = None
        self._launch_lock = asyncio.Lock()
        self._slots = asyncio.Semaphore(settings.browser_concurrency)

    async def __aenter__(self) -> "CamoufoxAuthenticator":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        async with self._launch_lock:
            await self._shutdown()

    async def _shutdown(self) -> None:
        cm, self._camoufox, self._browser = self._camoufox, None, None
        if cm is not None:
            with contextlib.suppress(Exception):
                await cm.__aexit__(None, None, None)

    async def _ensure_browser(self) -> Browser:
        """Launch Camoufox lazily (and again if the process died)."""
        async with self._launch_lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser
            await self._shutdown()
            s = self._settings
            visible = not s.headless or s.manual
            options: dict = {"headless": not visible}
            if s.window:
                options["window"] = tuple(s.window)
            elif visible:
                options["window"] = (1280, 720)  # a generated window is often larger than the screen
            cm = AsyncCamoufox(**options)
            started = time.monotonic()
            try:
                browser = await asyncio.wait_for(cm.__aenter__(), s.launch_timeout)
            except CamoufoxNotInstalled:
                raise BrowserError("Camoufox browser is not installed - run: python -m camoufox fetch") from None
            except TimeoutError:
                raise BrowserTimeoutError(f"Camoufox did not start within {s.launch_timeout:.0f}s") from None
            except PlaywrightError as e:
                raise _map_playwright_error(e, "browser launch") from None
            if not isinstance(browser, Browser):  # persistent_context is never used here
                raise BrowserError("unexpected Camoufox launch result")
            self._camoufox, self._browser = cm, browser
            logger.info("Camoufox %s started in %.1fs", browser.version, time.monotonic() - started)
            return browser

    async def login(self, account: Account, steam: SteamWebSession) -> BrowserLoginResult:
        manual = self._settings.manual
        budget = self._settings.login_timeout + (self._settings.manual_timeout if manual else 0)
        async with self._slots:
            browser = await self._ensure_browser()
            async with browser_proxy(account.proxy) as proxy:
                context = await self._new_context(browser, account, proxy)
                try:
                    async with asyncio.timeout(budget):
                        result = await self._flow(context, account, steam, manual)
                    if self._settings.keep_open:
                        await self._hold_open(context, account.account_id)
                    return result
                except TimeoutError:
                    raise BrowserTimeoutError(f"login flow did not finish within {budget:.0f}s") from None
                finally:
                    with contextlib.suppress(Exception):
                        await context.close()

    async def _new_context(self, browser: Browser, account: Account, proxy: ProxyConfig | None) -> BrowserContext:
        kwargs: dict = {}
        if self._settings.browser_os:
            kwargs["os"] = self._settings.browser_os
        if proxy is not None:
            # Camoufox looks up the proxy's exit IP to align timezone / WebRTC with it — this doubles as a
            # reachability check of the proxy before any page is opened.
            kwargs["proxy"] = proxy.to_playwright()
        try:
            context = await asyncio.wait_for(AsyncNewContext(browser, **kwargs), self._settings.navigation_timeout)
        except InvalidIP as e:
            raise ProxyError(f"proxy {account.proxy} is unreachable ({redact(str(e))[:200]})") from None
        except InvalidProxy as e:
            raise ConfigError(f"proxy {account.proxy} rejected by Camoufox: {redact(str(e))}") from None
        except TimeoutError:
            raise ProxyError(f"browser context with proxy {account.proxy} was not ready in time") from None
        except PlaywrightError as e:
            raise _map_playwright_error(e, "browser context") from None
        timeout_ms = self._settings.navigation_timeout * 1000
        context.set_default_timeout(timeout_ms)
        context.set_default_navigation_timeout(timeout_ms)
        return context

    # ── the flow ──────────────────────────────────────────────────────────────

    async def _flow(
        self, context: BrowserContext, account: Account, steam: SteamWebSession, manual: bool
    ) -> BrowserLoginResult:
        aid = account.account_id
        expected_steam_id = steam.steam_id or account.steam_id
        try:
            await context.add_cookies([c.to_playwright() for c in steam.cookies])
            page = await context.new_page()

            # 1. the "Sign in with Steam" URL -> Steam OpenID (cs.money's cookies come with the redirect chain)
            # the site redirects back to the market page, so it is already open when the login is done
            market = urlsplit(self._settings.market_url)
            market_query = f"?{market.query}" if market.query else ""
            login_url = csmoney.build_login_url(market._replace(query="", fragment="").geturl(), market_query)
            await self._goto(page, login_url, "start Steam sign-in")
            await self._wait_challenge(page, aid, manual, "start Steam sign-in")
            host = urlsplit(page.url).hostname or ""
            if host == COMMUNITY_HOST:
                logger.info("[%s] stage 1/3: Steam OpenID page reached", aid)
                await self._pause(page)
                await self._steam_openid(page, aid, expected_steam_id, manual)
            elif csmoney.is_final_csmoney_url(page.url):
                logger.info("[%s] stage 1-2/3: redirected straight back to cs.money", aid)
            else:
                raise UnexpectedPageError(f"sign-in redirect ended on {urlsplit(page.url).netloc or page.url!r}")

            # 2. the page itself must report the expected signed-in user
            await self._wait_challenge(page, aid, manual, "return to cs.money")
            user = await self._app_user(page)
            if user is None or not user.is_logged:
                raise CsMoneyLoginFailed(
                    f"back on cs.money, but the page reports a guest (path={urlsplit(page.url).path})"
                )
            if expected_steam_id and user.steam_id != expected_steam_id:
                raise WrongSteamAccount(f"cs.money signed in as {user.steam_id}, expected {expected_steam_id}")
            logger.info("[%s] stage 3/3: cs.money shows the signed-in user (steam_id=%s)", aid, user.steam_id)
            await self._pause(page)

            # a new account has to give its trade link and email first (the site shows a registration form)
            if not user.is_registered:
                await self._register(page, account, user.steam_id or expected_steam_id or "")
                await self._pause(page)

            # 3. market page + scrolling
            await self._visit_market(page, aid)
            await self._pause(page)

            # results: the browser's User-Agent (the request header equals navigator.userAgent in Camoufox)
            user_agent = await page.evaluate("() => navigator.userAgent")
            all_cookies = [StoredCookie.from_playwright(c) for c in await context.cookies()]
        except PlaywrightTimeoutError as e:
            raise BrowserTimeoutError(f"timed out: {redact(str(e).splitlines()[0])}") from None
        except PlaywrightError as e:
            raise _map_playwright_error(e, "login flow") from None

        cs_cookies = [c for c in all_cookies if csmoney.is_cookie_for_csmoney(c.domain)]
        if missing := set(csmoney.AUTH_COOKIES) - {c.name for c in cs_cookies}:
            logger.warning("[%s] cookies %s missing after a verified login - saving all cs.money cookies", aid, missing)
        return BrowserLoginResult(
            steam_id=user.steam_id or expected_steam_id or "",
            csmoney_cookies=cs_cookies,
            steam_cookies=[c for c in all_cookies if is_steam_cookie(c)],
            user_agent=user_agent,
        )

    async def _steam_openid(self, page: Page, aid: str, expected_steam_id: str | None, manual: bool) -> None:
        state = await self._openid_page(page)
        if not state.logged_in:
            if not manual:
                raise SteamSessionRejected("Steam shows its sign-in form: the Steam cookies were not accepted")
            logger.warning(
                "[%s] Steam is not signed in: sign in in the browser window (password or QR, Steam Guard) "
                "and press 'Sign In' - waiting up to %.0fs",
                aid,
                self._settings.manual_timeout,
            )
            await page.wait_for_url(
                csmoney.is_final_csmoney_url,
                wait_until="domcontentloaded",
                timeout=self._settings.manual_timeout * 1000,
            )
            return
        if expected_steam_id and state.steam_id and state.steam_id != expected_steam_id:
            raise WrongSteamAccount(f"Steam is signed in as {state.steam_id}, expected {expected_steam_id}")
        logger.info("[%s] stage 2/3: Steam account %s, approving the OpenID request", aid, state.steam_id)
        assert state.submit is not None
        await self._pause(page)
        posts: list[int] = []  # statuses of the approval POSTs: none means the click did not submit the form

        def on_response(response: Response) -> None:
            if response.request.method == "POST" and urlsplit(response.url).path.startswith("/openid/login"):
                posts.append(response.status)

        page.on("response", on_response)
        await state.submit.click()
        try:
            deadline = time.monotonic() + self._settings.navigation_timeout
            while not csmoney.is_final_csmoney_url(page.url):
                # the approval POST came back and Steam stays on its page with a visible error: no point waiting
                if posts and (error := await self._openid_error(page)):
                    dump = await self._dump_page(page, aid, "openid-rejected")
                    raise SteamOpenIdRejected(
                        f"Steam rejected the OpenID approval (POST answered {posts[-1]}; Steam says: {error!r})"
                        + (f"; page saved to {dump}" if dump else "")
                    )
                if time.monotonic() > deadline:
                    where = urlsplit(page.url)
                    submitted = (
                        f"approval POST answered {posts[-1]}" if posts else "the approval form was not submitted"
                    )
                    steam_says = await self._steam_error_text(page)
                    dump = await self._dump_page(page, aid, "openid-stuck")
                    raise BrowserTimeoutError(
                        f"no redirect back to cs.money after approval (stuck at {where.netloc}{where.path}; {submitted}"
                        + (f"; Steam says: {steam_says!r}" if steam_says else "")
                        + (f"; page saved to {dump}" if dump else "")
                        + ")"
                    )
                await page.wait_for_timeout(500)
            await page.wait_for_load_state("domcontentloaded")
        finally:
            page.remove_listener("response", on_response)

    async def _openid_error(self, page: Page) -> str:
        """Text of the visible ``#error_display`` box of Steam's OpenID page ('' while hidden / navigating)."""
        with contextlib.suppress(PlaywrightError):
            if urlsplit(page.url).hostname != COMMUNITY_HOST:
                return ""
            text = await page.evaluate(
                "() => { const el = document.querySelector('#error_display');"
                " return el && el.offsetParent !== null ? el.innerText : ''; }"
            )
            return " ".join(str(text or "").split())[:300]
        return ""

    async def _openid_page(self, page: Page) -> _OpenIdPage:
        html = await page.content()
        match = _G_STEAM_ID.search(html)
        form = page.locator(_APPROVAL_FORM)
        submit = page.locator("#imageLogin")
        if await submit.count() == 0:
            submit = form.locator('input[type="submit"], button[type="submit"], input[type="image"]')
        has_form = await form.count() > 0 and await submit.count() > 0
        if match and not has_form:
            raise UnexpectedPageError(
                "signed in to Steam, but the OpenID approval form was not found (layout changed?)"
            )
        if has_form and not match:
            raise UnexpectedPageError("OpenID approval form found, but the signed-in Steam ID is unknown")
        return _OpenIdPage(
            logged_in=has_form, steam_id=match.group(1) if match else None, submit=submit.first if has_form else None
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _steam_error_text(self, page: Page) -> str:
        """The message of a Steam error page / error box, or the page title when none is found."""
        with contextlib.suppress(PlaywrightError):
            text = await page.evaluate(_STEAM_ERROR_JS)
            return " ".join(str(text or "").split())[:300]
        return ""

    async def _dump_page(self, page: Page, aid: str, reason: str) -> Path | None:
        """Save the page's HTML and a screenshot under ``data_dir/failures`` for a failure that needs a look."""
        folder = self._settings.data_dir / "failures"
        stem = f"{re.sub(r'[^\w.-]', '_', aid)}-{time.strftime('%Y%m%d-%H%M%S')}-{reason}"
        try:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{stem}.html").write_text(await page.content(), encoding="utf-8")
            await page.screenshot(path=str(folder / f"{stem}.png"), full_page=True, timeout=10000)
        except (OSError, PlaywrightError) as e:
            logger.debug("[%s] could not save the failed page: %s", aid, e)
        return folder / f"{stem}.html" if (folder / f"{stem}.html").exists() else None

    async def _goto(self, page: Page, url: str, stage: str) -> None:
        try:
            await page.goto(url, wait_until="domcontentloaded")
        except PlaywrightTimeoutError:
            raise BrowserTimeoutError(f"{stage}: navigation timed out") from None
        except PlaywrightError as e:
            raise _map_playwright_error(e, stage) from None

    async def _is_challenge(self, page: Page) -> bool | None:
        try:
            return csmoney.looks_like_challenge(await page.content(), await page.title())
        except PlaywrightError:
            return None  # navigation in progress

    async def _wait_challenge(self, page: Page, aid: str, manual: bool, stage: str) -> None:
        limit = self._settings.manual_timeout if manual else self._settings.challenge_timeout
        deadline = time.monotonic() + limit
        warned = False
        while (challenged := await self._is_challenge(page)) is not False:
            if challenged and manual and not warned:
                logger.warning("[%s] Cloudflare check on cs.money - complete it in the window if it does not pass", aid)
                warned = True
            if time.monotonic() > deadline:
                raise CloudflareChallengeError(f"{stage}: Cloudflare check was not passed within {limit:.0f}s")
            await page.wait_for_timeout(1000)
        if warned:
            logger.info("[%s] Cloudflare check passed", aid)

    async def _app_user(self, page: Page) -> csmoney.AppUser | None:
        locator = page.locator("#__app-params")
        if await locator.count() == 0:
            return None
        return csmoney.parse_app_user(await locator.first.text_content())

    async def _pause(self, page: Page) -> None:
        if self._settings.step_delay > 0:
            await page.wait_for_timeout(self._settings.step_delay * 1000)

    async def _hold_open(self, context: BrowserContext, aid: str) -> None:
        """Keep the window for the user until it is closed or Enter is pressed in the console."""
        closed = asyncio.Event()
        context.on("close", lambda _: closed.set())
        browser = context.browser
        if browser is not None:
            browser.on("disconnected", lambda _: closed.set())
        logger.info("[%s] browser left open: explore the site, then close the window or press Enter here", aid)
        enter = asyncio.create_task(asyncio.to_thread(_wait_enter))
        waiter = asyncio.create_task(closed.wait())
        try:
            await asyncio.wait({enter, waiter}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            waiter.cancel()  # the input() thread cannot be cancelled; it ends with the process

    async def _register(self, page: Page, account: Account, steam_id: str) -> None:
        """Registration form of a new account: trade link (read from the account's own Steam page), email, terms.

        The marketing-mails checkbox stays off. Needs the Steam cookies in the context (``_flow`` adds them)."""
        aid = account.account_id
        if not account.email:
            raise RegistrationRequired(f"{aid} is not registered on cs.money: set `email` or add it to emails.txt")
        steam_page = await page.context.new_page()
        try:
            await steam_page.goto(
                f"https://{COMMUNITY_HOST}/profiles/{steam_id}/tradeoffers/privacy", wait_until="domcontentloaded"
            )
            trade_url = await steam_page.evaluate("document.querySelector('#trade_offer_access_url')?.value || ''")
        finally:
            await steam_page.close()
        if not _TRADE_URL.match(trade_url):
            raise UnexpectedPageError("could not read the trade URL from the Steam privacy page")

        await self._goto(page, _PERSONAL_URL, "registration")
        await accept_cookie_banner(page)
        trade_input = page.locator("input[placeholder*=tradeoff]")
        await trade_input.first.wait_for(state="visible", timeout=15000)
        await trade_input.first.fill(trade_url)
        await page.get_by_placeholder("yourname@gmail.com").fill(account.email)
        boxes = page.locator("input[type=checkbox]")  # [0] marketing mails (left off), [1] terms; inputs are hidden
        await boxes.nth(1).evaluate("el => (el.closest('label') || el.parentElement).click()")
        if not await boxes.nth(1).is_checked() or await boxes.nth(0).is_checked():
            raise UnexpectedPageError("registration checkboxes are not in the expected state")
        await page.get_by_role("button", name="Зарегистрироваться").evaluate("el => el.click()")
        try:
            await trade_input.first.wait_for(state="detached", timeout=15000)
        except PlaywrightTimeoutError:
            raise UnexpectedPageError("the registration form did not close after submitting") from None
        logger.info("[%s] registered on cs.money", aid)

    async def _visit_market(self, page: Page, aid: str) -> None:
        """Make sure the market page is open and scroll it a few times like a user.

        cs.money's list endpoints answer 403/4030 (captcha) to a session until it has been through a real browser
        market page. The authoritative check is the plain-HTTP request that ``SessionManager`` makes with the new
        session before saving it."""
        s = self._settings
        wanted = urlsplit(s.market_url)
        if urlsplit(page.url).path != wanted.path:  # the login redirect did not end on the market page
            await self._goto(page, s.market_url, "market page")
            await self._wait_challenge(page, aid, s.manual, "market page")
        logger.info("[%s] market page open (%s)", aid, urlsplit(page.url).path)
        await accept_cookie_banner(page)
        await page.mouse.move(640, 400)
        for _ in range(s.scroll_steps):
            await page.mouse.wheel(0, 700)
            await page.wait_for_timeout(s.scroll_pause * 1000)
        logger.info("[%s] scrolled the market page %d time(s)", aid, s.scroll_steps)
