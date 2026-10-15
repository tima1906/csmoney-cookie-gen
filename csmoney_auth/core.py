"""Shared models, configuration, cookies, proxies, site helpers, errors and logging."""

import asyncio
import base64
import contextlib
import dataclasses
import enum
import json
import logging
import re
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import asdict, dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlencode, urlsplit, urlunsplit

from python_socks import ProxyError as SocksError
from python_socks import ProxyTimeoutError as SocksTimeoutError
from python_socks.async_.asyncio import Proxy as SocksProxy

# --- errors ---


class CsMoneyAuthError(Exception):
    """Base error of the package."""


class ConfigError(CsMoneyAuthError):
    """Invalid configuration or account data."""


class StorageError(CsMoneyAuthError):
    """The session store cannot be read or decrypted."""


# ── network ────────────────────────────────────────────────────────────────────


class NetworkError(CsMoneyAuthError):
    """Connection problem (timeout, reset, DNS) not attributable to the proxy."""


class ProxyError(NetworkError):
    """The proxy is unreachable, refused the connection or rejected its credentials."""


class ServiceUnavailableError(CsMoneyAuthError):
    """CS.MONEY answered with 5xx or an error page — temporary unavailability."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# ── Steam side (aiosteampy) ────────────────────────────────────────────────────


class SteamAuthError(CsMoneyAuthError):
    """No valid Steam web session could be produced for the account."""


class SteamGuardRequired(SteamAuthError):
    """Steam asks for a confirmation that cannot be completed automatically."""


# ── browser (Camoufox) ─────────────────────────────────────────────────────────


class BrowserError(CsMoneyAuthError):
    """Browser launch or page interaction failed."""


class BrowserTimeoutError(BrowserError):
    """A navigation or the whole login flow did not finish in time."""


class CloudflareChallengeError(BrowserError):
    """Cloudflare kept showing a challenge page (it is never solved automatically)."""


class SteamSessionRejected(BrowserError):
    """Steam OpenID page shows the sign-in form: the injected Steam cookies were not accepted."""


class SteamOpenIdRejected(BrowserError):
    """Steam answered the OpenID approval with its error page: the account (or its IP) may not sign in to sites."""


class WrongSteamAccount(BrowserError):
    """The Steam / CS.MONEY page belongs to another Steam account than expected."""


class UnexpectedPageError(BrowserError):
    """A page does not look like expected (site layout or flow changed)."""


class RegistrationRequired(BrowserError):
    """A new cs.money account needs an email (account `email` or a line in emails.txt) to be registered."""


class CsMoneyLoginFailed(BrowserError):
    """The flow returned to CS.MONEY, but the site does not consider the user signed in."""


# ── HTTP usage of a stored session ─────────────────────────────────────────────


class CsMoneyHTTPError(CsMoneyAuthError):
    """CS.MONEY rejected an HTTP request."""

    def __init__(self, message: str, *, status: int, url: str, codes: list[int] | None = None):
        super().__init__(message)
        self.status = status
        self.url = url
        self.codes = codes or []


class SessionInvalidError(CsMoneyHTTPError):
    """401/403 or CS.MONEY ``AuthError`` (code 6): the cookies are expired or revoked."""


class ChallengeRequiredError(CsMoneyHTTPError):
    """Cloudflare challenged the HTTP request: ``cf_clearance`` must be refreshed in the browser."""


class CaptchaRequiredError(CsMoneyHTTPError):
    """cs.money answered CaptchaRequired (code 4030). The session is valid; the request needs a solved captcha."""


class RateLimitedError(CsMoneyHTTPError):
    """HTTP 429 / CS.MONEY rate limit code, retries exhausted."""


# ── orchestration ──────────────────────────────────────────────────────────────


class SessionNotFound(CsMoneyAuthError):
    """No stored session for the account."""


class ReauthNotAllowed(CsMoneyAuthError):
    """A new browser login is blocked by the cooldown after recent failures."""


# --- logs ---

_SECRET_COOKIES = (
    r"steamLoginSecure|steamRefresh_steam|sessionid|sessionidSecureOpenIDNonce|csgo_ses|cf_clearance|"
    r"INGRESSCOOKIE|passport_login_nonce\w*|auth_login_state\w*|support_token|session_id|device_id"
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # name=value pairs of known secret cookies (Cookie / Set-Cookie headers, query strings)
    (re.compile(rf"\b({_SECRET_COOKIES})=([^;\s&\"',]+)"), r"\1=<redacted>"),
    # steamLoginSecure / steamRefresh_steam values: "<steamid64>%7C%7C<jwt>"
    (re.compile(r"\b7656\d{13}(?:%7C%7C|\|\|)[\w.\-]+"), "<steam-token>"),
    # bare JWTs (Steam access / refresh tokens)
    (re.compile(r"\beyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]*"), "<jwt>"),
    # credentials inside proxy / URLs
    (re.compile(r"(?i)\b((?:https?|socks[45]h?)://)[^/\s:@]+:[^/\s@]*@"), r"\1***:***@"),
]


def redact(text: str) -> str:
    """Mask secrets in arbitrary text (log lines, stored error messages)."""
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class RedactingFormatter(logging.Formatter):
    """Applies ``redact`` to the whole formatted record, tracebacks included."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def setup_logging(level: str | int = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        RedactingFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level if isinstance(level, int) else level.upper())
    # third-party chatter that may echo request details
    for noisy in ("asyncio", "aiohttp", "httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# --- csmoney ---

BASE_URL = "https://cs.money"
HOST = "cs.money"

LOGIN_PATH = "/api/public/v1/auth/steam-login"
AUTH_PATH_PREFIX = "/api/public/v1/auth/"
USER_INFO_PATH = "/api/public/v3/user-info"
# Endpoint a session must be able to call for the market to work. It answers 403/4030 (captcha) until the
# market page has been opened and scrolled in a real browser with the same session (verified 2026-10-14).
# Several different list requests in a row: a session that passes the first one but gets 4030 on the next
# ones (as observed) must not be accepted.
MARKET_CHECK_PATHS = (
    "/3.0/market/sell-orders?limit=1&order=desc&sort=insertDate",
    "/3.0/market/sell-orders?limit=1&order=asc&sort=price",
    "/3.0/market/sell-orders?limit=1&order=desc&sort=price",
)
MARKET_LIST_PATH = "/3.0/market/sell-orders"
PUBLIC_STATUS_PATH = "/api/public/v1/platform/statuses"  # public endpoint, used as proxy reachability probe

SESSION_COOKIE = "csgo_ses"  # httpOnly cookie that carries the authenticated session
# Cookies without which user-info answers AuthError (found with `analyze-cookies` on a live session, 2026-10-14).
AUTH_COOKIES = (SESSION_COOKIE, "steamid")

CAPTCHA_ERROR_CODE = 4030  # frontend enum: CaptchaRequired (HTTP 403 with this code is NOT an expired session)
AUTH_ERROR_CODE = 6  # frontend enum: AuthError
RATE_LIMIT_ERROR_CODE = 9999  # returned by market endpoints when throttled

_CHALLENGE_MARKERS = ("_cf_chl_opt", 'id="challenge-form"', "/cdn-cgi/challenge-platform/h/b/orchestrate", "cf-chl-")
_CHALLENGE_TITLES = ("just a moment", "attention required", "один момент", "un moment")


def build_login_url(redirect_url: str = BASE_URL + "/", redirect_query: str = "") -> str:
    """The same URL the site's "Sign in with Steam" button navigates to.

    After the login the site redirects to ``redirect_url`` + ``redirect_query`` (the button passes the current page)."""
    query = urlencode(
        {"redirectUrl": redirect_url, "callbackUrl": BASE_URL + "/login", "redirectQuery": redirect_query}
    )
    return f"{BASE_URL}{LOGIN_PATH}?{query}"


def is_csmoney_host(host: str | None) -> bool:
    host = (host or "").lower()
    return host == HOST or host.endswith("." + HOST)


def is_cookie_for_csmoney(domain: str) -> bool:
    return is_csmoney_host(domain.lstrip("."))


def is_final_csmoney_url(url: str) -> bool:
    """True once the login redirect chain has landed on a regular CS.MONEY page."""
    parts = urlsplit(url)
    if not is_csmoney_host(parts.hostname):
        return False
    path = parts.path or "/"
    return not path.startswith(AUTH_PATH_PREFIX) and path.rstrip("/") != "/login"


@dataclass(frozen=True, slots=True)
class AppUser:
    is_logged: bool
    steam_id: str | None
    is_registered: bool = True  # False: a new account that still has to give its trade link and email


def parse_app_user(raw: str | None) -> AppUser | None:
    """Parse the ``#__app-params`` JSON of a server-rendered page."""
    if not raw:
        return None
    try:
        info = json.loads(raw).get("userInfo") or {}
    except (json.JSONDecodeError, AttributeError):
        return None
    steam_id = str(info.get("steamId64") or "") or None
    return AppUser(
        is_logged=info.get("isLogged") is True, steam_id=steam_id, is_registered=info.get("isRegistered") is not False
    )


def looks_like_challenge(text: str, title: str | None = None) -> bool:
    if title and title.strip().lower().startswith(_CHALLENGE_TITLES):
        return True
    head = text[:20000]
    return any(marker in head for marker in _CHALLENGE_MARKERS)


def error_codes(body: Any) -> list[int]:
    if not isinstance(body, dict):
        return []
    errors = body.get("errors")
    if not isinstance(errors, list):
        return []
    return [e["code"] for e in errors if isinstance(e, dict) and isinstance(e.get("code"), int)]


class ResponseKind(enum.StrEnum):
    OK = "ok"
    AUTH = "auth"  # session rejected → browser re-login
    CHALLENGE = "challenge"  # Cloudflare challenge → browser re-login refreshes cf_clearance
    RATE_LIMIT = "rate_limit"  # retry later
    SERVER = "server"  # 5xx / Cloudflare origin errors → retry with backoff
    CAPTCHA = "captcha"  # cs.money wants a captcha for this request; cookies are fine, no retry
    CLIENT = "client"  # other 4xx → caller's problem, no retry


def classify_response(status: int, headers: Mapping[str, str], text: str) -> tuple[ResponseKind, list[int]]:
    if headers.get("cf-mitigated", "").lower() == "challenge" or (
        status in (403, 429, 503) and looks_like_challenge(text)
    ):
        return ResponseKind.CHALLENGE, []
    codes: list[int] = []
    if "json" in headers.get("content-type", "").lower() and text:
        with contextlib.suppress(json.JSONDecodeError):
            codes = error_codes(json.loads(text))
    if CAPTCHA_ERROR_CODE in codes:
        return ResponseKind.CAPTCHA, codes
    if status == 429 or RATE_LIMIT_ERROR_CODE in codes:
        return ResponseKind.RATE_LIMIT, codes
    if status in (401, 403) or AUTH_ERROR_CODE in codes:
        return ResponseKind.AUTH, codes
    if status >= 500:
        return ResponseKind.SERVER, codes
    if status >= 400:
        return ResponseKind.CLIENT, codes
    return ResponseKind.OK, codes


# --- cookies ---

_SAME_SITE = {"lax": "Lax", "strict": "Strict", "none": "None"}


@dataclass(slots=True)
class StoredCookie:
    name: str
    value: str = field(repr=False)
    domain: str  # leading dot = domain cookie (sent to subdomains), otherwise host-only
    path: str = "/"
    expires: float | None = None  # unix timestamp, None = session cookie
    http_only: bool = False
    secure: bool = False
    same_site: str | None = None  # "Lax" | "Strict" | "None"

    def is_expired(self, now: float | None = None) -> bool:
        return self.expires is not None and self.expires <= (time.time() if now is None else now)

    def key(self) -> tuple[str, str, str]:
        return self.name, self.domain.lstrip(".").lower(), self.path

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StoredCookie":
        return cls(**data)

    # ── Playwright ────────────────────────────────────────────────────────────

    @classmethod
    def from_playwright(cls, c: dict[str, Any]) -> "StoredCookie":
        expires = c.get("expires")
        return cls(
            name=c["name"],
            value=c["value"],
            domain=c["domain"],
            path=c.get("path") or "/",
            expires=float(expires) if expires is not None and expires >= 0 else None,
            http_only=bool(c.get("httpOnly")),
            secure=bool(c.get("secure")),
            same_site=c.get("sameSite"),
        )

    def to_playwright(self) -> dict[str, Any]:
        same_site = self.same_site if self.same_site in ("Lax", "Strict", "None") else "Lax"
        return {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path,
            "expires": self.expires if self.expires is not None else -1,
            "httpOnly": self.http_only,
            "secure": self.secure or same_site == "None",
            "sameSite": same_site,
        }

    # ── aiosteampy ────────────────────────────────────────────────────────────

    @classmethod
    def from_steam(cls, c: Any) -> "StoredCookie":
        """From ``aiosteampy.transport.Cookie`` (Steam sets its auth cookies with SameSite=None)."""
        return cls(
            name=c.name,
            value=c.value,
            domain=c.domain,
            path=c.path or "/",
            expires=c.expires.timestamp() if c.expires is not None else None,
            http_only=bool(c.http_only),
            secure=True,
            same_site=c.same_site or "None",
        )


def domain_matches(cookie_domain: str, host: str) -> bool:
    host = host.lower()
    domain = cookie_domain.lower()
    if domain.startswith("."):
        bare = domain[1:]
        return host == bare or host.endswith("." + bare)
    return host == domain


def path_matches(cookie_path: str, request_path: str) -> bool:
    request_path = request_path or "/"
    if request_path == cookie_path or cookie_path == "/":
        return True
    prefix = cookie_path if cookie_path.endswith("/") else cookie_path + "/"
    return request_path.startswith(prefix)


def cookies_for_url(cookies: list[StoredCookie], url: str, now: float | None = None) -> list[StoredCookie]:
    parts = urlsplit(url)
    host, path, secure = parts.hostname or "", parts.path or "/", parts.scheme == "https"
    now = time.time() if now is None else now
    selected = [
        c
        for c in cookies
        if domain_matches(c.domain, host)
        and path_matches(c.path, path)
        and (secure or not c.secure)
        and not c.is_expired(now)
    ]
    # RFC 6265 5.4: longer paths first
    return sorted(selected, key=lambda c: len(c.path), reverse=True)


def cookie_header(cookies: list[StoredCookie]) -> str:
    return "; ".join(f"{c.name}={c.value}" for c in cookies)


def parse_set_cookie(header: str, request_host: str, now: float | None = None) -> StoredCookie | None:
    """Parse one ``Set-Cookie`` header value. Returns None for malformed headers or foreign domains."""
    now = time.time() if now is None else now
    pair, *attrs = header.split(";")
    if "=" not in pair:
        return None
    name, value = (s.strip() for s in pair.split("=", 1))
    if not name:
        return None
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]

    cookie = StoredCookie(name=name, value=value, domain=request_host.lower())
    max_age: float | None = None
    for attr in attrs:
        key, _, val = attr.strip().partition("=")
        key, val = key.strip().lower(), val.strip()
        if key == "domain" and val:
            domain = val.lstrip(".").lower()
            if not domain_matches("." + domain, request_host):
                return None  # a server may not set cookies for unrelated domains
            cookie.domain = "." + domain
        elif key == "path" and val.startswith("/"):
            cookie.path = val
        elif key == "expires" and val:
            with contextlib.suppress(TypeError, ValueError, IndexError):
                cookie.expires = parsedate_to_datetime(val).timestamp()
        elif key == "max-age":
            with contextlib.suppress(ValueError):
                max_age = float(val)
        elif key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.http_only = True
        elif key == "samesite":
            cookie.same_site = _SAME_SITE.get(val.lower())
    if max_age is not None:  # Max-Age has precedence over Expires
        cookie.expires = now + max_age
    return cookie


def merge_cookie(cookies: list[StoredCookie], new: StoredCookie, now: float | None = None) -> bool:
    """Insert / replace / delete (expired) ``new`` in ``cookies``. Returns True if the jar changed."""
    key = new.key()
    for i, existing in enumerate(cookies):
        if existing.key() == key:
            if new.is_expired(now):
                del cookies[i]
                return True
            if existing == new:
                return False
            cookies[i] = new
            return True
    if new.is_expired(now):
        return False
    cookies.append(new)
    return True


def jwt_expiry(value: str) -> float | None:
    """``exp`` claim of a JWT-looking cookie value, if any."""
    parts = value.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, json.JSONDecodeError):
        return None
    exp = payload.get("exp") if isinstance(payload, dict) else None
    return float(exp) if isinstance(exp, (int, float)) else None


# --- proxy ---

logger = logging.getLogger(__name__)

SUPPORTED_SCHEMES = {"http", "https", "socks4", "socks5", "socks5h"}


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    scheme: str
    host: str
    port: int
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)

    @classmethod
    def parse(cls, raw: str) -> "ProxyConfig":
        """Accepts ``scheme://[user:pass@]host:port``, ``host:port`` and ``host:port:user:pass`` (HTTP)."""
        raw = raw.strip()
        if "://" not in raw:
            parts = raw.split(":")
            if len(parts) == 2:
                raw = f"http://{parts[0]}:{parts[1]}"
            elif len(parts) == 4:
                host, port, user, password = parts
                raw = f"http://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
            else:
                raise ConfigError("Unrecognized proxy format (expected scheme://user:pass@host:port)")
        url = urlsplit(raw)
        scheme = url.scheme.lower()
        if scheme not in SUPPORTED_SCHEMES:
            raise ConfigError(f"Unsupported proxy scheme {scheme!r}; supported: {sorted(SUPPORTED_SCHEMES)}")
        try:
            port = url.port
        except ValueError:
            port = None
        if not url.hostname or not port:
            raise ConfigError(f"Proxy must include host and port ({scheme}://host:port)")
        return cls(
            scheme=scheme,
            host=url.hostname,
            port=port,
            username=unquote(url.username) if url.username else None,
            password=unquote(url.password) if url.password else None,
        )

    @property
    def _netloc_host(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def url(self) -> str:
        """Full URL including credentials. Never log it — use ``masked``."""
        auth = ""
        if self.username:
            auth = quote(self.username, safe="")
            if self.password:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        return f"{self.scheme}://{auth}{self._netloc_host}:{self.port}"

    @property
    def masked(self) -> str:
        return f"{self.scheme}://{'***@' if self.username else ''}{self._netloc_host}:{self.port}"

    @property
    def is_socks(self) -> bool:
        return self.scheme.startswith("socks")

    @property
    def needs_browser_bridge(self) -> bool:
        return self.is_socks and bool(self.username)

    def socks_client_url(self) -> str:
        """URL for SOCKS client libraries (they know ``socks5``; remote DNS is enabled separately)."""
        return self.url.replace("socks5h://", "socks5://", 1)

    def to_playwright(self) -> dict[str, str]:
        if self.needs_browser_bridge:
            raise ValueError("authenticated SOCKS proxies must go through SocksBridge")
        scheme = "socks5" if self.scheme == "socks5h" else self.scheme
        out = {"server": f"{scheme}://{self._netloc_host}:{self.port}"}
        if self.username:
            out["username"] = self.username
            out["password"] = self.password or ""
        return out

    def __str__(self) -> str:
        return self.masked


class SocksBridge:
    """Local unauthenticated HTTP proxy (CONNECT + plain HTTP) forwarding through an authenticated SOCKS proxy."""

    def __init__(self, upstream: ProxyConfig, *, connect_timeout: float = 20.0, header_timeout: float = 30.0):
        if not upstream.is_socks:
            raise ValueError("SocksBridge upstream must be a SOCKS proxy")
        self._upstream = upstream
        self._connect_timeout = connect_timeout
        self._header_timeout = header_timeout
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task] = set()

    async def start(self) -> ProxyConfig:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        logger.debug("SOCKS bridge 127.0.0.1:%d -> %s", port, self._upstream.masked)
        return ProxyConfig("http", "127.0.0.1", port)

    async def close(self) -> None:
        if self._server is None:
            return
        self._server.close()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._server.wait_closed(), 5)
        self._server = None

    async def __aenter__(self) -> ProxyConfig:
        return await self.start()

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def _open_upstream(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        proxy = SocksProxy.from_url(self._upstream.socks_client_url(), rdns=True)
        sock = await proxy.connect(dest_host=host, dest_port=port, timeout=self._connect_timeout)
        return await asyncio.open_connection(sock=sock)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self._header_timeout)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ConnectionError):
                return
            request_line, *header_lines = head.decode("latin-1").split("\r\n")
            try:
                method, target, version = request_line.split(" ", 2)
            except ValueError:
                await self._reply(writer, b"400 Bad Request")
                return

            try:
                if method.upper() == "CONNECT":
                    host, _, port = target.rpartition(":")
                    up_reader, upstream_writer = await self._open_upstream(host.strip("[]"), int(port or 443))
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                else:
                    url = urlsplit(target)
                    if url.scheme != "http" or not url.hostname:
                        await self._reply(writer, b"400 Bad Request")
                        return
                    up_reader, upstream_writer = await self._open_upstream(url.hostname, url.port or 80)
                    path = urlunsplit(("", "", url.path or "/", url.query, ""))
                    kept = [
                        line
                        for line in header_lines
                        if line and not line.lower().startswith(("proxy-", "connection:", "keep-alive:"))
                    ]
                    lines = [f"{method} {path} {version}", *kept, "Connection: close", "", ""]
                    upstream_writer.write("\r\n".join(lines).encode("latin-1"))
                    await upstream_writer.drain()
            except (SocksError, SocksTimeoutError, OSError, ValueError) as e:
                logger.debug("SOCKS bridge upstream failure: %s", e)
                await self._reply(writer, b"502 Bad Gateway")
                return

            await asyncio.gather(self._copy(reader, upstream_writer), self._copy(up_reader, writer))
        except asyncio.CancelledError:
            pass
        finally:
            for w in (upstream_writer, writer):
                if w is not None:
                    w.close()
            if task is not None:
                self._tasks.discard(task)

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: bytes) -> None:
        with contextlib.suppress(ConnectionError):
            writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()

    @staticmethod
    async def _copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while data := await src.read(65536):
                dst.write(data)
                await dst.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            with contextlib.suppress(Exception):
                if dst.can_write_eof():
                    dst.write_eof()
                else:
                    dst.close()


@contextlib.asynccontextmanager
async def browser_proxy(proxy: ProxyConfig | None) -> AsyncIterator[ProxyConfig | None]:
    """Yield the proxy the browser should use (a local bridge for authenticated SOCKS)."""
    if proxy is None or not proxy.needs_browser_bridge:
        yield proxy
        return
    async with SocksBridge(proxy) as local:
        yield local


# --- models ---


class SessionStatus(enum.StrEnum):
    ACTIVE = "active"  # cookies passed the last check
    EXPIRED = "expired"  # CS.MONEY rejected the cookies (401/403/AuthError) or they ran out
    CHALLENGED = "challenged"  # Cloudflare challenged HTTP requests (cf_clearance is stale)
    ERROR = "error"  # the last browser login attempt failed


@dataclass(slots=True)
class SteamCredentials:
    """What is known about the Steam side of an account. Any subset may be present."""

    cookies: dict[str, str] = field(default_factory=dict, repr=False)  # steamLoginSecure, sessionid, steamRefresh_steam
    access_token: str | None = field(default=None, repr=False)
    refresh_token: str | None = field(default=None, repr=False)
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    shared_secret: str | None = field(default=None, repr=False)
    mafile: Path | None = None


@dataclass(slots=True)
class Account:
    account_id: str
    proxy: ProxyConfig | None
    steam: SteamCredentials
    email: str | None = None  # entered when a new cs.money account is registered
    steam_id: str | None = None  # expected Steam ID64; checked on Steam and CS.MONEY pages when known


@dataclass(slots=True)
class CsMoneySession:
    """A CS.MONEY session bound to the proxy (and User-Agent) it was obtained with."""

    account_id: str
    steam_id: str | None
    cookies: list[StoredCookie] = field(repr=False)
    proxy: str | None = field(repr=False)  # full proxy URL, None = direct connection
    user_agent: str
    created_at: float
    expires_at: float | None
    status: SessionStatus
    last_verified_at: float | None = None
    last_error: str | None = None

    @property
    def proxy_config(self) -> ProxyConfig | None:
        return ProxyConfig.parse(self.proxy) if self.proxy else None

    def is_expired(self, margin: float = 0.0, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.expires_at is not None and self.expires_at <= now + margin

    def session_cookie(self) -> StoredCookie | None:
        return next((c for c in self.cookies if c.name == SESSION_COOKIE and is_cookie_for_csmoney(c.domain)), None)


def session_expiry(cookies: list[StoredCookie]) -> float | None:
    """Best known expiry of the authenticated session: the earliest expiry (cookie or JWT ``exp``) of the
    cookies the session cannot work without (``csgo_ses``, ``steamid``)."""
    candidates: list[float] = []
    for c in cookies:
        if c.name not in AUTH_COOKIES or not is_cookie_for_csmoney(c.domain):
            continue
        if c.expires is not None:
            candidates.append(c.expires)
        if (exp := jwt_expiry(c.value)) is not None:
            candidates.append(exp)
    return min(candidates) if candidates else None


# --- config ---


@dataclass(slots=True)
class Settings:
    data_dir: Path = Path("data")
    db_file: str = "sessions.db"
    emails_file: str = "emails.txt"  # optional `login,email` lines for registering new cs.money accounts
    key_file: str = "store.key"  # used when the CSMONEY_STORE_KEY env variable is not set

    # browser
    headless: bool = True
    market_url: str = "https://cs.money/ru/market/buy/?order=asc&sort=price"  # opened after login
    scroll_steps: int = 3  # how many times to scroll that page down (0 = do not scroll)
    scroll_pause: float = 0.5  # seconds after each scroll (lets the page request the next list page)
    # requests, made one after another, that prove a session works (after login and in verify)
    check_paths: list[str] = field(default_factory=lambda: list(MARKET_CHECK_PATHS))
    window: list[int] | None = None  # [width, height] of the browser window; default 1280x720 when visible
    keep_open: bool = False  # leave the browser open after a successful login (needs a visible window)
    step_delay: float = 0.0  # pause after each flow stage, seconds (to watch the flow)
    manual: bool = False  # allow waiting for a human (Steam sign-in, Cloudflare check) in a visible window
    browser_os: str | list[str] | None = "windows"  # OS of the generated fingerprint
    browser_concurrency: int = 2  # parallel browser contexts
    launch_timeout: float = 90
    navigation_timeout: float = 45
    challenge_timeout: float = 45
    login_timeout: float = 180  # whole automatic flow per account
    manual_timeout: float = 300  # extra time when waiting for a human
    login_attempts: int = 3

    # HTTP usage of saved sessions
    http_backend: str = "aiohttp"  # or "httpx"
    http_timeout: float = 30
    http_retries: int = 3
    backoff_base: float = 2.0
    backoff_max: float = 60.0
    verify_interval: float = 600  # a session verified less than this many seconds ago is reused without a request

    # re-authorization guard rails
    reauth_cooldown: float = 120  # after a failed login; doubles with each consecutive failure
    reauth_cooldown_max: float = 3600

    # Steam
    steam_token_margin: float = 900  # refresh Steam access tokens that expire sooner than this
    guard_timeout: float = 180  # waiting for a Steam Guard approval in the mobile app

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        if self.http_backend not in ("aiohttp", "httpx"):
            raise ConfigError("settings.http_backend must be 'aiohttp' or 'httpx'")
        if self.window is not None and (len(self.window) != 2 or min(self.window) < 400):
            raise ConfigError("settings.window must be [width, height], both >= 400")
        if self.browser_concurrency < 1 or self.login_attempts < 1 or self.http_retries < 0:
            raise ConfigError("browser_concurrency and login_attempts must be >= 1, http_retries >= 0")

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_file

    @property
    def key_path(self) -> Path:
        return self.data_dir / self.key_file

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Settings":
        known = {f.name for f in dataclasses.fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"Unknown settings: {', '.join(sorted(unknown))}")
        return cls(**data)


def load_config(path: Path) -> tuple[Settings, list[Account]]:
    if not path.exists():
        raise ConfigError(f"{path} not found - copy config.example.json and fill in your accounts")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON ({e})") from None

    settings = Settings.from_dict(raw.get("settings") or {})
    if not settings.data_dir.is_absolute():
        settings.data_dir = path.parent / settings.data_dir

    accounts: list[Account] = []
    seen: set[str] = set()
    mafiles = _mafile_index(path.parent)
    for index, entry in enumerate(raw.get("accounts") or []):
        account = parse_account(entry, base_dir=path.parent, index=index, mafiles=mafiles)
        if account.account_id in seen:
            raise ConfigError(f"Duplicate account_id {account.account_id!r}")
        seen.add(account.account_id)
        accounts.append(account)
    emails = _load_emails(path.parent / settings.emails_file)
    for account in accounts:
        account.email = account.email or emails.get(account.account_id)
    return settings, accounts


def _load_emails(path: Path) -> dict[str, str]:
    """`login,email` per line; further columns are ignored."""
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2 and parts[0] and "@" in parts[-1]:
            result[parts[0]] = parts[-1]
    return result


def _mafile_index(base_dir: Path) -> dict[str, Path]:
    directory = base_dir / "maFiles"
    if not directory.is_dir():
        return {}
    return {p.name.casefold(): p for p in directory.iterdir() if p.is_file() and p.suffix.casefold() == ".mafile"}


def parse_account(
    entry: dict[str, Any], *, base_dir: Path, index: int = 0, mafiles: dict[str, Path] | None = None
) -> Account:
    account_id = str(entry.get("account_id") or "").strip()
    if not account_id:
        raise ConfigError(f"accounts[{index}]: account_id is required")

    proxy_raw = entry.get("proxy")
    try:
        proxy = ProxyConfig.parse(proxy_raw) if proxy_raw else None
    except ConfigError as e:
        raise ConfigError(f"{account_id}: {e}") from None

    steam_raw = entry.get("steam") or {}
    cookies = steam_raw.get("cookies") or {}
    if isinstance(cookies, str):  # "a=1; b=2" copied from a browser
        cookies = dict(part.strip().split("=", 1) for part in cookies.split(";") if "=" in part)
    steam = SteamCredentials(
        cookies={str(k): str(v) for k, v in cookies.items()},
        access_token=steam_raw.get("access_token"),
        refresh_token=steam_raw.get("refresh_token"),
        username=steam_raw.get("username"),
        password=steam_raw.get("password"),
        shared_secret=steam_raw.get("shared_secret"),
    )
    steam_id = str(entry["steam_id"]) if entry.get("steam_id") else None

    if steam_raw.get("mafile"):
        mafile = Path(steam_raw["mafile"])
        steam.mafile = mafile if mafile.is_absolute() else base_dir / mafile
    else:
        if mafiles is None:
            mafiles = _mafile_index(base_dir)
        steam.mafile = mafiles.get(f"{account_id}.mafile".casefold())
    if steam.mafile is not None:
        steam_id = _apply_mafile(steam, steam.mafile, account_id) or steam_id

    return Account(account_id=account_id, proxy=proxy, steam=steam, email=entry.get("email") or None, steam_id=steam_id)


def _apply_mafile(steam: SteamCredentials, path: Path, account_id: str) -> str | None:
    """Fill missing Steam data from a Steam Desktop Authenticator maFile. Returns its Steam ID."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"{account_id}: cannot read maFile {path.name}: {e}") from None
    session = data.get("Session") or {}
    steam.shared_secret = steam.shared_secret or data.get("shared_secret")
    steam.username = steam.username or data.get("account_name")
    steam.refresh_token = steam.refresh_token or session.get("RefreshToken")
    steam.access_token = steam.access_token or session.get("AccessToken")
    if session.get("SteamLoginSecure"):  # older SDA format
        steam.cookies.setdefault("steamLoginSecure", session["SteamLoginSecure"])
    if session.get("SessionID"):
        steam.cookies.setdefault("sessionid", session["SessionID"])
    return str(session["SteamID"]) if session.get("SteamID") else None
