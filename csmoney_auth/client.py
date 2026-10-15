"""HTTP client and cookie diagnostics for saved CS.MONEY sessions."""

import asyncio
import copy
import json
import logging
import random
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp_socks import ProxyConnector
from aiohttp_socks import ProxyError as SocksProxyError

from . import core as csmoney
from .core import (
    CaptchaRequiredError,
    ChallengeRequiredError,
    CsMoneyHTTPError,
    CsMoneySession,
    NetworkError,
    ProxyConfig,
    ProxyError,
    RateLimitedError,
    ResponseKind,
    ServiceUnavailableError,
    SessionInvalidError,
    cookie_header,
    cookies_for_url,
    is_cookie_for_csmoney,
    merge_cookie,
    parse_set_cookie,
    session_expiry,
)

# --- http_client ---

logger = logging.getLogger(__name__)

MAX_REDIRECTS = 5


@dataclass(slots=True)
class HttpResponse:
    status: int
    url: str
    headers: Mapping[str, str] = field(repr=False)  # case-insensitive mapping
    set_cookies: list[str] = field(repr=False)
    content: bytes = field(repr=False)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.content)


class HttpBackend(Protocol):
    async def request(
        self, method: str, url: str, *, headers: dict[str, str], params: Any, json: Any, data: Any
    ) -> HttpResponse: ...

    async def aclose(self) -> None: ...


class AiohttpBackend:
    def __init__(self, proxy: ProxyConfig | None, timeout: float):
        connector = None
        self._proxy_url: str | None = None
        if proxy is not None and proxy.is_socks:
            connector = ProxyConnector.from_url(proxy.socks_client_url(), rdns=True)
        elif proxy is not None:
            self._proxy_url = proxy.url
        self._session = aiohttp.ClientSession(
            connector=connector,
            cookie_jar=aiohttp.DummyCookieJar(),
            timeout=aiohttp.ClientTimeout(total=timeout),
        )

    async def request(self, method, url, *, headers, params, json, data) -> HttpResponse:
        kwargs: dict[str, Any] = {"headers": headers, "params": params, "allow_redirects": False}
        if json is not None:
            kwargs["json"] = json
        elif data is not None:
            kwargs["data"] = data
        try:
            async with self._session.request(method, url, proxy=self._proxy_url, **kwargs) as r:
                body = await r.read()
                return HttpResponse(r.status, str(r.url), r.headers, r.headers.getall("Set-Cookie", []), body)
        except (aiohttp.ClientProxyConnectionError, aiohttp.ClientHttpProxyError, SocksProxyError) as e:
            raise ProxyError(f"proxy failure: {type(e).__name__}") from e
        except (aiohttp.ClientConnectionError, aiohttp.ClientPayloadError, TimeoutError) as e:
            raise NetworkError(f"network failure: {type(e).__name__}") from e

    async def aclose(self) -> None:
        await self._session.close()


class HttpxBackend:
    def __init__(self, proxy: ProxyConfig | None, timeout: float):
        import httpx  # optional backend

        self._httpx = httpx
        proxy_url = proxy.socks_client_url() if proxy is not None else None
        self._client = httpx.AsyncClient(proxy=proxy_url, timeout=timeout, follow_redirects=False)

    async def request(self, method, url, *, headers, params, json, data) -> HttpResponse:
        httpx = self._httpx
        try:
            r = await self._client.request(method, url, headers=headers, params=params, json=json, data=data)
        except httpx.ProxyError as e:
            raise ProxyError(f"proxy failure: {type(e).__name__}") from e
        except (httpx.TransportError, httpx.DecodingError) as e:
            raise NetworkError(f"network failure: {type(e).__name__}") from e
        finally:
            self._client.cookies.clear()  # cookies are managed by CsMoneyHttpClient
        return HttpResponse(r.status_code, str(r.url), r.headers, r.headers.get_list("set-cookie"), r.content)

    async def aclose(self) -> None:
        await self._client.aclose()


def make_backend(name: str, proxy: ProxyConfig | None, timeout: float) -> HttpBackend:
    if name == "httpx":
        return HttpxBackend(proxy, timeout)
    return AiohttpBackend(proxy, timeout)


def retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    value = headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError):
        return None


def backoff_delay(attempt: int, base: float, maximum: float) -> float:
    return min(maximum, base * 2 ** (attempt - 1)) * random.uniform(0.8, 1.2)


Reauth = Callable[[CsMoneySession, str], Awaitable[CsMoneySession]]
Persist = Callable[[CsMoneySession], Awaitable[None]]


class CsMoneyHttpClient:
    """Requests on behalf of one account. Use as ``async with``.

    ``reauth(stale_session, reason)`` is called at most once per request when CS.MONEY rejects the
    session or Cloudflare challenges it; it must return a fresh session (``SessionManager.reauth``).
    """

    def __init__(
        self,
        session: CsMoneySession,
        *,
        backend: str = "aiohttp",
        timeout: float = 30,
        max_retries: int = 3,
        backoff_base: float = 2.0,
        backoff_max: float = 60.0,
        reauth: Reauth | None = None,
        persist: Persist | None = None,
        base_url: str = csmoney.BASE_URL,
    ):
        self._backend_name = backend
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._reauth = reauth
        self._persist = persist
        self._base_url = base_url
        self._session = session
        self._backend = make_backend(backend, session.proxy_config, timeout)

    @property
    def session(self) -> CsMoneySession:
        return self._session

    async def __aenter__(self) -> "CsMoneyHttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._backend.aclose()

    async def _use_session(self, session: CsMoneySession) -> None:
        if session.proxy != self._session.proxy:
            await self._backend.aclose()
            self._backend = make_backend(self._backend_name, session.proxy_config, self._timeout)
        self._session = session

    def _headers(self, method: str, url: str, extra: Mapping[str, str] | None) -> dict[str, str]:
        headers = {
            "User-Agent": self._session.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": self._base_url + "/",
        }
        if method not in ("GET", "HEAD"):
            headers["Origin"] = self._base_url
        headers.update(extra or {})
        if cookies := cookies_for_url(self._session.cookies, url):
            headers["Cookie"] = cookie_header(cookies)
        return headers

    async def _absorb_cookies(self, response: HttpResponse) -> None:
        host = urlsplit(response.url).hostname or ""
        changed = False
        for header in response.set_cookies:
            cookie = parse_set_cookie(header, host)
            if cookie is not None and merge_cookie(self._session.cookies, cookie):
                changed = True
        if changed:
            self._session.expires_at = session_expiry(self._session.cookies) or self._session.expires_at
            if self._persist is not None:
                await self._persist(self._session)

    async def _send(self, method: str, url: str, *, params, json, data, headers) -> HttpResponse:
        """One logical request: follows redirects manually so every hop's Set-Cookie is kept."""
        for _ in range(MAX_REDIRECTS + 1):
            response = await self._backend.request(
                method, url, headers=self._headers(method, url, headers), params=params, json=json, data=data
            )
            await self._absorb_cookies(response)
            location = response.headers.get("location")
            if response.status not in (301, 302, 303, 307, 308) or not location:
                return response
            url = urljoin(url, location)
            params = None
            if response.status == 303 or (response.status in (301, 302) and method == "POST"):
                method, json, data = "GET", None, None
        raise CsMoneyHTTPError("too many redirects", status=response.status, url=url)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        json: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | None = None,
        allow_reauth: bool = True,
    ) -> HttpResponse:
        """Send a request; returns a 2xx/3xx response or raises a ``CsMoneyAuthError`` subclass."""
        method = method.upper()
        url = urljoin(self._base_url + "/", url)
        attempt = 0
        reauthed = False
        while True:
            try:
                response = await self._send(method, url, params=params, json=json, data=data, headers=headers)
            except (ProxyError, NetworkError) as e:
                attempt += 1
                if attempt > self._max_retries:
                    raise
                delay = backoff_delay(attempt, self._backoff_base, self._backoff_max)
                logger.warning(
                    "[%s] %s %s: %s - retry %d/%d in %.1fs",
                    self._aid,
                    method,
                    _path(url),
                    e,
                    attempt,
                    self._max_retries,
                    delay,
                )
                await asyncio.sleep(delay)
                continue

            kind, codes = csmoney.classify_response(response.status, response.headers, response.text)
            if kind is ResponseKind.OK:
                return response

            if kind in (ResponseKind.AUTH, ResponseKind.CHALLENGE):
                if kind is ResponseKind.CHALLENGE:
                    reason = "cloudflare challenge"
                else:
                    reason = f"HTTP {response.status} codes={codes}"
                if allow_reauth and self._reauth is not None and not reauthed:
                    reauthed = True
                    logger.warning("[%s] cs.money rejected the session (%s) - re-authorizing", self._aid, reason)
                    await self._use_session(await self._reauth(self._session, reason))
                    continue
                error = ChallengeRequiredError if kind is ResponseKind.CHALLENGE else SessionInvalidError
                raise error(f"session rejected: {reason}", status=response.status, url=_path(url), codes=codes)

            if kind is ResponseKind.CAPTCHA:
                raise CaptchaRequiredError(
                    "captcha required (code 4030)", status=response.status, url=_path(url), codes=codes
                )

            if kind in (ResponseKind.RATE_LIMIT, ResponseKind.SERVER):
                attempt += 1
                if attempt > self._max_retries:
                    if kind is ResponseKind.RATE_LIMIT:
                        raise RateLimitedError("rate limited", status=response.status, url=_path(url), codes=codes)
                    raise ServiceUnavailableError(f"cs.money unavailable: HTTP {response.status}", response.status)
                delay = backoff_delay(attempt, self._backoff_base, self._backoff_max)
                if kind is ResponseKind.RATE_LIMIT and (hint := retry_after_seconds(response.headers)) is not None:
                    delay = min(max(hint, 0.5), self._backoff_max)
                logger.warning(
                    "[%s] %s %s: HTTP %d (%s) - retry %d/%d in %.1fs",
                    self._aid,
                    method,
                    _path(url),
                    response.status,
                    kind,
                    attempt,
                    self._max_retries,
                    delay,
                )
                await asyncio.sleep(delay)
                continue

            raise CsMoneyHTTPError(
                f"HTTP {response.status} codes={codes}", status=response.status, url=_path(url), codes=codes
            )

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        return (await self.request("GET", url, **kwargs)).json()

    async def post_json(self, url: str, payload: Any, **kwargs: Any) -> Any:
        response = await self.request("POST", url, json=payload, **kwargs)
        return response.json() if response.content else None

    async def check_session(self, paths: str | Sequence[str] = csmoney.USER_INFO_PATH) -> ResponseKind:
        """Is the stored session still accepted? The requests are sent one after another; the first rejected one
        decides. Never re-authorizes; retries only transient failures."""
        for path in [paths] if isinstance(paths, str) else paths:
            try:
                await self.request("GET", path, allow_reauth=False)
            except CaptchaRequiredError:
                return ResponseKind.CAPTCHA
            except ChallengeRequiredError:
                return ResponseKind.CHALLENGE
            except SessionInvalidError:
                return ResponseKind.AUTH
        return ResponseKind.OK

    @property
    def _aid(self) -> str:
        return self._session.account_id


def _path(url: str) -> str:
    """URL without the query string — for logs and errors."""
    parts = urlsplit(url)
    return f"{parts.netloc}{parts.path}"


# --- diagnostics ---


@dataclass(slots=True)
class CookieVerdict:
    name: str
    domain: str
    without_it: ResponseKind  # result of the check when this cookie is not sent

    @property
    def required(self) -> bool:
        return self.without_it is not ResponseKind.OK


async def analyze_cookies(
    session: CsMoneySession, *, backend: str = "aiohttp", http_timeout: float = 30, pause: float = 1.0
) -> tuple[ResponseKind, list[CookieVerdict]]:
    """Returns the baseline result and a verdict per cs.money cookie. Nothing is persisted."""

    async def check(candidate: CsMoneySession) -> ResponseKind:
        async with CsMoneyHttpClient(candidate, backend=backend, timeout=http_timeout, max_retries=1) as client:
            return await client.check_session()

    baseline = await check(copy.deepcopy(session))
    if baseline is not ResponseKind.OK:
        return baseline, []

    verdicts = []
    for cookie in session.cookies:
        if not is_cookie_for_csmoney(cookie.domain):
            continue
        trimmed = copy.deepcopy(session)
        trimmed.cookies = [c for c in trimmed.cookies if c.key() != cookie.key()]
        await asyncio.sleep(pause)
        verdicts.append(CookieVerdict(cookie.name, cookie.domain, await check(trimmed)))
    return baseline, verdicts
