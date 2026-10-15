"""HTTP client against a local fake CS.MONEY, and the SOCKS bridge against a local SOCKS5 server with auth."""

import asyncio
import contextlib
import socket
import time

import aiohttp
import pytest
from aiohttp import web

from csmoney_auth.client import CsMoneyHttpClient
from csmoney_auth.core import (
    ChallengeRequiredError,
    CsMoneyHTTPError,
    CsMoneySession,
    NetworkError,
    ProxyConfig,
    ServiceUnavailableError,
    SessionInvalidError,
    SessionStatus,
    SocksBridge,
    StoredCookie,
)

USER_INFO = "/api/public/v3/user-info"


def make_session(cookie_value: str = "bad", proxy: str | None = None) -> CsMoneySession:
    return CsMoneySession(
        account_id="acc",
        steam_id="76561198000000001",
        cookies=[StoredCookie("csgo_ses", cookie_value, "127.0.0.1")],
        proxy=proxy,
        user_agent="TestUA/1.0",
        created_at=time.time(),
        expires_at=None,
        status=SessionStatus.ACTIVE,
    )


@contextlib.asynccontextmanager
async def serve(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


class FakeCsMoney:
    """user-info answers like the real site: 400 {"errors":[{"code":6}]} for guests."""

    def __init__(self):
        self.hits: list[web.Request] = []
        self.script: list[web.Response] = []  # forced responses, consumed first
        self.app = web.Application()
        self.app.router.add_get(USER_INFO, self.user_info)
        self.app.router.add_get("/old", self.old)

    async def user_info(self, request: web.Request) -> web.Response:
        self.hits.append(request)
        if self.script:
            return self.script.pop(0)
        if request.cookies.get("csgo_ses") in ("good", "rotated"):
            assert request.headers["User-Agent"] == "TestUA/1.0"
            resp = web.json_response({"balance": 10})
            if request.cookies["csgo_ses"] == "good":
                resp.set_cookie("csgo_ses", "rotated", path="/", httponly=True)
            return resp
        return web.json_response({"errors": [{"code": 6}]}, status=400)

    async def old(self, request: web.Request) -> web.Response:
        resp = web.Response(status=302, headers={"Location": USER_INFO})
        resp.set_cookie("csgo_ses", "good", path="/")
        return resp


@pytest.fixture(params=["aiohttp", "httpx"])
def backend(request):
    return request.param


async def test_reauth_once_then_success_and_cookie_rotation(backend):
    fake = FakeCsMoney()
    reauth_calls, persisted = [], []

    async def reauth(stale, reason):
        reauth_calls.append(reason)
        return make_session("good")

    async def persist(session):
        persisted.append([c.value for c in session.cookies])

    async with serve(fake.app) as base:
        async with CsMoneyHttpClient(
            make_session("bad"), backend=backend, base_url=base, reauth=reauth, persist=persist
        ) as client:
            assert (await client.get_json(USER_INFO)) == {"balance": 10}
            assert client.session.cookies[0].value == "rotated"  # Set-Cookie absorbed
            await client.get_json(USER_INFO)  # rotated cookie is sent next time
    assert len(reauth_calls) == 1 and "codes=[6]" in reauth_calls[0]
    assert persisted == [["rotated"]]
    assert [h.cookies.get("csgo_ses") for h in fake.hits] == ["bad", "good", "rotated"]


async def test_reauth_is_attempted_only_once(backend):
    fake = FakeCsMoney()
    calls = []

    async def reauth(stale, reason):
        calls.append(1)
        return make_session("still-bad")

    async with serve(fake.app) as base:
        async with CsMoneyHttpClient(make_session(), backend=backend, base_url=base, reauth=reauth) as client:
            with pytest.raises(SessionInvalidError) as err:
                await client.request("GET", USER_INFO)
    assert calls == [1] and err.value.status == 400 and err.value.codes == [6]


async def test_check_session_without_reauth(backend):
    fake = FakeCsMoney()
    async with serve(fake.app) as base:
        async with CsMoneyHttpClient(make_session("bad"), backend=backend, base_url=base) as client:
            assert await client.check_session() == "auth"
        async with CsMoneyHttpClient(make_session("good"), backend=backend, base_url=base) as client:
            assert await client.check_session() == "ok"


async def test_rate_limit_and_server_errors_are_retried(backend):
    fake = FakeCsMoney()
    fake.script = [
        web.Response(status=429, headers={"Retry-After": "0"}),
        web.Response(status=502, text="bad gateway"),
    ]
    async with serve(fake.app) as base:
        async with CsMoneyHttpClient(
            make_session("good"), backend=backend, base_url=base, max_retries=3, backoff_base=0.01
        ) as client:
            assert (await client.get_json(USER_INFO)) == {"balance": 10}
    assert len(fake.hits) == 3


async def test_server_errors_exhaust_retries(backend):
    fake = FakeCsMoney()
    fake.script = [web.Response(status=503, text="down") for _ in range(10)]
    async with serve(fake.app) as base:
        async with CsMoneyHttpClient(
            make_session("good"), backend=backend, base_url=base, max_retries=2, backoff_base=0.01
        ) as client:
            with pytest.raises(ServiceUnavailableError):
                await client.request("GET", USER_INFO)
    assert len(fake.hits) == 3


async def test_cloudflare_challenge_detected(backend):
    fake = FakeCsMoney()
    fake.script = [web.Response(status=403, headers={"cf-mitigated": "challenge"}, text="<html>")]
    async with serve(fake.app) as base:
        async with CsMoneyHttpClient(make_session("good"), backend=backend, base_url=base) as client:
            with pytest.raises(ChallengeRequiredError):
                await client.request("GET", USER_INFO)


async def test_client_errors_are_not_retried(backend):
    fake = FakeCsMoney()
    async with serve(fake.app) as base:
        async with CsMoneyHttpClient(make_session("good"), backend=backend, base_url=base) as client:
            with pytest.raises(CsMoneyHTTPError) as err:
                await client.request("GET", "/missing")
    assert err.value.status == 404


async def test_redirect_hops_keep_cookies(backend):
    fake = FakeCsMoney()
    async with serve(fake.app) as base:
        async with CsMoneyHttpClient(make_session("bad"), backend=backend, base_url=base) as client:
            assert (await client.get_json("/old")) == {"balance": 10}


async def test_network_error_after_retries(backend):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # closed port
    async with CsMoneyHttpClient(
        make_session(), backend=backend, base_url=f"http://127.0.0.1:{port}", max_retries=1, backoff_base=0.01
    ) as client:
        with pytest.raises(NetworkError):
            await client.request("GET", USER_INFO)


# ── SOCKS bridge ───────────────────────────────────────────────────────────────


class Socks5Server:
    """Minimal RFC 1928/1929 server: username/password auth, CONNECT only."""

    def __init__(self, user: bytes = b"user", password: bytes = b"pass"):
        self.credentials = (user, password)
        self.targets: list[tuple[str, int]] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            _, n = await reader.readexactly(2)
            await reader.readexactly(n)
            writer.write(b"\x05\x02")
            _, ulen = await reader.readexactly(2)
            user = await reader.readexactly(ulen)
            password = await reader.readexactly((await reader.readexactly(1))[0])
            if (user, password) != self.credentials:
                writer.write(b"\x01\x01")
                return
            writer.write(b"\x01\x00")
            _, _, _, atyp = await reader.readexactly(4)
            if atyp == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            else:
                host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
            port = int.from_bytes(await reader.readexactly(2))
            self.targets.append((host, port))
            up_reader, up_writer = await asyncio.open_connection(host, port)
            writer.write(b"\x05\x00\x00\x01" + bytes(6))

            async def pipe(src, dst):
                with contextlib.suppress(ConnectionError):
                    while data := await src.read(65536):
                        dst.write(data)
                        await dst.drain()
                dst.close()

            await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


@contextlib.asynccontextmanager
async def socks_server(**kwargs):
    srv = Socks5Server(**kwargs)
    server = await asyncio.start_server(srv.handle, "127.0.0.1", 0)
    try:
        yield srv, server.sockets[0].getsockname()[1]
    finally:
        server.close()


def hello_app() -> web.Application:
    app = web.Application()

    async def hello(request):
        return web.Response(text=f"hello {request.path_qs}")

    app.router.add_get("/hello", hello)
    return app


async def test_bridge_plain_http_through_authenticated_socks():
    async with serve(hello_app()) as origin, socks_server() as (srv, socks_port):
        upstream = ProxyConfig.parse(f"socks5://user:pass@127.0.0.1:{socks_port}")
        async with SocksBridge(upstream) as local:
            assert local.scheme == "http" and local.username is None
            async with aiohttp.ClientSession() as http:
                async with http.get(f"{origin}/hello?x=1", proxy=local.url) as r:
                    assert r.status == 200 and await r.text() == "hello /hello?x=1"
    assert srv.targets and srv.targets[0][1] == int(origin.rsplit(":", 1)[1])


async def test_bridge_connect_tunnel():
    async with serve(hello_app()) as origin, socks_server() as (_, socks_port):
        port = int(origin.rsplit(":", 1)[1])
        upstream = ProxyConfig.parse(f"socks5://user:pass@127.0.0.1:{socks_port}")
        async with SocksBridge(upstream) as local:
            reader, writer = await asyncio.open_connection(local.host, local.port)
            writer.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
            assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
            writer.write(f"GET /hello HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
            body = await asyncio.wait_for(reader.read(), 5)
            writer.close()
    assert body.startswith(b"HTTP/1.1 200") and body.endswith(b"hello /hello")


async def test_bridge_reports_bad_upstream_credentials():
    async with serve(hello_app()) as origin, socks_server() as (_, socks_port):
        upstream = ProxyConfig.parse(f"socks5://user:WRONG@127.0.0.1:{socks_port}")
        async with SocksBridge(upstream, connect_timeout=5) as local, aiohttp.ClientSession() as http:
            async with http.get(f"{origin}/hello", proxy=local.url) as r:
                assert r.status == 502


async def test_http_client_through_socks_proxy():
    """aiohttp backend with an authenticated SOCKS5 proxy (aiohttp-socks)."""
    fake = FakeCsMoney()
    async with serve(fake.app) as base, socks_server() as (srv, socks_port):
        session = make_session("good", proxy=f"socks5://user:pass@127.0.0.1:{socks_port}")
        async with CsMoneyHttpClient(session, base_url=base) as client:
            assert (await client.get_json(USER_INFO)) == {"balance": 10}
    assert srv.targets


async def test_check_session_runs_requests_in_a_row_and_catches_captcha_on_a_later_one(backend):
    """The observed failure: the first list request passes, the following ones need a captcha (4030)."""
    hits = []

    async def sell_orders(request: web.Request) -> web.Response:
        hits.append(request.query["sort"])
        if len(hits) >= 2:
            return web.json_response({"errors": [{"code": 4030}]}, status=403)
        return web.json_response({"items": []})

    app = web.Application()
    app.router.add_get("/3.0/market/sell-orders", sell_orders)
    paths = ["/3.0/market/sell-orders?limit=1&sort=insertDate", "/3.0/market/sell-orders?limit=1&sort=price"]
    async with serve(app) as base, CsMoneyHttpClient(make_session("x"), backend=backend, base_url=base) as client:
        assert await client.check_session(paths[:1]) == "ok"  # one request alone would have been accepted
        hits.clear()
        assert await client.check_session(paths) == "captcha"
    assert hits == ["insertDate", "price"]
