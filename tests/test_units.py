"""Pure logic: proxies, cookies, CS.MONEY response classification, redaction, config parsing."""

import json
import time

import pytest

from csmoney_auth import core as csmoney
from csmoney_auth.core import (
    ConfigError,
    ProxyConfig,
    ResponseKind,
    Settings,
    StoredCookie,
    classify_response,
    cookie_header,
    cookies_for_url,
    jwt_expiry,
    load_config,
    merge_cookie,
    parse_set_cookie,
    redact,
    session_expiry,
)

from .conftest import make_jwt

# ── proxy ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "scheme", "host", "port", "user", "password"),
    [
        ("http://user:p%40ss@1.2.3.4:8080", "http", "1.2.3.4", 8080, "user", "p@ss"),
        ("socks5://u:p@proxy.example:1080", "socks5", "proxy.example", 1080, "u", "p"),
        ("1.2.3.4:3128", "http", "1.2.3.4", 3128, None, None),
        ("1.2.3.4:3128:user:secret", "http", "1.2.3.4", 3128, "user", "secret"),
        ("SOCKS5H://h:1", "socks5h", "h", 1, None, None),
    ],
)
def test_proxy_parse(raw, scheme, host, port, user, password):
    p = ProxyConfig.parse(raw)
    assert (p.scheme, p.host, p.port, p.username, p.password) == (scheme, host, port, user, password)
    assert ProxyConfig.parse(p.url) == p  # url round-trips (credentials are percent-encoded)


def test_proxy_masking_and_browser_mapping():
    p = ProxyConfig.parse("http://user:secret@1.2.3.4:8080")
    assert "secret" not in p.masked and "secret" not in str(p) and "secret" not in repr(p)
    assert p.to_playwright() == {"server": "http://1.2.3.4:8080", "username": "user", "password": "secret"}
    assert not p.needs_browser_bridge

    socks = ProxyConfig.parse("socks5h://user:secret@h:1080")
    assert socks.needs_browser_bridge
    assert socks.socks_client_url().startswith("socks5://")
    with pytest.raises(ValueError):
        socks.to_playwright()
    assert ProxyConfig.parse("socks5h://h:1080").to_playwright() == {"server": "socks5://h:1080"}


@pytest.mark.parametrize("raw", ["ftp://h:1", "http://host", "garbage", "h:1:2"])
def test_proxy_invalid(raw):
    with pytest.raises(ConfigError):
        ProxyConfig.parse(raw)


# ── cookies ────────────────────────────────────────────────────────────────────


def test_parse_set_cookie_attributes():
    now = 1_000_000.0
    c = parse_set_cookie(
        "csgo_ses=abc; Path=/; Domain=.cs.money; Max-Age=60; Expires=Wed, 21 Oct 2015 07:28:00 GMT; "
        "Secure; HttpOnly; SameSite=Lax",
        "cs.money",
        now,
    )
    assert c == StoredCookie("csgo_ses", "abc", ".cs.money", "/", now + 60, True, True, "Lax")
    assert parse_set_cookie("x=1; Domain=evil.com", "cs.money") is None
    assert parse_set_cookie("novalue", "cs.money") is None
    assert parse_set_cookie('q="quoted"', "cs.money").value == "quoted"


def test_cookie_selection_rules():
    now = time.time()
    jar = [
        StoredCookie("host", "1", "cs.money"),
        StoredCookie("dom", "2", ".cs.money", "/"),
        StoredCookie("api", "3", "cs.money", "/api"),
        StoredCookie("sec", "4", "cs.money", secure=True),
        StoredCookie("old", "5", "cs.money", expires=now - 1),
        StoredCookie("other", "6", "steamcommunity.com"),
    ]
    names = [c.name for c in cookies_for_url(jar, "https://cs.money/api/public/v3/user-info", now)]
    assert names[0] == "api" and set(names) == {"host", "dom", "api", "sec"}
    assert [c.name for c in cookies_for_url(jar, "http://cs.money/apix", now)] == ["host", "dom"]
    assert [c.name for c in cookies_for_url(jar, "https://www.cs.money/", now)] == ["dom"]
    assert cookie_header(jar[:2]) == "host=1; dom=2"


def test_merge_cookie_replace_and_delete():
    jar = [StoredCookie("a", "1", "cs.money")]
    assert merge_cookie(jar, StoredCookie("a", "2", "cs.money"))
    assert jar[0].value == "2"
    assert not merge_cookie(jar, StoredCookie("a", "2", "cs.money"))
    assert merge_cookie(jar, StoredCookie("a", "", "cs.money", expires=1.0))
    assert jar == []


def test_playwright_round_trip():
    c = StoredCookie("csgo_ses", "v", "cs.money", "/", None, True, True, None)
    pw = c.to_playwright()
    assert pw["expires"] == -1 and pw["sameSite"] == "Lax"
    assert StoredCookie.from_playwright({**pw, "sameSite": None}) == c


def test_jwt_expiry_and_session_expiry():
    token = make_jwt(exp_in=100)
    exp = jwt_expiry(token)
    assert exp is not None and abs(exp - (time.time() + 100)) < 5
    assert jwt_expiry("not-a-jwt") is None
    cookies = [
        StoredCookie("csgo_ses", token, "cs.money", expires=time.time() + 10_000),
        StoredCookie("cf_clearance", "x", ".cs.money", expires=time.time() + 5),
    ]
    assert session_expiry(cookies) == pytest.approx(exp)
    cookies.append(StoredCookie("steamid", "7656", ".cs.money", expires=time.time() + 50))  # required too
    assert session_expiry(cookies) == pytest.approx(time.time() + 50, abs=2)
    assert session_expiry([StoredCookie("csgo_ses", "opaque", "cs.money")]) is None


# ── CS.MONEY facts ─────────────────────────────────────────────────────────────

JSON = {"content-type": "application/json; charset=utf-8"}


@pytest.mark.parametrize(
    ("status", "headers", "body", "kind"),
    [
        (200, JSON, '{"balance": 1}', ResponseKind.OK),
        (400, JSON, '{"errors":[{"code":6}]}', ResponseKind.AUTH),  # real guest answer of user-info
        (200, JSON, '{"errors":[{"code":6}]}', ResponseKind.AUTH),
        (401, {}, "", ResponseKind.AUTH),
        (403, {}, "Forbidden", ResponseKind.AUTH),
        (403, {"cf-mitigated": "challenge"}, "", ResponseKind.CHALLENGE),
        (503, {}, "<script>window._cf_chl_opt={}</script>", ResponseKind.CHALLENGE),
        (429, {}, "", ResponseKind.RATE_LIMIT),
        (200, JSON, '{"errors":[{"code":9999}]}', ResponseKind.RATE_LIMIT),
        (502, {}, "Bad gateway", ResponseKind.SERVER),
        (404, {}, "Not Found", ResponseKind.CLIENT),
        (400, JSON, "{broken", ResponseKind.CLIENT),
    ],
)
def test_classify_response(status, headers, body, kind):
    assert classify_response(status, headers, body)[0] is kind


def test_login_url_matches_site_button():
    url = csmoney.build_login_url()
    assert url.startswith("https://cs.money/api/public/v1/auth/steam-login?")
    assert "callbackUrl=https%3A%2F%2Fcs.money%2Flogin" in url and "redirectQuery=" in url


@pytest.mark.parametrize(
    ("url", "final"),
    [
        ("https://cs.money/ro/", True),
        ("https://cs.money/market/buy/?a=1", True),
        ("https://cs.money/api/public/v1/auth/steam-callback?x", False),
        ("https://cs.money/login?token=1", False),
        ("https://steamcommunity.com/openid/login", False),
        ("https://cs.money.evil.com/", False),
    ],
)
def test_final_url(url, final):
    assert csmoney.is_final_csmoney_url(url) is final


def test_parse_app_user():
    raw = json.dumps({"userInfo": {"isLogged": True, "steamId64": "76561198000000001"}})
    assert csmoney.parse_app_user(raw) == csmoney.AppUser(True, "76561198000000001")
    assert csmoney.parse_app_user(json.dumps({"userInfo": {"isLogged": False, "steamId64": ""}})) == csmoney.AppUser(
        False, None
    )
    assert csmoney.parse_app_user("<html>") is None


# ── logs ───────────────────────────────────────────────────────────────────────


def test_redact():
    jwt = make_jwt()
    text = (
        f"Cookie: csgo_ses=SECRET1; cf_clearance=SECRET2 steamLoginSecure=76561198000000001%7C%7C{jwt} "
        f"bare {jwt} proxy socks5://user:SECRET3@1.2.3.4:1080"
    )
    out = redact(text)
    for secret in ("SECRET1", "SECRET2", "SECRET3", jwt):
        assert secret not in out
    assert "1.2.3.4:1080" in out


# ── config ─────────────────────────────────────────────────────────────────────


def test_load_config_with_mafile(tmp_path):
    rt = make_jwt(refresh=True)
    (tmp_path / "a.maFile").write_text(
        json.dumps(
            {
                "shared_secret": "c2VjcmV0",
                "account_name": "login1",
                "Session": {"SteamID": 76561198000000001, "RefreshToken": rt, "SessionID": "abc"},
            }
        )
    )
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "settings": {"headless": False, "http_backend": "httpx"},
                "accounts": [
                    {"account_id": "a", "proxy": "socks5://u:p@h:1", "steam": {"mafile": "a.maFile"}},
                    {"account_id": "b", "steam": {"cookies": "steamLoginSecure=x; sessionid=y"}},
                ],
            }
        )
    )
    settings, accounts = load_config(tmp_path / "config.json")
    assert isinstance(settings, Settings) and settings.http_backend == "httpx"
    assert settings.data_dir == tmp_path / "data"
    a, b = accounts
    assert a.steam_id == "76561198000000001" and a.steam.refresh_token == rt
    assert a.steam.username == "login1" and a.steam.cookies["sessionid"] == "abc"
    assert a.proxy.needs_browser_bridge
    assert b.proxy is None and b.steam.cookies == {"steamLoginSecure": "x", "sessionid": "y"}


@pytest.mark.parametrize(
    "payload",
    [
        {"settings": {"nope": 1}},
        {"accounts": [{"account_id": "a"}, {"account_id": "a"}]},
        {"accounts": [{"steam": {}}]},
        {"settings": {"http_backend": "requests"}},
    ],
)
def test_config_errors(tmp_path, payload):
    (tmp_path / "config.json").write_text(json.dumps(payload))
    with pytest.raises(ConfigError):
        load_config(tmp_path / "config.json")


def test_parse_app_user_registration_flag():
    raw = json.dumps({"userInfo": {"isLogged": True, "steamId64": "1", "isRegistered": False}})
    assert csmoney.parse_app_user(raw).is_registered is False
    raw = json.dumps({"userInfo": {"isLogged": True, "steamId64": "1", "isRegistered": True}})
    assert csmoney.parse_app_user(raw).is_registered is True


def test_emails_file_fills_account_email(tmp_path):
    from csmoney_auth.core import load_config

    (tmp_path / "config.json").write_text(
        json.dumps({"accounts": [{"account_id": "a"}, {"account_id": "b", "email": "own@x.io"}]})
    )
    (tmp_path / "emails.txt").write_text("a,pw,a@x.io\nb,b@x.io\nbad line\n")
    _, accounts = load_config(tmp_path / "config.json")
    assert [a.email for a in accounts] == ["a@x.io", "own@x.io"]
