"""CLI import, maFile discovery, bounded verification and dependency loading (no external requests)."""

import argparse
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from csmoney_auth.__main__ import build_parser, cmd_verify, main, parse_account_line
from csmoney_auth.core import ConfigError, CsMoneySession, NetworkError, SessionStatus, StoredCookie, load_config
from csmoney_auth.store import SecretBox, SessionStore

ROOT = Path(__file__).resolve().parents[1]
CLI_WITHOUT_LOGIN = """
import importlib.abc, json, sys
class BlockLogin(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('camoufox', 'playwright', 'aiosteampy') or fullname in (
            'csmoney_auth.browser', 'csmoney_auth.steam'
        ):
            raise AssertionError('Unexpected login import: ' + fullname)
sys.meta_path.insert(0, BlockLogin())
from csmoney_auth.__main__ import main
rc = main(json.loads(sys.argv[1]))
assert rc == int(sys.argv[2]), rc
"""


def write_config(tmp_path, accounts, **settings):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"settings": settings, "accounts": accounts}), encoding="utf-8")
    return path


def test_import_file_and_fill_missing_email_without_overwriting_existing_data(tmp_path, capsys):
    existing = {"account_id": "existing", "steam": {"password": "kept"}, "proxy": "http://old:80"}
    config = write_config(tmp_path, [existing])
    source = tmp_path / "accounts.txt"
    source.write_text(
        "\ufeffexisting,unused,first@example.org\n"
        "alice,test-password,alice@example.org\n"
        "bob,another-password,c2VjcmV0\n"
        "alice,ignored,replacement@example.org\n"
        "invalid\n",
        encoding="utf-8",
    )
    proxies = tmp_path / "proxies.txt"
    proxies.write_text("http://one:80\nsocks5://two:1080\n", encoding="utf-8")
    argv = ["-c", str(config), "import", str(source), "--proxies", str(proxies)]
    original = config.read_bytes()
    assert main([*argv, "--dry-run"]) == 0
    assert config.read_bytes() == original
    assert main(argv) == 0
    a, b, c = json.loads(config.read_text(encoding="utf-8"))["accounts"]
    assert a == existing | {"email": "first@example.org"}
    assert b == {
        "account_id": "alice",
        "steam": {"username": "alice", "password": "test-password"},
        "email": "alice@example.org",
        "proxy": "http://one:80",
    }
    assert c["steam"] == {"username": "bob", "password": "another-password", "shared_secret": "c2VjcmV0"}
    assert c["proxy"] == "socks5://two:1080" and "email" not in c
    assert main(argv) == 0
    assert len(json.loads(config.read_text(encoding="utf-8"))["accounts"]) == 3
    output = capsys.readouterr().out
    assert "test-password" not in output and "c2VjcmV0" not in output and "unused" not in output


def test_import_can_create_config_and_preserves_logins_only_mode(tmp_path):
    config = tmp_path / "config.json"
    source = tmp_path / "accounts.txt"
    source.write_text("alice,password,alice@example.org\n", encoding="utf-8")
    assert main(["-c", str(config), "import", str(source), "--logins-only"]) == 0
    assert json.loads(config.read_text())["accounts"] == [{"account_id": "alice", "email": "alice@example.org"}]


def test_mafile_discovery_is_case_insensitive_and_relative_to_config(tmp_path):
    directory = tmp_path / "maFiles"
    directory.mkdir()
    mafile = directory / "MiXeD.MaFiLe"
    mafile.write_text(json.dumps({"account_name": "mixed", "shared_secret": "c2VjcmV0"}))
    config = write_config(tmp_path, [{"account_id": "mixed"}, {"account_id": "without"}])
    _, (found, missing) = load_config(config)
    assert found.steam.mafile == mafile
    assert found.steam.shared_secret == "c2VjcmV0" and found.steam.username == "mixed"
    assert missing.steam.mafile is None


def test_explicit_mafile_takes_precedence_and_missing_explicit_path_is_an_error(tmp_path):
    directory = tmp_path / "maFiles"
    directory.mkdir()
    (directory / "alice.mafile").write_text('{"shared_secret":"automatic"}')
    explicit = tmp_path / "chosen.mafile"
    explicit.write_text('{"shared_secret":"explicit"}')
    config = write_config(tmp_path, [{"account_id": "alice", "steam": {"mafile": explicit.name}}])
    assert load_config(config)[1][0].steam.shared_secret == "explicit"
    config = write_config(tmp_path, [{"account_id": "alice", "steam": {"mafile": "missing.mafile"}}])
    with pytest.raises(ConfigError, match="cannot read maFile"):
        load_config(config)


@pytest.mark.parametrize("jobs", [1, 3, 8])
async def test_verify_limits_concurrency_and_keeps_output_order(jobs, capsys):
    class Manager:
        account_ids = [str(i) for i in range(17)]
        running = peak = 0
        completed = []

        async def verify(self, aid):
            self.running += 1
            self.peak = max(self.peak, self.running)
            try:
                await asyncio.sleep(0.01)
                self.completed.append(aid)
                if aid == "2":
                    raise NetworkError("offline")
                return None if aid == "4" else SessionStatus.ACTIVE
            finally:
                self.running -= 1

    manager = Manager()
    assert await cmd_verify(manager, argparse.Namespace(account=None, jobs=jobs)) == 1
    assert manager.peak == jobs
    assert set(manager.completed) == set(manager.account_ids)
    lines = capsys.readouterr().out.splitlines()
    assert [line.split(":")[0] for line in lines] == manager.account_ids
    assert "NetworkError" in lines[2] and "no stored session" in lines[4]


def test_verify_jobs_must_be_positive():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["verify", "--jobs", "0"])


@pytest.mark.parametrize("command", ["status", "cookies", "export", "verify", "import"])
async def test_cli_does_not_load_login_dependencies(tmp_path, command):
    config = write_config(tmp_path, [{"account_id": "alice"}], data_dir="data")
    data = tmp_path / "data"
    box = SecretBox.load(data / "store.key")
    if command != "verify":
        async with SessionStore(data / "sessions.db", box) as store:
            await store.save(
                CsMoneySession(
                    account_id="alice",
                    steam_id="76561198000000001",
                    cookies=[StoredCookie("csgo_ses", "fake-session", "cs.money")],
                    proxy=None,
                    user_agent="TestUA",
                    created_at=time.time(),
                    expires_at=None,
                    status=SessionStatus.ACTIVE,
                )
            )
    argv = ["-c", str(config), command]
    if command == "cookies":
        argv += ["-a", "alice"]
    elif command == "export":
        argv += ["-d", str(tmp_path / "exports")]
    elif command == "import":
        source = tmp_path / "accounts.txt"
        source.write_text("bob,password,bob@example.org\n")
        argv += [str(source), "--dry-run"]
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", CLI_WITHOUT_LOGIN, json.dumps(argv), str(int(command == "verify"))],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


async def test_verify_saved_session_uses_http_without_login_imports(tmp_path):
    from aiohttp import web

    from .test_network import serve

    hits = []

    async def check(request):
        assert request.cookies.get("csgo_ses") == "fake-session"
        hits.append(request.query["page"])
        return web.json_response({"items": []})

    app = web.Application()
    app.router.add_get("/check", check)
    async with serve(app) as base:
        config = write_config(
            tmp_path,
            [{"account_id": "alice"}],
            data_dir="data",
            check_paths=[f"{base}/check?page={i}" for i in range(3)],
        )
        data = tmp_path / "data"
        box = SecretBox.load(data / "store.key")
        async with SessionStore(data / "sessions.db", box) as store:
            await store.save(
                CsMoneySession(
                    account_id="alice",
                    steam_id=None,
                    cookies=[StoredCookie("csgo_ses", "fake-session", "127.0.0.1")],
                    proxy=None,
                    user_agent="TestUA",
                    created_at=time.time(),
                    expires_at=None,
                    status=SessionStatus.ACTIVE,
                )
            )
        result = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-c", CLI_WITHOUT_LOGIN, json.dumps(["-c", str(config), "verify"]), "0"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert "alice: active" in result.stdout and hits == ["0", "1", "2"]


async def test_lazy_login_components_are_reused_and_closed_on_error(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from csmoney_auth import browser, steam
    from csmoney_auth.core import Account, Settings, SteamCredentials
    from csmoney_auth.manager import SessionManager

    created, closed = [], []

    class Browser:
        def __init__(self, settings):
            created.append("browser")

        async def close(self):
            closed.append("browser")

    class Steam:
        def __init__(self, store, **kwargs):
            created.append("steam")

        async def web_session(self, account, **kwargs):
            return SimpleNamespace(source="test", steam_id="test")

    monkeypatch.setattr(browser, "CamoufoxAuthenticator", Browser)
    monkeypatch.setattr(steam, "SteamAuthProvider", Steam)
    with pytest.raises(RuntimeError, match="test failure"):
        async with SessionManager.open(Settings(data_dir=tmp_path), []) as manager:
            assert manager._browser is None and manager._steam is None
            account = Account("alice", None, SteamCredentials())
            await manager._steam_session(account, force_refresh=False)
            await manager._steam_session(account, force_refresh=False)
            assert created == ["browser", "steam"]
            raise RuntimeError("test failure")
    assert closed == ["browser"]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("alice,pw,alice@example.org", ("alice", "pw", "alice@example.org", "")),
        ("bob,pw,c2VjcmV0", ("bob", "pw", "", "c2VjcmV0")),
        ("carol:pw:carol@example.org", ("carol", "pw", "carol@example.org", "")),
        ("dave:pw:dave@example.org:MailPass!  # RYB2I-BK9W7", ("dave", "pw", "dave@example.org", "")),
        ("erin:p:w#1:erin@example.org", ("erin", "p:w#1", "erin@example.org", "")),
        ("frank:pw:c2VjcmV0", ("frank", "pw", "", "c2VjcmV0")),
        ("grace:pw", ("grace", "pw", "", "")),
        ("invalid", ("invalid", "", "", "")),
    ],
)
def test_parse_account_line_accepts_comma_and_colon(line, expected):
    assert parse_account_line(line) == expected


def test_import_reads_colon_lines_and_skips_comments(tmp_path, capsys):
    config = write_config(tmp_path, [])
    source = tmp_path / "accounts.txt"
    source.write_text("# header\nalice:pw:alice@example.org:MailPass # code\n", encoding="utf-8")
    assert main(["-c", str(config), "import", str(source)]) == 0
    assert json.loads(config.read_text(encoding="utf-8"))["accounts"] == [
        {"account_id": "alice", "steam": {"username": "alice", "password": "pw"}, "email": "alice@example.org"}
    ]
    assert "MailPass" not in capsys.readouterr().out
