"""Command line interface.

python -m csmoney_auth login   [-a ID ...] [--force] [--manual] [--headful]
python -m csmoney_auth verify  [-a ID ...]
python -m csmoney_auth status
python -m csmoney_auth request -a ID [-X METHOD] [--json BODY] PATH
python -m csmoney_auth analyze-cookies -a ID
python -m csmoney_auth forget  -a ID
"""

import argparse
import asyncio
import json
import logging
import re
import sys
import time
from pathlib import Path

from .client import analyze_cookies
from .core import (
    ConfigError,
    CsMoneyAuthError,
    SessionNotFound,
    is_cookie_for_csmoney,
    load_config,
    redact,
    setup_logging,
)
from .manager import SessionManager

logger = logging.getLogger("csmoney_auth")


def _ts(value: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value)) if value else "-"


def _table(rows: list[list[str]], header: list[str]) -> str:
    widths = [max(len(str(x)) for x in col) for col in zip(header, *rows, strict=True)]
    line = lambda r: "  ".join(str(x).ljust(w) for x, w in zip(r, widths, strict=True))  # noqa: E731
    return "\n".join([line(header), line(["-" * w for w in widths]), *map(line, rows)])


async def cmd_login(manager: SessionManager, args) -> int:
    ids = args.account or manager.account_ids
    results = await manager.ensure_all(ids, force=args.force)
    failed = 0
    for aid, result in results.items():
        if isinstance(result, BaseException):
            failed += 1
            print(f"{aid}: FAILED - {type(result).__name__}: {redact(str(result))}")
            if not isinstance(result, CsMoneyAuthError):
                logger.error("[%s] unexpected error", aid, exc_info=result)
        else:
            print(
                f"{aid}: OK - steam_id={result.steam_id}, {len(result.cookies)} cookies, "
                f"expires {_ts(result.expires_at)}, proxy={result.proxy_config or 'direct'}"
            )
    return 1 if failed else 0


async def cmd_verify(manager: SessionManager, args) -> int:
    ids = args.account or manager.account_ids
    limit = asyncio.Semaphore(args.jobs)

    async def check(aid):
        async with limit:
            try:
                return await manager.verify(aid)
            except CsMoneyAuthError as e:
                return e

    results = await asyncio.gather(*(check(aid) for aid in ids))
    rc = 0
    for aid, status in zip(ids, results, strict=True):
        if isinstance(status, CsMoneyAuthError):
            print(f"{aid}: check failed - {type(status).__name__}: {redact(str(status))}")
            rc = 1
            continue
        print(f"{aid}: {status or 'no stored session'}")
        rc |= status is None or status.value != "active"
    return rc


async def cmd_status(manager: SessionManager, args) -> int:
    rows = [
        [
            r["account_id"],
            r["steam_id"] or "-",
            r["status"],
            r["proxy_masked"] or "direct",
            _ts(r["created_at"]),
            _ts(r["expires_at"]),
            _ts(r["last_verified_at"]),
            (r["last_error"] or "")[:60],
        ]
        for r in await manager.store.list_overview()
    ]
    if not rows:
        print("no stored sessions")
        return 0
    print(_table(rows, ["account", "steam_id", "status", "proxy", "created", "expires", "verified", "last error"]))
    return 0


async def cmd_request(manager: SessionManager, args) -> int:
    payload = json.loads(args.json) if args.json else None
    async with manager.client(args.account[0]) as client:
        response = await client.request(args.method, args.path, json=payload)
    print(f"HTTP {response.status} {response.headers.get('content-type', '')}")
    print(response.text[: args.limit])
    return 0


async def cmd_analyze(manager: SessionManager, args) -> int:
    session = await manager.store.get(args.account[0])
    if session is None:
        raise SessionNotFound(f"no stored session for {args.account[0]}")
    baseline, verdicts = await analyze_cookies(session, backend=manager.settings.http_backend)
    if not verdicts:
        print(f"baseline check is not OK ({baseline}) - run login first")
        return 1
    rows = [[v.name, v.domain, "REQUIRED" if v.required else "optional", str(v.without_it)] for v in verdicts]
    print(_table(rows, ["cookie", "domain", "verdict", "check without it"]))
    return 0


def _mask(value: str) -> str:
    return f"{value[:4]}...{value[-4:]} ({len(value)} chars)" if len(value) > 12 else "***"


def flat_bundle(session) -> dict:
    """Config-style layout: {cookie name: value, ..., "cookie": "a=1; b=2", "user_agent": ..., "proxy": ...}."""
    cookies = [c for c in session.cookies if is_cookie_for_csmoney(c.domain)]
    flat = {c.name: c.value for c in cookies}
    flat["cookie"] = "; ".join(f"{c.name}={c.value}" for c in cookies)
    flat["user_agent"] = session.user_agent
    if session.proxy:
        flat["proxy"] = session.proxy
    return flat


async def cmd_cookies(manager: SessionManager, args) -> int:
    session = await manager.store.get(args.account[0])
    if session is None:
        raise SessionNotFound(f"no stored session for {args.account[0]}")
    if args.format == "config":
        print(json.dumps(flat_bundle(session), indent=2, ensure_ascii=False))
    elif args.format == "header":
        print("; ".join(f"{c.name}={c.value}" for c in session.cookies))
        print(f"# User-Agent: {session.user_agent}", file=sys.stderr)
    elif args.format == "json":
        print(
            json.dumps(
                {
                    "user_agent": session.user_agent,
                    "proxy": session.proxy if args.reveal else None,
                    "cookies": [c.to_dict() for c in session.cookies],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        rows = [
            [
                c.name,
                c.domain,
                c.path,
                _ts(c.expires) if c.expires else "session",
                "H" * c.http_only + "S" * c.secure,
                c.value if args.reveal else _mask(c.value),
            ]
            for c in session.cookies
        ]
        print(_table(rows, ["name", "domain", "path", "expires", "flags", "value"]))
        print()
        print("flags: H=HttpOnly S=Secure; values are masked, use --reveal to show them")
    return 0


async def cmd_export(manager: SessionManager, args) -> int:
    out_dir = args.dir
    out_dir.mkdir(parents=True, exist_ok=True)
    rc = 0
    for aid in args.account or manager.account_ids:
        session = await manager.store.get(aid)
        if session is None:
            print(f"{aid}: no stored session")
            rc = 1
            continue
        bundle = {
            "account_id": session.account_id,
            "steam_id": session.steam_id,
            "status": session.status.value,
            "proxy": session.proxy,
            "user_agent": session.user_agent,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "last_verified_at": session.last_verified_at,
            "cookies": [c.to_dict() for c in session.cookies],
        }
        if args.format == "config":
            bundle = flat_bundle(session)
        path = out_dir / f"{aid}.json"
        path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"{aid}: {len(session.cookies)} cookies -> {path}")
    return rc


async def cmd_forget(manager: SessionManager, args) -> int:
    for aid in args.account:
        print(f"{aid}: {'deleted' if await manager.store.delete(aid) else 'nothing stored'}")
    return 0


def read_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


_COMMENT = re.compile(r"\s+#.*$")


def parse_account_line(line: str) -> tuple[str, str, str, str]:
    """``login,password[,email | shared_secret]`` or the same with ``:``; returns (login, password, email, secret).

    Fields after the email (e.g. the mailbox password) and a trailing `` # comment`` are ignored."""
    line = _COMMENT.sub("", line).strip()
    sep = "," if "," in line else ":"
    fields = [f.strip() for f in line.split(sep)]
    login = fields[0]
    at = next((i for i in range(2, len(fields)) if "@" in fields[i]), None)
    if at is not None:  # the email marks where the password ends (a ':' password stays whole)
        return login, sep.join(fields[1:at]), fields[at], ""
    password = fields[1] if len(fields) > 1 else ""
    return login, password, "", fields[2] if len(fields) > 2 else ""


def cmd_import(args) -> int:
    config = json.loads(args.config.read_text(encoding="utf-8")) if args.config.exists() else {}
    accounts = config.setdefault("accounts", [])
    existing = {a["account_id"] for a in accounts}
    proxies = read_lines(args.proxies) if args.proxies else []

    new = []
    updated = []
    for number, line in enumerate(read_lines(args.accounts), 1):
        if line.startswith("#"):
            continue
        login, password, email, shared_secret = parse_account_line(line)
        if args.logins_only:
            password = shared_secret = ""
        elif not (login and password):
            print(f"line {number}: expected 'login,password' or 'login:password' - skipped")
            continue
        if login in existing or any(a["account_id"] == login for a in new):
            current = next((a for a in accounts + new if a["account_id"] == login), None)
            if email and current is not None and not current.get("email"):
                current["email"] = email
                updated.append(login)
            print(f"line {number}: {login} already present - skipped")
            continue
        if not login:
            print(f"line {number}: empty login - skipped")
            continue
        entry = {"account_id": login}
        if not args.logins_only:
            entry["steam"] = {"username": login, "password": password}
            if shared_secret:
                entry["steam"]["shared_secret"] = shared_secret
        if email:
            entry["email"] = email
        if len(new) < len(proxies):
            entry["proxy"] = proxies[len(new)]
        new.append(entry)

    if proxies and len(proxies) < len(new):
        print(f"warning: {len(new) - len(proxies)} of {len(new)} new accounts got no proxy (only {len(proxies)} given)")
    if proxies and len(proxies) > len(new):
        print(f"note: {len(proxies) - len(new)} proxies were not used")
    print(f"{len(new)} account(s) to add, {len(existing)} already in {args.config}, email added to {len(updated)}")
    if args.dry_run or not (new or updated):
        return 0
    accounts.extend(new)
    args.config.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"written to {args.config}")
    return 0


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m csmoney_auth", description="CS.MONEY sessions via Steam + Camoufox"
    )
    parser.add_argument("-c", "--config", type=Path, default=Path("config.json"))
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging (secrets stay masked)")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_accounts(p: argparse.ArgumentParser, required: bool = False) -> argparse.ArgumentParser:
        p.add_argument("-a", "--account", action="append", required=required, help="account_id (repeatable)")
        return p

    login = with_accounts(sub.add_parser("login", help="ensure valid sessions (browser login when needed)"))
    login.add_argument("--force", action="store_true", help="new browser login even if the stored session is valid")
    login.add_argument(
        "--manual", action="store_true", help="visible browser; wait for a human when Steam/Cloudflare need one"
    )
    login.add_argument("--window", metavar="WxH", help="browser window size, e.g. 1100x650")
    login.add_argument("--headful", action="store_true", help="show the browser window")
    login.add_argument(
        "--keep-open", action="store_true", help="show the window and keep it open after login (implies --headful)"
    )
    login.add_argument(
        "--step-delay", type=float, default=0.0, metavar="SEC", help="pause after each stage to watch the flow"
    )
    login.set_defaults(handler=cmd_login)

    verify = with_accounts(sub.add_parser("verify", help="check stored sessions over HTTP (no browser)"))
    verify.add_argument("-j", "--jobs", type=positive_int, default=8, help="parallel checks (default: 8)")
    verify.set_defaults(handler=cmd_verify)
    sub.add_parser("status", help="list stored sessions (no secrets)").set_defaults(handler=cmd_status)

    request = with_accounts(sub.add_parser("request", help="HTTP request with a stored session"), required=True)
    request.add_argument("path", help="path or URL, e.g. /api/public/v3/user-info")
    request.add_argument("-X", "--method", default="GET")
    request.add_argument("--json", help="JSON body")
    request.add_argument("--limit", type=int, default=2000, help="print at most N characters of the body")
    request.set_defaults(handler=cmd_request)

    with_accounts(
        sub.add_parser("analyze-cookies", help="find which cookies the session needs"), required=True
    ).set_defaults(handler=cmd_analyze)
    cookies = with_accounts(sub.add_parser("cookies", help="show stored cookies of an account"), required=True)
    cookies.add_argument("--reveal", action="store_true", help="show full values (secrets!)")
    cookies.add_argument(
        "--format",
        choices=["table", "json", "header", "config"],
        default="table",
        help="config = flat {name: value} + cookie string + user_agent + proxy; header = 'Cookie:' value; "
        "json = full export (all but table always include values)",
    )
    cookies.set_defaults(handler=cmd_cookies)
    export = with_accounts(sub.add_parser("export", help="save cookies + proxy + User-Agent as JSON files"))
    export.add_argument("-d", "--dir", type=Path, default=Path("exports"), help="output directory (default: exports)")
    export.add_argument(
        "--format", choices=["full", "config"], default="full", help="config = flat layout like cookies --format config"
    )
    export.set_defaults(handler=cmd_export)
    with_accounts(sub.add_parser("forget", help="delete stored data of an account"), required=True).set_defaults(
        handler=cmd_forget
    )
    importer = sub.add_parser("import", help="import login,password[,email or shared_secret] (or the same with ':') from a text file")
    importer.add_argument("accounts", type=Path)
    importer.add_argument("--proxies", type=Path, help="one proxy per new account, in order")
    importer.add_argument("--logins-only", action="store_true", help="store only logins, ignore passwords")
    importer.add_argument("--dry-run", action="store_true", help="preview without writing config")
    importer.set_defaults(handler=cmd_import)
    return parser


async def _main(args) -> int:
    if args.command == "import":
        return cmd_import(args)
    settings, accounts = load_config(args.config)
    if getattr(args, "manual", False):
        settings.manual = True
    if getattr(args, "window", None):
        try:
            settings.window = [int(x) for x in args.window.lower().split("x")]
        except ValueError:
            raise ConfigError("--window expects WIDTHxHEIGHT, e.g. 1100x650") from None
    settings.keep_open = getattr(args, "keep_open", False)
    settings.step_delay = getattr(args, "step_delay", 0.0)
    if getattr(args, "headful", False) or settings.manual or settings.keep_open:
        settings.headless = False
    async with SessionManager.open(settings, accounts) as manager:
        return await args.handler(manager, args)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging("DEBUG" if args.verbose else "INFO")
    try:
        return asyncio.run(_main(args))
    except CsMoneyAuthError as e:
        print(f"error: {type(e).__name__}: {redact(str(e))}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
