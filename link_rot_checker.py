#!/usr/bin/env python3
"""Audit HTTP(S) links in UTF-8 Markdown and plain-text files."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import errno
import http.client
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import tempfile
import time
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


CLASSES = ("ok", "redirect", "client-error", "server-error", "unreachable")
DEAD = frozenset(CLASSES[2:])
TRANSIENT = frozenset({408, 425, 429, 500, 502, 503, 504})
SCHEME = re.compile(r"https?://", re.I)
BARE_END = frozenset(" \t\r\n<>\"`|")
CLOSERS = {")": "(", "]": "[", "}": "{"}
MAX_RETRY_WAIT = 10.0
SAFE_PATH = "/%:@!$&'()*+,;=-._~"
USER_AGENT_RE = re.compile(r"[ -~]+")


def extract(line):
    """Yield every http(s) URL from *line*, heeding common Markdown wrappers."""
    pos = 0
    while True:
        match = SCHEME.search(line, pos)
        if not match:
            return
        start = match.start()
        angle = start > 0 and line[start - 1] == "<"
        inline = line[:start].rstrip().endswith("](")
        stack = []
        i = match.end()
        while i < len(line):
            ch = line[i]
            if ch.isspace() or ch in BARE_END:
                break
            if not angle:
                if ch in "([{":
                    stack.append(ch)
                elif ch in CLOSERS:
                    if not stack or stack[-1] != CLOSERS[ch]:
                        break
                    stack.pop()
            i += 1
        url = line[start:i]
        if not (angle or inline):
            url = url.rstrip(".,;:!?")
            if start and line[start - 1] == "'":
                url = url.rstrip("'")
        yield url
        pos = i


def without_credentials(url: str) -> str:
    """Return *url* with any embedded userinfo removed."""
    parts = urlsplit(url)
    if parts.username is None:
        return url
    host = parts.hostname or ""
    port = parts.port
    if ":" in host:
        netloc = f"[{host}]:{port}" if port is not None else f"[{host}]"
    else:
        netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def wire_url(url: str) -> str:
    """Validate and normalise *url* for network use (IDNA, percent-encoding)."""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise ValueError("control character in URL")
    parts = urlsplit(url)
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError("expected an HTTP(S) hostname")
    if parts.username is not None or "\\" in parts.netloc:
        raise ValueError("unsupported URL authority")
    port = parts.port  # validates port range
    host = host.encode("idna").decode("ascii")
    authority = "[" + host + "]" if ":" in host else host
    if port is not None:
        authority += ":" + str(port)
    # '%' is kept safe so already-percent-encoded bytes are not double-encoded.
    safe = SAFE_PATH + "%"
    return urlunsplit((
        parts.scheme,
        authority,
        quote(parts.path, safe=safe),
        quote(parts.query, safe=safe + "?"),
        "",  # fragment is never sent
    ))


class Redirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            target = wire_url(newurl)
        except ValueError:
            fp.close()
            raise
        redirected = super().redirect_request(req, fp, code, msg, headers, target)
        if redirected is not None:
            redirected.method = req.get_method()
        return redirected


@dataclass(frozen=True)
class Result:
    status: str
    code: Optional[int] = None
    final_url: Optional[str] = None
    detail: str = ""


def retry_delay(header):
    if not header:
        return 1
    value = header.strip()
    if value.isdigit():
        return int(value)
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except (ValueError, OverflowError, TypeError):
        return 1


def _is_temporary(reason) -> bool:
    """Return True when *reason* looks like a transient network failure."""
    if isinstance(reason, ssl.SSLError):
        return False
    if isinstance(reason, (TimeoutError, ConnectionError, http.client.RemoteDisconnected)):
        return True
    errno_ = getattr(reason, "errno", None)
    return errno_ in (errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH, socket.EAI_AGAIN)


def attempt(opener, target, agent, timeout, method):
    """Check *target* once. Returns (Result, retry_delay_or_None)."""
    try:
        req = Request(target, headers={"User-Agent": agent}, method=method)
        with opener.open(req, timeout=timeout) as response:
            final = response.geturl()
            return Result("redirect" if final != target else "ok", response.status, final), None
    except HTTPError as exc:
        try:
            code = exc.code
            group = ("client-error" if 400 <= code < 500 else
                     "server-error" if 500 <= code < 600 else "unreachable")
            delay = retry_delay(exc.headers.get("Retry-After")) if code in TRANSIENT else None
            return Result(group, code, exc.geturl(), str(exc.reason)), delay
        finally:
            exc.close()
    except (OSError, ValueError, http.client.HTTPException) as exc:
        reason = exc.reason if isinstance(exc, URLError) else exc
        detail = str(reason)
        temporary = _is_temporary(reason)
        return Result("unreachable", detail=detail), 1 if temporary else None


def check(url, timeout, agent):
    try:
        target = wire_url(url)
    except ValueError as exc:
        return Result("unreachable", detail=str(exc))

    opener = build_opener(Redirects())
    result, delay = attempt(opener, target, agent, timeout, "HEAD")

    # Healthy link or definitive non-HTTP failure: done.
    if result.status not in DEAD:
        return result
    if delay is None and result.code is None:
        return result

    # Retry a transient HEAD failure once as GET. For definitive HTTP
    # rejections (e.g. 405) fall back to GET because some hosts block HEAD.
    if delay is not None and delay > MAX_RETRY_WAIT:
        return result
    if delay is not None:
        time.sleep(delay)

    fallback, next_delay = attempt(opener, target, agent, timeout, "GET")
    # A definitive HEAD rejection that yields a transient GET failure gets
    # its single allowed retry.
    if delay is None and next_delay is not None and next_delay <= MAX_RETRY_WAIT:
        time.sleep(next_delay)
        fallback, _ = attempt(opener, target, agent, timeout, "GET")
    return fallback


def collect(paths):
    links = {}
    for path in paths:
        with path.open(encoding="utf-8-sig") as stream:
            for number, line in enumerate(stream, 1):
                for url in extract(line):
                    # Never send embedded credentials over the wire or into
                    # reports; drop them before anything else.
                    try:
                        url = without_credentials(url)
                    except ValueError:
                        pass
                    links.setdefault(url, []).append({"file": str(path), "line": number})
    return links


def cell(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\\", "\\\\").replace("|", "\\|")
            .replace("\r", " ").replace("\n", " "))


def markdown(rows, counts):
    lines = ["# Link rot report", "", "| Status | Unique URLs |", "|---|---:|"]
    lines.extend(f"| {key} | {counts[key]} |" for key in CLASSES)
    lines.extend(["", "| URL | Status | HTTP | Final URL | Detail | Sources |",
                  "|---|---|---:|---|---|---|"])
    for row in rows:
        sources = ", ".join(f"{s['file']}:{s['line']}" for s in row["sources"])
        fields = (row["url"], row["status"], row["code"] or "", row["final_url"] or "",
                  row["detail"], sources)
        lines.append("| " + " | ".join(map(cell, fields)) + " |")
    return "\n".join(lines) + "\n"


def save(path, content):
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, delete=False) as stream:
            tmp = Path(stream.name)
            stream.write(content)
        os.replace(tmp, path)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path, help="input file(s)")
    parser.add_argument("--timeout", type=float, default=10, metavar="SECONDS",
                        help="socket operation timeout (default: 10)")
    parser.add_argument("--workers", type=int, default=8,
                        help="maximum concurrent URL checks (default: 8)")
    parser.add_argument("--out", type=Path, help="write a .md or .json report")
    parser.add_argument("--user-agent", default="LinkRotChecker/1.0",
                        help="HTTP User-Agent header")
    args = parser.parse_args()

    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 86400:
        parser.error("--timeout must be positive and at most 86400 seconds")
    if not 1 <= args.workers <= 256:
        parser.error("--workers must be between 1 and 256")
    if not USER_AGENT_RE.fullmatch(args.user_agent) or not args.user_agent.strip():
        parser.error("--user-agent must contain visible ASCII text without controls")

    if args.out:
        suffix = args.out.suffix.lower()
        if suffix not in (".json", ".md"):
            parser.error("--out must end in .json or .md")
        if args.out.exists() and any(args.out.samefile(p) for p in args.files):
            parser.error("output must not overwrite an input file")
        if not args.out.parent.is_dir():
            parser.error("output directory does not exist")

    try:
        links = collect(args.files)
        rows = []
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = pool.map(lambda u: check(u, args.timeout, args.user_agent), links)
            for url, result in zip(links, results):
                rows.append(dict(url=url, sources=links[url], **asdict(result)))
        counts = Counter(row["status"] for row in rows)

        if args.out:
            if args.out.suffix.lower() == ".json":
                report = {"summary": {k: counts[k] for k in CLASSES}, "links": rows}
                content = json.dumps(report, ensure_ascii=True, indent=2) + "\n"
            else:
                content = markdown(rows, counts)
            save(args.out, content)

        print(f"{'Status':<14} Unique URLs")
        for key in CLASSES:
            print(f"{key:<14} {counts[key]:>11}")
        print(f"{'total':<14} {len(rows):>11}")

        return int(any(counts[key] for key in DEAD))
    except (OSError, RuntimeError) as exc:
        parser.exit(2, f"{parser.prog}: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
