#!/usr/bin/python3
"""
Key rotation script for Tang server
(C) 2026 Orsiris de Jong - NetInvent


  tang-keyctl: rotate this Tang server's keys; delete retired keys once no client needs them.

  tang-keyctl rotate [--hide-sig]          new key pair; the old exchange key stops being advertised
  tang-keyctl cleanup [--now]              delete retired keys when every safety check passes
  tang-keyctl status                       refresh the metrics only
  tang-keyctl forget [--force] ADDRESS...  stop waiting for clients that are gone

Clients are known from the tangd journal: clevis-rebind test-unlocks every disk
daily, so this server sees which client address still uses which of its keys.
After a rotation the old signing key stays advertised until cleanup, so clients
can trust the new advertisement. --hide-sig hides it at once (keys leaked).
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
from pathlib import Path

VERSION = "2026102201"
DB = Path("/var/db/tang")
STATE = Path("/var/lib/tang-keyctl")
CONF = Path("/etc/tang-keyctl.conf")
C = {"TANG_URLS": "", "MIN_AGE_DAYS": 90, "QUIET_DAYS": 14,
     "TEXTFILE_DIR": "/var/lib/node_exporter/textfile_collector"}
RECENT_DAYS = 2  # clevis-rebind tests every disk daily, so a client silent for longer is not testing
UNLOCK = re.compile(r"(?P<client>\S+) POST \S*/rec/+(?P<kid>[\w-]+) => 200")  # tangd's request log


class Fail(Exception):
    """A command that cannot complete: reported as failed."""


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def run(*cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, check=True, timeout=120).stdout


# --- helpers shared with clevis-rebind.py (a test keeps them identical) -------

def lines(path):
    """Lines of path without comments and blanks; none if path is missing."""
    try:
        return [s for s in (line.split("#")[0].strip() for line in path.read_text().splitlines()) if s]
    except FileNotFoundError:
        return []


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def thumbprints(jwk):
    """RFC 7638 thumbprints: SHA-256 (what clevis and tang use) first, then SHA-1."""
    members = {"EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n")}[jwk["kty"]]
    data = json.dumps({m: jwk[m] for m in members}, sort_keys=True, separators=(",", ":")).encode()
    return [base64.urlsafe_b64encode(hashlib.new(h, data).digest()).rstrip(b"=").decode()
            for h in ("sha256", "sha1")]


def write_atomic(path, text, mode=0o644):
    """Replace path through a new private file, so no reader ever sees half of it,
    even after a power cut (the data is on disk before the rename)."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def prom_text(samples):
    """Prometheus text format for [(name, labels, value)]."""
    def esc(v):
        return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    out = []
    for name in sorted({s[0] for s in samples}):
        out.append(f"# TYPE {name} gauge")
        for n, labels, value in samples:
            if n == name:
                lbl = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
                out.append(f"{name}{{{lbl}}} {int(value)}" if lbl else f"{name} {int(value)}")
    return "\n".join(out) + "\n"


# --- settings, keys, rotations and clients ------------------------------------

def load_settings():
    """Read KEY=value lines from CONF into C."""
    for line in lines(CONF):
        key, _, value = (s.strip() for s in line.partition("="))
        if key not in C:
            sys.exit(f"{CONF}: unknown setting {key}")
        value = value.strip("\"'")
        if isinstance(C[key], int) and not value.isdigit():
            sys.exit(f"{CONF}: {key} must be a whole number of days")
        C[key] = int(value) if isinstance(C[key], int) else value
    if not C["TANG_URLS"]:
        sys.exit(f"{CONF}: TANG_URLS is required")
    if C["QUIET_DAYS"] < RECENT_DAYS:
        sys.exit(f"{CONF}: QUIET_DAYS must be at least {RECENT_DAYS}, one round of daily tests")


def keys():
    """{file name: JWK} of the key files; a leading dot means hidden (not advertised)."""
    return {n: json.loads((DB / n).read_text()) for n in sorted(os.listdir(DB)) if n.endswith(".jwk")}


def use(jwk):
    return "exc" if "deriveKey" in jwk.get("key_ops", ()) else "sig"


def visible(kind):
    """The advertised keys of a kind, "sig" or "exc"."""
    return [k for n, k in keys().items() if not n.startswith(".") and use(k) == kind]


def rotations():
    """[(file, rotation)] of the rotations whose retired keys are not deleted yet, oldest first."""
    return [(p, json.loads(p.read_text())) for p in sorted(STATE.glob("rotation-*.json"))]


def when(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def journal(cursor):
    """tangd's journal entries after cursor (all of them without one). They are selected by
    tangd's identifier: each connection is a unit of its own, too many to name."""
    cmd = ["journalctl", "-q", "-t", "tangd", "-o", "json"] + (["--after-cursor", cursor] if cursor else [])
    result = subprocess.run(cmd, stdout=subprocess.PIPE, timeout=120)
    if result.returncode:  # read nothing, so that nothing is missed: cleanup waits meanwhile
        raise Fail("cannot read the tangd journal")
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith(b"{")]


def client_state():
    path = STATE / "clients.json"
    return json.loads(path.read_text()) if path.exists() else {"cursor": None, "clients": {}, "first": {}}


def update_clients():
    """Add the tangd journal entries written since the last call to the client state, and return it:
    {"clients": {address: {key id: last unlock with it}}, "first": {address: first unlock}, "cursor": ...}."""
    state = client_state()
    for entry in journal(state["cursor"]):
        unlock = UNLOCK.match(str(entry.get("MESSAGE", "")))
        if unlock:
            client, at = unlock["client"], int(entry["__REALTIME_TIMESTAMP"]) // 10**6
            kids = state["clients"].setdefault(client, {})
            kids[unlock["kid"]] = max(kids.get(unlock["kid"], 0), at)
            state["first"][client] = min(state["first"].get(client, at), at)
        state["cursor"] = entry["__CURSOR"]
    write_atomic(STATE / "clients.json", json.dumps(state), 0o600)  # saved with its journal position
    return state


def forget(addresses, force):
    """Stop waiting for clients that are gone: decommissioned, stolen or renumbered."""
    state = update_clients()
    for address in addresses:
        if address not in state["clients"]:
            raise Fail(f"unknown client: {address}")
        last = max(state["clients"][address].values(), default=0)
        if not force and time.time() - last < RECENT_DAYS * 86400:
            raise Fail(f"{address} unlocked on {when(last)}, so it is not gone: add --force if it is")
    for address in addresses:
        del state["clients"][address], state["first"][address]
    write_atomic(STATE / "clients.json", json.dumps(state), 0o600)
    log(f"forgot {' '.join(addresses)}")


def advertisement_ok():
    """True if tangd advertises exactly the exchange keys that are visible on disk."""
    try:
        with urllib.request.urlopen(C["TANG_URLS"].split()[0] + "/adv", timeout=10) as r:
            served = json.loads(b64d(json.load(r)["payload"]))["keys"]
    except Exception:  # unreachable, or not a Tang server's answer
        return False
    return {thumbprints(k)[0] for k in served if use(k) == "exc"} == {thumbprints(k)[0] for k in visible("exc")}


def rotate(hide_sig):
    """Create a new key pair and retire the current keys."""
    old = {n: k for n, k in keys().items() if not n.startswith(".")}
    hide = [n for n, k in old.items() if use(k) == "exc" or hide_sig]
    pending = {n.lstrip(".") for _, r in rotations() for n in r["delete"]}  # deleted by their own rotation
    # Recorded first, so a crash cannot leave hidden keys that nothing will delete. An exchange
    # key is only ever deleted under its hidden name; a signing key under either name.
    rotation = {"ts": int(time.time()),
                "kids": [t for k in old.values() if use(k) == "exc" for t in thumbprints(k)],
                "delete": [f for n, k in old.items() if n not in pending
                           for f in ([f".{n}"] if use(k) == "exc" else [n, f".{n}"])]}
    write_atomic(STATE / f"rotation-{time.time_ns()}.json", json.dumps(rotation), 0o600)
    run("/usr/libexec/tangd-keygen", str(DB))
    for n in hide:
        os.rename(DB / n, DB / f".{n}")
    if not advertisement_ok():
        raise Fail(f"tangd does not advertise the new keys: check the files in {DB}")
    new = [thumbprints(k)[0] for n, k in keys().items() if n not in old and not n.startswith(".") and use(k) == "sig"]
    log(f"rotated; new signing key thumbprint: {' '.join(new)}")


def blocker(rotation):
    """Why the keys retired by rotation must stay, or "" when they can be deleted.
    An urgent rotation (cleanup --now) waits no minimum age, and a quiet period of RECENT_DAYS."""
    min_age, quiet = (0, RECENT_DAYS) if rotation.get("urgent") else (C["MIN_AGE_DAYS"], C["QUIET_DAYS"])
    if time.time() - rotation["ts"] < min_age * 86400:
        return f"retired less than {min_age} days ago"
    retired, active = set(rotation["kids"]), {t for k in visible("exc") for t in thumbprints(k)}
    if retired & active:
        return "a retired exchange key is advertised again"
    known, now = update_clients()["clients"], time.time()
    if not known:
        return "no client has unlocked with this server yet"
    if "<unknown>" in known:
        return "tangd does not log client addresses"

    def used(kids, wanted, days):
        return any(k in wanted and now - t < days * 86400 for k, t in kids.items())

    problems = {f"used a retired key in the last {quiet} days":
                [a for a, kids in known.items() if used(kids, retired, quiet)],
                f"no unlock with the current key for {RECENT_DAYS} days":
                [a for a, kids in known.items() if not used(kids, active, RECENT_DAYS)]}
    return "; ".join(f"{what}: {', '.join(sorted(addrs))}" for what, addrs in problems.items() if addrs)


def why_kept(rotation):
    try:
        return blocker(rotation)
    except Exception as e:  # the journal cannot be read
        return f"cannot check: {e}"


def cleanup(now):
    """Delete the keys of every rotation whose safety checks all pass. With now, the pending
    rotations become urgent, and stay so until the daily cleanup has deleted their keys."""
    for path, rotation in rotations():
        if now and not rotation.get("urgent"):
            rotation["urgent"] = True
            write_atomic(path, json.dumps(rotation), 0o600)
        reason = why_kept(rotation)
        if reason:
            log(f"keys retired {when(rotation['ts'])} kept: {reason}")
            continue
        for name in rotation["delete"]:
            (DB / name).unlink(missing_ok=True)
        path.rename(path.with_name(path.name + ".done"))
        log(f"keys retired {when(rotation['ts'])} deleted")


def metrics():
    """Samples describing the keys, the pending rotations, the clients and the last commands."""
    urls, pending = C["TANG_URLS"].split(), rotations()
    retiring = {n.lstrip(".") for _, r in pending for n in r["delete"]}
    active = {t for k in visible("exc") for t in thumbprints(k)}
    samples = []
    for name, jwk in keys().items():
        state = "retired" if name.startswith(".") or name in retiring else "active"
        created = (DB / name).stat().st_mtime
        for hash_name, kid in zip(("sha256", "sha1"), thumbprints(jwk)):
            samples += [("tang_key_created_timestamp_seconds",
                         {"url": u, "kid": kid, "hash": hash_name, "use": use(jwk), "state": state}, created)
                        for u in urls]
    for path, r in pending:
        labels = {"rotation": path.stem[len("rotation-"):], "rotated": when(r["ts"]),
                  "urgent": int(bool(r.get("urgent")))}
        samples.append(("tang_rotation_pending_timestamp_seconds", labels, r["ts"]))
        reason = why_kept(r)
        if reason:
            samples.append(("tang_rotation_blocked_info", {**labels, "blocked_by": reason}, 1))
    known = update_clients()
    for client, kids in known["clients"].items():
        for key, is_current in (("current", True), ("retired", False)):
            last = max((t for k, t in kids.items() if (k in active) == is_current), default=0)
            samples.append(("tang_client_last_unlock_timestamp_seconds", {"client": client, "key": key}, last))
        samples.append(("tang_client_first_unlock_timestamp_seconds", {"client": client}, known["first"][client]))
    samples.append(("tang_advertisement_ok", {"url": urls[0]}, advertisement_ok()))
    for path in STATE.glob("last-*.json"):
        result, command = json.loads(path.read_text()), path.stem[len("last-"):]
        samples += [("tang_keyctl_success", {"command": command}, result["ok"]),
                    ("tang_keyctl_timestamp_seconds", {"command": command}, result["ts"])]
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("rotate").add_argument("--hide-sig", action="store_true",
                                               help="also hide the old signing key (keys leaked)")
    commands.add_parser("cleanup").add_argument("--now", action="store_true",
                                                help=f"make the pending rotations urgent: no MIN_AGE_DAYS wait, "
                                                     f"QUIET_DAYS shortened to {RECENT_DAYS}, same client checks")
    commands.add_parser("status")
    commands.add_parser("version").add_argument("--version", action="store_true",
                                                help="Shows version and exits")
    forget_parser = commands.add_parser("forget")
    forget_parser.add_argument("--force", action="store_true", help="even if it unlocked recently (stolen)")
    forget_parser.add_argument("addresses", nargs="+", metavar="ADDRESS")
    args = parser.parse_args()
    if args.command == "version":
        print("tang-keyctl.py version "+ VERSION)
        sys.exit(0)
    load_settings()
    STATE.mkdir(parents=True, exist_ok=True)
    with open(STATE / "lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # one command at a time
        ok = True
        try:
            if args.command == "rotate":
                rotate(args.hide_sig)
            elif args.command == "cleanup":
                cleanup(args.now)
            elif args.command == "forget":
                forget(args.addresses, args.force)
        except Exception as e:  # recorded below, so that an alert fires
            if not isinstance(e, Fail):
                traceback.print_exc()
            log(f"{args.command} failed: {e}")
            ok = False
        if args.command != "forget":
            write_atomic(STATE / f"last-{args.command}.json", json.dumps({"ok": ok, "ts": int(time.time())}), 0o600)
        textfile = Path(C["TEXTFILE_DIR"])
        textfile.mkdir(parents=True, exist_ok=True)
        write_atomic(textfile / "tang_keyctl.prom", prom_text(metrics()))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
