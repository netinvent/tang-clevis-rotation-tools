#!/usr/bin/python3
"""
Clevis bind to tang server script
(C) 2026 Orsiris de Jong - NetInvent

Runs daily on every client. A Clevis binding that uses a Tang key the server no
longer advertises is bound again to the current key, pinned to a signing key the
volume already trusts; the old binding is removed only once the new one works.
Then every Tang pin is test-unlocked with its server: this proves it works, and
shows that server which key this client uses, which it checks before deleting
any key. A volume that goes missing is still tested, from its last known pins.
Results go to node_exporter's textfile collector, if there is one.
"""
import base64
import fcntl
import functools
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
from pathlib import Path

STATE = Path("/var/lib/clevis-rebind")
TRUSTED = Path("/etc/clevis-rebind/trusted")  # signing-key thumbprints to trust as well
REVOKED = Path("/etc/clevis-rebind/revoked")  # signing-key thumbprints never to trust
TEXTFILE_DIRS = [os.environ.get("TEXTFILE_DIR", ""), "/var/lib/node_exporter/textfile_collector",
                 "/var/lib/prometheus/node-exporter"]
HOST = socket.gethostname()


class Fail(Exception):
    """A problem that needs a human: the volume is reported as failing."""


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def run(*cmd, input=None, capture=True):
    out = subprocess.PIPE if capture else subprocess.DEVNULL
    return subprocess.run(cmd, input=input, stdout=out, check=True, timeout=120).stdout


def ok(*cmd, input=None):
    """True if cmd succeeds. Its output, possibly a secret, is discarded."""
    try:
        run(*cmd, input=input, capture=False)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def output(*cmd):
    """stdout of cmd, or b"" if it fails."""
    try:
        return run(*cmd)
    except subprocess.CalledProcessError:
        return b""


# --- helpers shared with tang-keyctl.py (a test keeps them identical) ---------

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


# --- Clevis bindings, as compact JWEs -----------------------------------------

def key_ids(keys, op):
    """Thumbprints of the keys usable for op: "verify" or "deriveKey"."""
    return {t for k in keys if op in k.get("key_ops", ()) for t in thumbprints(k)}


def luks_devices():
    """[(device, LUKS UUID)] of the LUKS devices lsblk lists."""
    found = {d["name"]: d["uuid"] for d in json.loads(run("lsblk", "-lJpo", "NAME,FSTYPE,UUID"))["blockdevices"]
             if d["fstype"] == "crypto_LUKS"}
    return sorted(found.items())


def luks2(dev):
    return json.loads(run("cryptsetup", "luksDump", "--dump-json-metadata", dev))


def header(jwe):
    return json.loads(b64d(jwe.split(".")[0]))


def tang_pins(jwe):
    """The Tang pins of a binding, at any sss depth."""
    c = header(jwe)["clevis"]
    if c["pin"] == "sss":
        return [p for child in c["sss"]["jwe"] for p in tang_pins(child)]
    return [jwe] if c["pin"] == "tang" else []


def url(pin):
    return header(pin)["clevis"]["tang"]["url"]


def bindings(meta):
    """{keyslot: JWE} of the Clevis bindings that use Tang (tokens left without keyslot are skipped)."""
    found = {}
    for token in meta["tokens"].values():
        if token["type"] == "clevis" and token["keyslots"]:
            jwe = ".".join(token["jwe"].get(k, "") for k in ("protected", "encrypted_key", "iv", "ciphertext", "tag"))
            if tang_pins(jwe):
                found[token["keyslots"][0]] = jwe
    return found


def config(jwe, thps):
    """The clevis config that rebuilds a binding, each Tang pin pinned to thps.get(url).

    None if a pin is neither tang nor sss: such bindings are rebound by hand.
    """
    c = header(jwe)["clevis"]
    if c["pin"] == "tang":
        return {"url": c["tang"]["url"], "thp": thps.get(c["tang"]["url"])}
    if c["pin"] != "sss":
        return None
    pins = {}
    for child in c["sss"]["jwe"]:
        cfg = config(child, thps)
        if cfg is None:
            return None
        pins.setdefault(header(child)["clevis"]["pin"], []).append(cfg)
    return {"t": c["sss"]["t"], "pins": pins}


@functools.lru_cache(maxsize=None)
def fetch_advertisement(tang):
    """Keys the Tang server advertises, or why they could not be fetched: asked once per run."""
    try:
        with urllib.request.urlopen(f"{tang}/adv", timeout=10) as r:
            return json.loads(b64d(json.load(r)["payload"]))["keys"]
    except Exception as e:  # unreachable, or not a Tang server's answer
        return f"cannot fetch {tang}/adv: {e}"


def advertised(tang):
    keys = fetch_advertisement(tang)
    if isinstance(keys, str):
        raise Fail(keys)
    return keys


def current(jwe):
    """True if every Tang pin of a binding uses an exchange key its server still advertises."""
    return all(header(p)["kid"] in key_ids(advertised(url(p)), "deriveKey") for p in tang_pins(jwe))


def anchor(pin, trusted, revoked):
    """Thumbprint of an advertised signing key this pin trusts (bound with it, or listed in TRUSTED)."""
    known = key_ids(header(pin)["clevis"]["tang"]["adv"]["keys"], "verify") | trusted
    for key in advertised(url(pin)):
        ids = set(thumbprints(key))
        if "verify" in key.get("key_ops", ()) and ids & known and not ids & revoked:
            return thumbprints(key)[0]
    raise Fail(f"no trusted signing key in the advertisement of {url(pin)}: add its thumbprint to {TRUSTED}")


def pin_failures(pins):
    """Test-unlock each Tang pin with its server (the decrypted share is discarded). This proves
    the pin works, and shows the server which of its keys this client uses."""
    failures = []
    for pin in pins:
        try:
            advertised(url(pin))  # do not wait for a server that is down
        except Fail as e:
            failures.append(str(e))
            continue
        if not ok("clevis", "decrypt", input=pin.encode()):
            failures.append(f"unlock test with {url(pin)} failed")
    return failures


def unbind(dev, slot):
    """Remove the Clevis binding in slot, once sure that its key opens exactly that keyslot,
    so that the emergency passphrase's keyslot can never be removed."""
    key = run("clevis", "luks", "pass", "-d", dev, "-s", slot)
    run("cryptsetup", "open", "--test-passphrase", "--key-slot", slot, "--key-file", "-", dev, input=key)
    run("clevis", "luks", "unbind", "-d", dev, "-s", slot, "-f")


def rebind(dev, slot, jwe, trusted, revoked):
    """Bind dev again like this binding, on current keys; remove the old one once the new one works."""
    if config(jwe, {}) is None:
        raise Fail(f"slot {slot} uses a retired Tang key and non-Tang pins: rebind it by hand")
    cfg = config(jwe, {url(p): anchor(p, trusted, revoked) for p in tang_pins(jwe)})
    before = luks2(dev)
    log(f"{dev}: rebinding slot {slot}")
    key = run("clevis", "luks", "pass", "-d", dev, "-s", slot)
    run("clevis", "luks", "bind", "-d", dev, "-k", "-", header(jwe)["clevis"]["pin"], json.dumps(cfg), input=key)
    after = bindings(luks2(dev))
    new = set(after) - set(bindings(before))
    if len(new) != 1 or new & set(before["keyslots"]):  # must be a keyslot this bind created
        raise Fail(f"cannot find the new binding; slot {slot} kept")
    new = new.pop()
    problems = pin_failures(tang_pins(after[new]))  # every server must work, not just one of them
    if not ok("clevis", "luks", "pass", "-d", dev, "-s", new):  # tests the new key on the volume
        problems.append("it does not unlock the volume")
    if problems:
        run("clevis", "luks", "unbind", "-d", dev, "-s", new, "-f")  # the keyslot this bind just created
        raise Fail(f"the new binding in slot {new} was removed: {'; '.join(problems)}")
    unbind(dev, slot)
    log(f"{dev}: slot {slot} replaced by slot {new}")


def update(dev, trusted, revoked):
    """Move every Tang binding of dev onto current keys, one change at a time."""
    problems = {}
    for _ in range(10):
        found = bindings(luks2(dev))
        current_slots = {slot for slot, jwe in found.items() if current(jwe)}
        stale = [slot for slot in found if slot not in current_slots and slot not in problems]
        if not stale:
            break
        slot, shape = stale[0], config(found[stale[0]], {})
        twin = next((s for s in current_slots if shape and config(found[s], {}) == shape), None)
        try:
            if twin:  # left by an interrupted rebind: the current twin replaces it
                if pin_failures(tang_pins(found[twin])) or not ok("clevis", "luks", "pass", "-d", dev, "-s", twin):
                    raise Fail(f"slot {twin} does not fully work, so slot {slot} is kept")
                unbind(dev, slot)
                log(f"{dev}: slot {slot} removed, slot {twin} replaces it")
            else:
                rebind(dev, slot, found[slot], trusted, revoked)
            fetch_advertisement.cache_clear()  # a Tang server may have rotated meanwhile
        except (Fail, subprocess.SubprocessError) as e:  # report it, and go on with the other bindings
            problems[slot] = str(e)
    else:
        problems["passes"] = "bindings still changing after 10 passes"
    if problems:
        raise Fail("; ".join(problems.values()))


def keyslot_ages(uuid, meta, labels):
    """When each keyslot got its key, tracked by its salt since LUKS2 records no date."""
    path = STATE / f"{uuid}.keyslots.json"
    try:
        known = json.loads(path.read_text())
    except (OSError, ValueError):
        known = None  # first run (or unreadable state): dates start now
    tokens = {s: t["type"] for t in meta["tokens"].values() for s in t["keyslots"]}
    seen, samples = {}, []
    for slot, keyslot in meta["keyslots"].items():
        fp = hashlib.sha256(keyslot.get("kdf", {}).get("salt", "").encode()).hexdigest()[:16]
        old = (known or {}).get(slot)
        seen[slot] = old if old and old["fp"] == fp else {"fp": fp, "since": int(time.time()),
                                                          "exact": known is not None}
        kind = {"clevis": "clevis", None: "passphrase"}.get(tokens.get(slot), "token")
        samples.append(("luks_keyslot_changed_timestamp_seconds",
                        {**labels, "slot": slot, "kind": kind, "exact": int(seen[slot]["exact"])}, seen[slot]["since"]))
    write_atomic(path, json.dumps(seen), 0o600)
    return samples


def remember(uuid, dev, pins):
    """Keep a volume's Tang pins, to go on testing them should the volume go missing.
    Returns the problem of a volume that had Tang bindings and has none left."""
    path = STATE / f"{uuid}.pins.json"
    if pins:
        write_atomic(path, json.dumps({"device": dev, "seen": int(time.time()), "pins": pins}), 0o600)
    elif path.exists():  # removed by hand, or by a bind and unbind gone wrong
        return [f"its Tang bindings are gone: bind it again, or delete {path} if that was meant"]
    return []


def remembered(path, present):
    """Test a volume not checked in this run from its last known pins, so that its Tang
    servers keep the keys it needs; report it if it is missing."""
    uuid = path.name[:-len(".pins.json")]
    labels = {"hostname": HOST, "uuid": uuid, "device": "unknown"}
    try:
        last = json.loads(path.read_text())
        labels["device"] = last["device"]
        failures = pin_failures(last["pins"])
    except (OSError, ValueError, KeyError) as e:
        return status(labels, [f"cannot read {path}: {e}"])
    if uuid in present:  # it failed, and was reported, above
        return []
    seen = time.strftime("%Y-%m-%d", time.localtime(last["seen"]))
    return status(labels, [f"not seen since {seen}: reattach it, or delete {path} if it is gone"] + failures)


def status(labels, problems):
    """clevis_volume_ok, and the reason when the volume is failing."""
    reason = "; ".join(dict.fromkeys(problems))  # without repeats
    if not reason:
        return [("clevis_volume_ok", labels, 1)]
    log(f"{labels['device']}: {reason}")
    return [("clevis_volume_ok", labels, 0), ("clevis_volume_problem_info", {**labels, "reason": reason}, 1)]


def volume(dev, uuid, trusted, revoked):
    """Check one LUKS device, rebinding if needed; return its metric samples."""
    labels = {"hostname": HOST, "uuid": uuid, "device": dev}
    if not ok("cryptsetup", "isLuks", dev):  # then it is tested from its last known pins
        raise Fail("cannot read the LUKS header")
    if not ok("cryptsetup", "isLuks", "--type", "luks2", dev):
        slots = re.findall(rb"^(\d+):", output("clevis", "luks", "list", "-d", dev), re.M)
        for slot in slots:  # still shows the Tang servers which keys it uses
            ok("clevis", "luks", "pass", "-d", dev, "-s", slot.decode())
        return status(labels, ["Clevis on LUKS1: convert the volume to LUKS2"]) if slots else []
    problems = []
    if bindings(luks2(dev)):
        try:
            update(dev, trusted, revoked)
        except Fail as e:
            problems.append(str(e))
        except Exception as e:  # a command failed or timed out
            traceback.print_exc()
            problems.append(f"error: {e}")
    meta = luks2(dev)  # the header as it is now
    found = bindings(meta)
    for slot, jwe in found.items():
        problems += [f"slot {slot}: {failure}" for failure in pin_failures(tang_pins(jwe))]
    if any(t["type"] == "clevis" and not t["keyslots"] for t in meta["tokens"].values()):
        problems.append("a Clevis token without keyslot is left over: remove it with cryptsetup token remove")
    problems += remember(uuid, dev, [p for jwe in found.values() for p in tang_pins(jwe)])
    samples = keyslot_ages(uuid, meta, labels)
    samples += [("clevis_binding_kid", {**labels, "url": url(p), "kid": header(p)["kid"]}, 1)
                for jwe in found.values() for p in tang_pins(jwe)]
    return samples + (status(labels, problems) if found or problems else [])


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    trusted, revoked = set(lines(TRUSTED)), set(lines(REVOKED))
    samples = [("clevis_rebind_run_timestamp_seconds", {"hostname": HOST}, time.time())]
    fetch_advertisement.cache_clear()
    with open(STATE / "lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # one run at a time
        devices, checked = luks_devices(), set()
        for dev, uuid in devices:
            try:
                samples += volume(dev, uuid, trusted, revoked)
                checked.add(uuid)
            except Exception as e:  # a command failed or timed out, or the header is unreadable
                if not isinstance(e, Fail):
                    traceback.print_exc()
                samples += status({"hostname": HOST, "uuid": uuid, "device": dev}, [f"error: {e}"])
        for path in sorted(STATE.glob("*.pins.json")):  # volumes missing, or that failed above
            if path.name[:-len(".pins.json")] not in checked:
                samples += remembered(path, present={uuid for _, uuid in devices})
    textfile = next((Path(d) for d in TEXTFILE_DIRS if d and os.path.isdir(d)), None)
    if textfile:
        write_atomic(textfile / "clevis_rebind.prom", prom_text(samples))
    else:
        log("no node_exporter textfile directory, so no metrics written (set TEXTFILE_DIR)")
    return 1 if any(name == "clevis_volume_ok" and not value for name, _, value in samples) else 0


if __name__ == "__main__":
    sys.exit(main())
