"""Offline tests for clevis-rebind.py and tang-keyctl.py.

Disks, Tang servers, system commands and the tangd journal are faked. The fake
clevis behaves like the real one where it matters: pinned thumbprints are
checked, sss needs t of its pins, and `clevis luks pass` checks the key
against the volume.
Run: python3 tests/test_nbde.py <directory holding the two scripts>
"""
import base64
import functools
import http.client
import importlib.util
import inspect
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

try:
    import fcntl  # noqa: F401
except ImportError:  # Windows: locking is not under test
    sys.modules["fcntl"] = types.SimpleNamespace(flock=lambda *a: None, LOCK_EX=0)
sys.dont_write_bytecode = True  # no __pycache__ beside the scripts under test

SRC = Path(sys.argv.pop(1) if len(sys.argv) > 1 else ".")


def load(file):
    spec = importlib.util.spec_from_file_location(file.replace("-", "_")[:-3], SRC / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cr, tk = load("clevis-rebind.py"), load("tang-keyctl.py")
T1, T2 = "http://t1:7500", "http://t2:7500"
SSS = {"t": 1, "pins": {"tang": [{"url": T1}, {"url": T2}]}}
DAY = 86400


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def ec(ops):
    return {"kty": "EC", "crv": "P-521", "x": secrets.token_urlsafe(66), "y": secrets.token_urlsafe(66),
            "key_ops": ops}


def kid(key):
    return cr.thumbprints(key)[0]


def compact(token):
    return ".".join(token["jwe"].get(k, "") for k in ("protected", "encrypted_key", "iv", "ciphertext", "tag"))


def metric(text, name):
    """[(labels, value)] of one metric in Prometheus text format."""
    found = []
    for line in text.splitlines():
        if line.startswith(name + "{"):
            labels, value = line[len(name) + 1:].rsplit("} ", 1)
            found.append((dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', labels)), int(value)))
    return found


class Tang:
    """A Tang server: advertised keys, hidden keys that still unlock, and the unlocks it served."""

    def __init__(self, url):
        self.url, self.sig, self.exc, self.hidden = url, [ec(["verify"])], [ec(["deriveKey"])], []
        self.unlocks, self.down, self.refuse, self.fetches = [], False, False, 0

    def rotate(self, hide_sig=False):
        self.hidden += self.exc
        self.exc = [ec(["deriveKey"])]
        self.sig = ([] if hide_sig else self.sig) + [ec(["verify"])]

    def advertisement(self):
        """What fetch_advertisement returns: the advertised keys, or why they could not be fetched."""
        self.fetches += 1
        return f"cannot fetch {self.url}/adv: connection refused" if self.down else self.sig + self.exc

    def unlock(self, key_id):
        if self.down or self.refuse or key_id not in {kid(k) for k in self.exc + self.hidden}:
            return False
        self.unlocks.append(key_id)
        return True


class Host:
    """A client: its LUKS devices, and the lsblk, cryptsetup and clevis commands acting on them."""

    def __init__(self, tangs):
        self.tangs, self.disks, self.calls, self.break_next, self.bind_into = {t.url: t for t in tangs}, {}, [], False, None

    def disk(self, dev, uuid="uuid-1", luks=2):
        self.disks[dev] = {"uuid": uuid, "luks": luks, "tokens": {},
                           "keyslots": {"0": {"kdf": {"salt": "pw"}, "key": "the passphrase"}}}

    def jwe(self, pin, cfg):
        """Compact JWE that clevis would write for this pin and config."""
        if pin == "tang":
            tang = self.tangs[cfg["url"]]
            if cfg.get("thp"):  # clevis refuses an advertisement the pinned key did not sign
                assert cfg["thp"] in {t for k in tang.sig for t in cr.thumbprints(k)}, "untrusted advertisement"
            hdr = {"alg": "ECDH-ES", "kid": kid(tang.exc[0]),
                   "clevis": {"pin": "tang", "tang": {"url": tang.url, "adv": {"keys": tang.sig + tang.exc}}}}
        elif pin == "sss":
            hdr = {"alg": "dir", "clevis": {"pin": "sss", "sss": {
                "t": cfg["t"], "jwe": [self.jwe(p, c) for p, cs in cfg["pins"].items() for c in cs]}}}
        else:
            hdr = {"clevis": {"pin": pin, pin: cfg}}
        return b64(hdr) + "..aXY.Y3Q.dGFn"

    def bind(self, dev, pin, cfg):
        """A new keyslot and its Clevis token; with break_next, the keyslot does not take the token's key."""
        disk, key = self.disks[dev], secrets.token_hex(8)
        slot = self.bind_into or str(max(map(int, disk["keyslots"])) + 1)
        protected, _, iv, ciphertext, tag = self.jwe(pin, cfg).split(".")
        if slot not in disk["keyslots"]:
            disk["keyslots"][slot] = {"kdf": {"salt": secrets.token_hex(8)}, "key": "broken" if self.break_next else key}
        disk["tokens"]["odd" if self.bind_into else slot] = {
            "type": "clevis", "keyslots": [slot], "secret": key,
            "jwe": {"protected": protected, "iv": iv, "ciphertext": ciphertext, "tag": tag}}
        return slot

    def unlock(self, jwe):
        """What clevis decrypt does: an sss pin needs t of its pins, a tang pin its server."""
        c = cr.header(jwe)["clevis"]
        if c["pin"] == "sss":
            return sum(self.unlock(child) for child in c["sss"]["jwe"]) >= c["sss"]["t"]
        return c["pin"] != "tang" or self.tangs[c["tang"]["url"]].unlock(cr.header(jwe)["kid"])

    def run(self, *cmd, input=None, capture=True):
        self.calls.append(cmd)
        fail = subprocess.CalledProcessError(1, cmd)
        if cmd[0] == "lsblk":
            devices = [{"name": "/dev/sda1", "fstype": "xfs", "uuid": "boot"}]
            devices += [{"name": dev, "fstype": "crypto_LUKS", "uuid": d["uuid"]} for dev, d in self.disks.items()]
            return json.dumps({"blockdevices": devices}).encode()
        if cmd[:2] == ("clevis", "decrypt"):
            if not self.unlock(input.decode()):
                raise fail
            return b"share"
        dev = cmd[cmd.index("-d") + 1] if "-d" in cmd else cmd[-1]
        disk, slot = self.disks[dev], cmd[cmd.index("-s") + 1] if "-s" in cmd else None
        keys = {k["key"] for k in disk["keyslots"].values()}
        if cmd[:2] == ("cryptsetup", "isLuks"):  # reads the header, like luksDump
            if disk.get("unreadable") or ("--type" in cmd and disk["luks"] != 2):
                raise fail
            return b""
        if cmd[:2] == ("cryptsetup", "luksDump"):
            if disk.get("unreadable"):
                raise fail
            return json.dumps({"keyslots": disk["keyslots"], "tokens": disk["tokens"]}).encode()
        if cmd[:2] == ("cryptsetup", "open"):  # --test-passphrase --key-slot N --key-file - DEV
            if disk["keyslots"].get(cmd[cmd.index("--key-slot") + 1], {}).get("key") != input.decode():
                raise fail
            return b""
        if cmd[:3] == ("clevis", "luks", "list"):
            if disk.get("unreadable"):
                raise fail
            return "".join(f"{t['keyslots'][0]}: tang '{{}}'\n" for t in disk["tokens"].values()).encode()
        if cmd[:3] == ("clevis", "luks", "pass"):  # decrypts the token, then tests its key on the volume
            token = next(t for t in disk["tokens"].values() if t["keyslots"] == [slot])
            if not self.unlock(compact(token)) or token["secret"] not in keys:
                raise fail
            return token["secret"].encode()
        if cmd[:3] == ("clevis", "luks", "bind"):
            assert input.decode() in keys, "bind needs a key of the volume"
            self.bind(dev, cmd[-2], json.loads(cmd[-1]))
            return b""
        if cmd[:3] == ("clevis", "luks", "unbind"):
            del disk["keyslots"][slot]
            disk["tokens"] = {i: t for i, t in disk["tokens"].items() if t["keyslots"] != [slot]}
            return b""
        raise AssertionError(cmd)


class ClevisRebindTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "textfile").mkdir()
        self.t1, self.t2 = Tang(T1), Tang(T2)
        self.host = Host([self.t1, self.t2])
        self.host.disk("/dev/sda3")
        self.host.bind("/dev/sda3", "sss", SSS)
        fetch = functools.lru_cache(maxsize=None)(lambda url: self.host.tangs[url].advertisement())
        for name, value in {"run": self.host.run, "fetch_advertisement": fetch, "STATE": self.dir / "state",
                            "TRUSTED": self.dir / "trusted", "REVOKED": self.dir / "revoked",
                            "TEXTFILE_DIRS": [str(self.dir / "textfile")], "HOST": "web01"}.items():
            patcher = mock.patch.object(cr, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def client(self):
        code = cr.main()
        return code, (self.dir / "textfile" / "clevis_rebind.prom").read_text()

    def slots(self, dev="/dev/sda3"):
        return sorted(self.host.disks[dev]["keyslots"])

    def binds(self):
        return [json.loads(c[-1]) for c in self.host.calls if c[:3] == ("clevis", "luks", "bind")]

    def reasons(self, text):
        return {m["device"]: m["reason"] for m, _ in metric(text, "clevis_volume_problem_info")}

    def test_rfc7638_example(self):
        jwk = {"kty": "RSA", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29",
               "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZ"
                    "CiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJ"
                    "ZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBn"
                    "iIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
        self.assertEqual(cr.thumbprints(jwk)[0], "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")

    def test_shared_helpers_are_identical(self):
        for name in ("lines", "b64d", "thumbprints", "write_atomic", "prom_text"):
            self.assertEqual(inspect.getsource(getattr(cr, name)), inspect.getsource(getattr(tk, name)), name)

    def test_files_are_on_disk_before_they_replace_the_old_ones(self):
        with mock.patch("os.fsync") as fsync:
            cr.write_atomic(self.dir / "file", "text")
        self.assertTrue(fsync.called)
        self.assertEqual((self.dir / "file").read_text(), "text")

    def test_nothing_to_do_but_the_daily_unlock_test(self):
        code, text = self.client()
        self.assertEqual(code, 0)
        self.assertEqual(metric(text, "clevis_volume_ok"),
                         [({"hostname": "web01", "uuid": "uuid-1", "device": "/dev/sda3"}, 1)])
        self.assertEqual(self.reasons(text), {})
        self.assertEqual(self.binds(), [])
        # each server unlocked once, so it knows this client uses its current key
        self.assertEqual((self.t1.unlocks, self.t2.unlocks), ([kid(self.t1.exc[0])], [kid(self.t2.exc[0])]))

    def test_rotation_rebinds_pinned_to_the_old_signing_key(self):
        old_sig = kid(self.t1.sig[0])
        self.t1.rotate()
        code, _ = self.client()
        self.assertEqual(code, 0)
        (cfg,) = self.binds()
        self.assertEqual(cfg["pins"]["tang"][0], {"url": T1, "thp": old_sig})
        self.assertEqual(self.slots(), ["0", "2"])  # the old binding (slot 1) is gone, the passphrase stays
        self.assertEqual(self.t1.unlocks[-1], kid(self.t1.exc[0]))  # the daily test used the new key

    def test_rotation_during_the_run_rebinds_once(self):
        self.t1.rotate()
        bind = self.host.bind

        def rotate_t2_first(dev, pin, cfg):  # t2 rotates after the client read its advertisement
            if not self.t2.hidden:
                self.t2.rotate()
            return bind(dev, pin, cfg)

        self.host.bind = rotate_t2_first
        code, _ = self.client()
        self.assertEqual((code, len(self.binds()), self.slots()), (0, 1, ["0", "2"]))

    def test_new_binding_must_work_with_every_server(self):
        self.t1.rotate()
        self.t2.refuse = True  # the new binding would still unlock through t1 alone
        code, text = self.client()
        self.assertEqual((code, self.slots()), (1, ["0", "1"]))
        self.assertIn("the new binding in slot 2 was removed: unlock test with http://t2:7500 failed", text)

    def test_new_binding_that_does_not_unlock_is_removed(self):
        self.t1.rotate()
        self.host.break_next = True
        code, text = self.client()
        self.assertEqual((code, self.slots()), (1, ["0", "1"]))
        self.assertIn("it does not unlock the volume", text)

    def test_interrupted_rebind_is_finished(self):
        self.t1.rotate()
        self.host.bind("/dev/sda3", "sss", SSS)  # the new binding exists, the old one was not removed yet
        code, _ = self.client()
        self.assertEqual((code, self.slots(), self.binds()), (0, ["0", "2"], []))

    def test_twin_that_does_not_unlock_replaces_nothing(self):
        self.t1.rotate()
        self.host.break_next = True
        self.host.bind("/dev/sda3", "sss", SSS)
        code, text = self.client()
        self.assertEqual((code, self.slots()), (1, ["0", "1", "2"]))
        self.assertIn("slot 2 does not fully work, so slot 1 is kept", text)

    def test_twin_that_fails_with_one_server_replaces_nothing(self):
        self.t1.rotate()
        self.host.bind("/dev/sda3", "sss", SSS)
        self.t2.refuse = True  # the twin still unlocks through t1 alone
        code, text = self.client()
        self.assertEqual((code, self.slots()), (1, ["0", "1", "2"]))
        self.assertIn("slot 2 does not fully work, so slot 1 is kept", text)

    def test_the_passphrase_keyslot_is_never_removed(self):
        self.t1.rotate()
        twin = self.host.bind("/dev/sda3", "sss", SSS)
        disk = self.host.disks["/dev/sda3"]
        # a damaged header: a stale Clevis token assigned to the passphrase's keyslot
        disk["tokens"]["7"] = dict(disk["tokens"]["1"], keyslots=["0"], secret=disk["tokens"][twin]["secret"])
        code, _ = self.client()
        self.assertEqual(code, 1)
        self.assertIn("0", self.slots())

    def test_a_new_binding_on_an_existing_keyslot_is_never_removed(self):
        self.t1.rotate()
        self.host.bind_into = "0"  # a bind that would attach its token to the passphrase's keyslot
        code, text = self.client()
        self.assertEqual(code, 1)
        self.assertIn("cannot find the new binding", text)
        self.assertIn("0", self.slots())

    def test_a_failing_command_does_not_stop_the_other_bindings(self):
        self.host.disk("/dev/sdb3", uuid="uuid-2")
        self.host.break_next = True  # slot 1 no longer takes its key: clevis luks pass fails on it
        self.host.bind("/dev/sdb3", "tang", {"url": T1})
        self.host.break_next = False
        self.host.bind("/dev/sdb3", "tang", {"url": T1})
        self.t1.rotate()
        code, _ = self.client()
        self.assertEqual((code, self.slots("/dev/sdb3")), (1, ["0", "1", "3"]))  # slot 2 moved to slot 3

    def test_one_binding_per_server_are_both_kept(self):
        self.host.disk("/dev/sdb3", uuid="uuid-2")
        self.host.bind("/dev/sdb3", "tang", {"url": T1})
        self.host.bind("/dev/sdb3", "tang", {"url": T2})
        self.t1.rotate()
        code, _ = self.client()
        self.assertEqual(code, 0)
        self.assertEqual(self.slots("/dev/sdb3"), ["0", "2", "3"])  # t2's binding kept, t1's replaced

    def test_untrusted_advertisement_needs_a_trusted_thumbprint(self):
        self.t1.rotate(hide_sig=True)  # chain of trust broken on purpose
        code, text = self.client()
        self.assertEqual((code, self.slots()), (1, ["0", "1"]))
        self.assertIn("no trusted signing key", self.reasons(text)["/dev/sda3"])
        (self.dir / "trusted").write_text(cr.thumbprints(self.t1.sig[0])[1] + "  # tang1, SHA-1 form\n")
        code, _ = self.client()
        self.assertEqual((code, self.slots()), (0, ["0", "2"]))

    def test_revoked_signing_key_is_never_trusted(self):
        self.t1.rotate()  # the old signing key is still advertised
        (self.dir / "revoked").write_text(kid(self.t1.sig[0]) + "\n")
        code, _ = self.client()
        self.assertEqual((code, self.slots()), (1, ["0", "1"]))

    def test_unreachable_server_changes_nothing(self):
        self.t1.rotate()
        self.t2.down = True
        code, text = self.client()
        self.assertEqual((code, self.slots()), (1, ["0", "1"]))
        self.assertIn("cannot fetch http://t2:7500/adv", self.reasons(text)["/dev/sda3"])
        self.assertEqual(self.t2.fetches, 1)  # asked once, not once per pin

    def test_advertisement_fetching(self):
        fetch = load("clevis-rebind.py").fetch_advertisement  # the real one: setUp replaced it
        adv = {"payload": b64({"keys": self.t1.sig + self.t1.exc})}
        with mock.patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(adv).encode())):
            self.assertEqual(fetch(T1), self.t1.sig + self.t1.exc)
        with mock.patch("urllib.request.urlopen", side_effect=OSError("refused")) as urlopen:
            self.assertEqual(fetch(T2), "cannot fetch http://t2:7500/adv: refused")
            fetch(T2)
            self.assertEqual(urlopen.call_count, 1)  # a failure is remembered for the run too
        for answer in (http.client.IncompleteRead(b""), io.BytesIO(b"[]")):  # cut short, or not from Tang
            fetch.cache_clear()
            with mock.patch("urllib.request.urlopen", side_effect=[answer]):
                self.assertTrue(fetch(T2).startswith("cannot fetch http://t2:7500/adv: "))

    def test_failed_unlock_test_is_reported(self):
        self.t2.refuse = True
        code, text = self.client()
        self.assertEqual(code, 1)
        self.assertEqual(self.reasons(text)["/dev/sda3"], "slot 1: unlock test with http://t2:7500 failed")

    def test_binding_with_tpm2_is_left_to_a_human_but_still_tested(self):
        del self.host.disks["/dev/sda3"]
        self.host.disk("/dev/sdb3", uuid="uuid-2")
        self.host.bind("/dev/sdb3", "sss", {"t": 2, "pins": {"tang": [{"url": T1}], "tpm2": [{"pcr_ids": "7"}]}})
        self.host.bind("/dev/sdb3", "sss", {"t": 2, "pins": {"tang": [{"url": T2}], "tpm2": [{"pcr_ids": "7"}]}})
        old_t1 = kid(self.t1.exc[0])
        self.assertEqual(self.client()[0], 0)
        self.t1.rotate()
        self.t1.unlocks.clear()
        code, text = self.client()
        self.assertEqual((code, self.slots("/dev/sdb3")), (1, ["0", "1", "2"]))  # never taken for a twin
        self.assertIn("non-Tang pins", self.reasons(text)["/dev/sdb3"])
        self.assertIn(old_t1, self.t1.unlocks)  # so t1 sees that this disk still needs the old key

    def test_one_bad_binding_does_not_stop_the_others(self):
        self.host.disk("/dev/sdb3", uuid="uuid-2")
        self.host.bind("/dev/sdb3", "sss", {"t": 2, "pins": {"tang": [{"url": T1}], "tpm2": [{"pcr_ids": "7"}]}})
        self.host.bind("/dev/sdb3", "tang", {"url": T1})
        self.t1.rotate()
        code, text = self.client()
        self.assertEqual((code, self.slots("/dev/sdb3")), (1, ["0", "1", "3"]))  # slot 2 moved to slot 3
        self.assertIn("non-Tang pins", self.reasons(text)["/dev/sdb3"])

    def test_token_without_keyslot_does_not_hide_the_volume(self):
        disk = self.host.disks["/dev/sda3"]
        disk["tokens"]["9"] = dict(disk["tokens"]["1"], keyslots=[])  # left by an interrupted unbind
        code, text = self.client()
        self.assertEqual(code, 1)
        self.assertIn("a Clevis token without keyslot", self.reasons(text)["/dev/sda3"])
        self.assertEqual(self.t1.unlocks, [kid(self.t1.exc[0])])  # its binding was still tested

    def test_missing_volume_is_still_tested_until_forgotten(self):
        old = kid(self.t1.exc[0])
        self.client()
        del self.host.disks["/dev/sda3"]  # detached
        self.t1.rotate()
        self.t1.unlocks.clear()
        code, text = self.client()
        self.assertEqual(code, 1)
        self.assertTrue(self.reasons(text)["/dev/sda3"].startswith("not seen since"))
        self.assertEqual(self.t1.unlocks, [old])  # so t1 keeps the key this disk needs
        (self.dir / "state" / "uuid-1.pins.json").unlink()  # it is gone for good
        code, text = self.client()
        self.assertEqual((code, metric(text, "clevis_volume_ok")), (0, []))

    def test_volume_whose_bindings_are_gone_is_reported(self):
        self.client()
        self.host.run("clevis", "luks", "unbind", "-d", "/dev/sda3", "-s", "1", "-f")  # by mistake
        code, text = self.client()
        self.assertEqual(code, 1)
        self.assertIn("its Tang bindings are gone", self.reasons(text)["/dev/sda3"])
        (self.dir / "state" / "uuid-1.pins.json").unlink()  # it was meant
        code, text = self.client()
        self.assertEqual((code, metric(text, "clevis_volume_ok")), (0, []))

    def test_damaged_pins_file_does_not_stop_the_others(self):
        self.host.disk("/dev/sdb3", uuid="uuid-2")
        self.host.bind("/dev/sdb3", "sss", SSS)
        self.client()
        self.host.disks.clear()  # both disks detached
        (self.dir / "state" / "uuid-1.pins.json").write_text("")  # damaged by a power cut
        self.t1.unlocks.clear()
        code, text = self.client()
        reasons = self.reasons(text)
        self.assertEqual(code, 1)
        self.assertIn("cannot read", reasons["unknown"])
        self.assertTrue(reasons["/dev/sdb3"].startswith("not seen since"))
        self.assertEqual(len(self.t1.unlocks), 1)  # sdb3 was still tested

    def test_unreadable_volume_is_still_tested(self):
        self.client()
        self.host.disks["/dev/sda3"]["unreadable"] = True
        self.t1.unlocks.clear()
        code, text = self.client()
        self.assertEqual(code, 1)
        self.assertEqual(self.reasons(text), {"/dev/sda3": "error: cannot read the LUKS header"})
        self.assertEqual(self.t1.unlocks, [kid(self.t1.exc[0])])

    def test_runs_without_node_exporter(self):
        self.t1.rotate()
        with mock.patch.object(cr, "TEXTFILE_DIRS", [str(self.dir / "missing")]):
            self.assertEqual(cr.main(), 0)
        self.assertEqual(self.slots(), ["0", "2"])
        self.assertIn(kid(self.t1.exc[0]), self.t1.unlocks)

    def test_copies_and_luks1(self):
        self.host.disk("/dev/sdb3", uuid="uuid-1")  # a copy of sda3, handled on its own
        self.host.bind("/dev/sdb3", "sss", SSS)
        self.host.disk("/dev/sdc1", uuid="uuid-3", luks=1)
        self.host.bind("/dev/sdc1", "tang", {"url": T1})
        self.host.disk("/dev/sdd1", uuid="uuid-4", luks=1)  # LUKS1 without Clevis: ignored
        self.t1.rotate()
        code, text = self.client()
        self.assertEqual(code, 1)
        self.assertEqual(self.reasons(text), {"/dev/sdc1": "Clevis on LUKS1: convert the volume to LUKS2"})
        self.assertEqual({m["device"]: v for m, v in metric(text, "clevis_volume_ok")},
                         {"/dev/sda3": 1, "/dev/sdb3": 1, "/dev/sdc1": 0})
        self.assertIn(("clevis", "luks", "pass", "-d", "/dev/sdc1", "-s", "1"), self.host.calls)  # t1 sees it

    def test_keyslot_ages(self):
        disk = self.host.disks["/dev/sda3"]
        disk["tokens"]["5"] = {"type": "systemd-tpm2", "keyslots": ["5"]}
        disk["keyslots"]["5"] = {"kdf": {"salt": "tpm"}, "key": "tpm"}
        _, text = self.client()
        first = {m["slot"]: (m["kind"], m["exact"], v) for m, v in metric(text, "luks_keyslot_changed_timestamp_seconds")}
        self.assertEqual({s: f[:2] for s, f in first.items()},
                         {"0": ("passphrase", "0"), "1": ("clevis", "0"), "5": ("token", "0")})
        disk["keyslots"]["0"] = {"kdf": {"salt": "new passphrase"}, "key": "a new passphrase"}
        with mock.patch.object(cr.time, "time", return_value=time.time() + DAY):
            _, text = self.client()
        later = {m["slot"]: (m["exact"], v) for m, v in metric(text, "luks_keyslot_changed_timestamp_seconds")}
        self.assertEqual(later["0"][0], "1")
        self.assertGreater(later["0"][1], first["0"][2])
        self.assertEqual(later["1"], ("0", first["1"][2]))

    def test_label_values_are_escaped(self):
        text = cr.prom_text([("m", {"reason": 'a "b" \\ c\nd'}, True)])
        self.assertEqual(text, '# TYPE m gauge\nm{reason="a \\"b\\" \\\\ c d"} 1\n')


class TangKeyctlTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.db, self.textfile = self.dir / "db", self.dir / "textfile"
        self.db.mkdir()
        self.keygen()
        (self.dir / "tang-keyctl.conf").write_text(
            f"TANG_URLS={T1} http://10.0.0.5:7500  # comment\nTEXTFILE_DIR={self.textfile}\n")
        self.entries, self.journal_broken, self.defaults = [], False, dict(tk.C)
        self.tang_down, self.served = None, None  # what urlopen raises; the keys tangd serves, if not those on disk
        patches = {"DB": self.db, "STATE": self.dir / "state", "CONF": self.dir / "tang-keyctl.conf",
                   "run": self.fake_run, "journal": self.fake_journal, "C": dict(self.defaults)}
        for name, value in patches.items():
            patcher = mock.patch.object(tk, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("urllib.request.urlopen", self.urlopen)
        patcher.start()
        self.addCleanup(patcher.stop)
        tk.load_settings()
        tk.STATE.mkdir()

    def keygen(self):
        for ops in (["sign", "verify"], ["deriveKey"]):
            key = dict(ec(ops), d="private")
            (self.db / f"{kid(key)}.jwk").write_text(json.dumps(key))

    def fake_run(self, *cmd):
        assert cmd[0] == "/usr/libexec/tangd-keygen", cmd
        self.keygen()
        return b""

    def fake_journal(self, cursor):
        if self.journal_broken:
            raise tk.Fail("cannot read the tangd journal")
        return self.entries[int(cursor) + 1:] if cursor else self.entries

    def urlopen(self, url, timeout):
        assert url.endswith("/adv"), url
        if self.tang_down:
            raise self.tang_down
        served = self.served or tk.visible("sig") + tk.visible("exc")
        keys = [{k: v for k, v in key.items() if k != "d"} for key in served]
        return io.BytesIO(json.dumps({"payload": b64({"keys": keys})}).encode())

    def unlock(self, client, key_id, days_ago=0, code=200, path="/rec/"):
        """A line of tangd's journal: client unlocked with key_id."""
        self.entries.append({"MESSAGE": f"{client} POST {path}{key_id} => {code} (src/tangd.c:180)",
                             "__REALTIME_TIMESTAMP": str(int((time.time() - days_ago * DAY) * 10**6)),
                             "__CURSOR": str(len(self.entries))})

    def exc(self):
        return kid(tk.visible("exc")[0])

    def files(self):
        return sorted(os.listdir(self.db))

    def age_rotations(self, days=100):
        for path, rotation in tk.rotations():
            rotation["ts"] -= days * DAY
            path.write_text(json.dumps(rotation))

    def why(self):
        return tk.why_kept(tk.rotations()[0][1])

    def later(self, days):
        """Patch the clock forward."""
        return mock.patch.object(tk.time, "time", return_value=time.time() + days * DAY)

    def test_rotate_hides_the_exchange_key_only(self):
        before = {n: tk.use(k) for n, k in tk.keys().items()}
        tk.rotate(hide_sig=False)
        exc, sig = sorted(before, key=before.get)  # "exc" sorts before "sig"
        self.assertIn(sig, self.files())
        self.assertIn(f".{exc}", self.files())
        self.assertEqual(len(tk.visible("exc")), 1)
        (_, rotation), = tk.rotations()
        self.assertEqual(sorted(rotation["delete"]), sorted([sig, f".{sig}", f".{exc}"]))

    def test_rotate_hide_sig_hides_both(self):
        tk.rotate(hide_sig=True)
        self.assertEqual(sum(n.startswith(".") for n in self.files()), 2)

    def test_rotate_fails_when_tangd_does_not_serve_the_new_keys(self):
        for down in (OSError("connection refused"), http.client.IncompleteRead(b"")):  # or a reply cut short
            self.tang_down = down
            with self.assertRaises(tk.Fail):
                tk.rotate(hide_sig=False)
        self.tang_down, self.served = None, tk.visible("sig") + tk.visible("exc")  # tangd reads another directory
        with self.assertRaisesRegex(tk.Fail, "does not advertise the new keys"):
            tk.rotate(hide_sig=False)

    def test_rotations_in_the_same_second_are_both_kept(self):
        with mock.patch.object(tk.time, "time", return_value=time.time()):
            tk.rotate(hide_sig=False)
            tk.rotate(hide_sig=False)
        self.assertEqual(len(tk.rotations()), 2)

    def test_cleanup_waits_for_every_client(self):
        old = self.exc()
        self.unlock("10.0.0.20", old, days_ago=20)
        self.unlock("10.0.0.21", old, days_ago=20)
        self.unlock("10.0.0.5", old, code=404)  # failed unlocks do not count
        tk.rotate(hide_sig=False)
        new = self.exc()
        self.assertIn("less than 90 days", self.why())
        self.age_rotations()
        self.assertEqual(self.why(), "no unlock with the current key for 2 days: 10.0.0.20, 10.0.0.21")
        self.unlock("10.0.0.20", old)  # rebinding uses the old key once,
        self.unlock("10.0.0.20", new)  # then the daily test uses the new one
        self.assertEqual(self.why(), "used a retired key in the last 14 days: 10.0.0.20; "
                                     "no unlock with the current key for 2 days: 10.0.0.21")
        with self.later(15):
            self.unlock("10.0.0.20", new)
            self.assertEqual(self.why(), "no unlock with the current key for 2 days: 10.0.0.21")
            tk.forget(["10.0.0.21"], force=False)  # silent for long: that client is gone
            self.assertEqual(self.why(), "")
            tk.cleanup(now=False)
        self.assertEqual((len(self.files()), tk.rotations()), (2, []))
        self.assertFalse(any(n.startswith(".") for n in self.files()))

    def test_first_scan_reads_the_whole_journal(self):
        self.unlock("10.0.0.40", self.exc(), days_ago=200)  # a client that has not run for months
        tk.rotate(hide_sig=False)
        self.age_rotations()
        self.unlock("10.0.0.20", self.exc())
        self.assertEqual(self.why(), "no unlock with the current key for 2 days: 10.0.0.40")

    def test_cleanup_refuses_without_known_clients(self):
        tk.rotate(hide_sig=False)
        self.age_rotations()
        self.assertEqual(self.why(), "no client has unlocked with this server yet")
        self.unlock("<unknown>", self.exc())
        self.assertEqual(self.why(), "tangd does not log client addresses")

    def test_cleanup_never_deletes_an_advertised_exchange_key(self):
        exc = [n for n, k in tk.keys().items() if tk.use(k) == "exc"][0]
        tk.rotate(hide_sig=False)
        self.age_rotations()
        self.unlock("10.0.0.20", self.exc())
        os.rename(self.db / f".{exc}", self.db / exc)  # someone undid the rotation by hand
        tk.cleanup(now=True)
        self.assertIn(exc, self.files())
        self.assertIn("advertised again", self.why())

    def test_cleanup_now_makes_the_rotation_urgent(self):
        old = self.exc()
        tk.rotate(hide_sig=False)
        new = self.exc()
        self.unlock("10.0.0.20", old)  # rebinding uses the old key once
        self.unlock("10.0.0.20", new)
        tk.cleanup(now=True)
        self.assertEqual(len(tk.rotations()), 1)  # one round of daily tests is still needed
        with self.later(3):
            self.unlock("10.0.0.20", new)  # volume X moved...
            self.unlock("10.0.0.20", old)  # ...but volume Y on the same host is stuck on the old key
            tk.cleanup(now=False)
            self.assertEqual(len(tk.rotations()), 1)
        with self.later(6):
            self.unlock("10.0.0.20", new)  # Y fixed: only the new key is used now
            tk.cleanup(now=False)  # the daily cleanup finishes what --now started
        self.assertEqual(tk.rotations(), [])

    def test_current_key_must_be_used_in_the_last_two_days(self):
        tk.rotate(hide_sig=False)
        self.age_rotations()
        self.unlock("10.0.0.20", self.exc(), days_ago=5)
        self.assertEqual(self.why(), "no unlock with the current key for 2 days: 10.0.0.20")

    def test_retired_key_used_under_its_sha1_id(self):
        retired = tk.visible("exc")[0]
        tk.rotate(hide_sig=False)
        self.age_rotations()
        self.unlock("10.0.0.20", self.exc())
        self.unlock("10.0.0.20", tk.thumbprints(retired)[1])  # older clevis versions name keys by SHA-1
        self.assertIn("used a retired key", self.why())

    def test_unlocks_through_a_url_ending_in_a_slash_count(self):
        old = self.exc()
        tk.rotate(hide_sig=False)
        self.age_rotations()
        self.unlock("10.0.0.20", old, path="//rec/")  # bound to http://tang:7500/, clevis posts to //rec/
        self.unlock("10.0.0.20", self.exc(), path="//rec/")
        self.assertEqual(self.why(), "used a retired key in the last 14 days: 10.0.0.20")

    def test_overlapping_rotations_delete_only_their_own_keys(self):
        sig0 = [n for n, k in tk.keys().items() if tk.use(k) == "sig"][0]
        exc0 = self.exc()
        tk.rotate(hide_sig=False)  # A retires sig0 and exc0
        with mock.patch.object(tk.time, "time", return_value=time.time() + 5):
            tk.rotate(hide_sig=False)  # B, before A is cleaned up
        self.age_rotations()
        self.unlock("10.0.0.20", self.exc())
        self.unlock("10.0.0.30", exc0, days_ago=3)  # a disk somewhere still uses A's key
        self.unlock("10.0.0.30", self.exc())
        tk.cleanup(now=False)
        self.assertEqual(len(tk.rotations()), 1)  # B done, A kept
        self.assertIn(sig0, self.files())  # the signing key that disk trusts is still there
        with self.later(15):
            self.unlock("10.0.0.20", self.exc())
            self.unlock("10.0.0.30", self.exc())
            tk.cleanup(now=False)
        self.assertEqual((tk.rotations(), len(self.files())), ([], 2))

    def test_forget(self):
        self.unlock("10.0.0.20", self.exc())
        with self.assertRaises(tk.Fail):  # it unlocked just now: it is not gone
            tk.forget(["10.0.0.20"], force=False)
        tk.forget(["10.0.0.20"], force=True)  # stolen
        self.assertNotIn("10.0.0.20", tk.update_clients()["clients"])  # and it stays forgotten
        with self.assertRaises(tk.Fail):
            tk.forget(["10.0.0.99"], force=True)

    def test_journal_failure_loses_nothing(self):
        old = self.exc()
        tk.rotate(hide_sig=False)
        self.age_rotations()
        self.unlock("10.0.0.20", self.exc())
        self.journal_broken = True
        self.assertEqual(self.why(), "cannot check: cannot read the tangd journal")
        self.unlock("10.0.0.30", old)  # written while the journal could not be read
        self.unlock("10.0.0.30", self.exc())
        self.journal_broken = False
        self.assertEqual(self.why(), "used a retired key in the last 14 days: 10.0.0.30")

    def test_journal_reading(self):
        journal = load("tang-keyctl.py").journal  # the real one: setUp replaced tk.journal
        entry = {"MESSAGE": "10.0.0.20 POST /rec/abc => 200", "__CURSOR": "c1"}
        read = subprocess.CompletedProcess([], 0, stdout=json.dumps(entry).encode() + b"\n")
        with mock.patch("subprocess.run", return_value=read) as run:
            self.assertEqual(journal("c0"), [entry])
            cmd = run.call_args[0][0]
            self.assertEqual((cmd[cmd.index("-t") + 1], cmd[cmd.index("--after-cursor") + 1]), ("tangd", "c0"))
            journal(None)
            self.assertNotIn("--after-cursor", run.call_args[0][0])
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, stdout=b"")):
            with self.assertRaisesRegex(Exception, "cannot read the tangd journal"):
                journal("c0")

    def test_main_writes_metrics(self):
        old = self.exc()
        self.unlock("10.0.0.20", old, days_ago=1)
        with mock.patch.object(sys, "argv", ["tang-keyctl", "rotate"]):
            self.assertEqual(tk.main(), 0)
        self.unlock("10.0.0.20", self.exc())
        with mock.patch.object(sys, "argv", ["tang-keyctl", "status"]):
            self.assertEqual(tk.main(), 0)
        text = (self.textfile / "tang_keyctl.prom").read_text()
        states = sorted({(m["use"], m["state"]) for m, _ in metric(text, "tang_key_created_timestamp_seconds")})
        self.assertEqual(states, [("exc", "active"), ("exc", "retired"), ("sig", "active"), ("sig", "retired")])
        self.assertEqual(len(metric(text, "tang_key_created_timestamp_seconds")), 16)  # 4 keys, 2 hashes, 2 URLs
        (pending,) = metric(text, "tang_rotation_pending_timestamp_seconds")
        self.assertEqual(sorted(pending[0]), ["rotated", "rotation", "urgent"])
        self.assertIn("less than 90 days", metric(text, "tang_rotation_blocked_info")[0][0]["blocked_by"])
        last = {m["key"]: v for m, v in metric(text, "tang_client_last_unlock_timestamp_seconds")}
        self.assertAlmostEqual(last["current"], time.time(), delta=5)
        self.assertAlmostEqual(last["retired"], time.time() - DAY, delta=5)
        (first,) = metric(text, "tang_client_first_unlock_timestamp_seconds")
        self.assertEqual(first[0], {"client": "10.0.0.20"})
        self.assertAlmostEqual(first[1], time.time() - DAY, delta=5)  # its first unlock, not its last
        self.assertEqual(metric(text, "tang_advertisement_ok"), [({"url": T1}, 1)])
        self.assertEqual(sorted((m["command"], v) for m, v in metric(text, "tang_keyctl_success")),
                         [("rotate", 1), ("status", 1)])
        with mock.patch.object(sys, "argv", ["tang-keyctl", "forget", "10.0.0.20"]):
            self.assertEqual(tk.main(), 1)  # it unlocked just now
        with mock.patch.object(sys, "argv", ["tang-keyctl", "forget", "--force", "10.0.0.20"]):
            self.assertEqual(tk.main(), 0)

    def test_bad_settings_are_refused(self):
        for conf in ("TANG_URLS=http://t1\nPROM_URL=x\n", "TANG_URLS=http://t1\nMIN_AGE_DAYS=a month\n",
                     "QUIET_DAYS=7\n", "TANG_URLS=http://t1\nQUIET_DAYS=1\n"):
            tk.C.clear()
            tk.C.update(self.defaults)
            (self.dir / "tang-keyctl.conf").write_text(conf)
            with self.assertRaises(SystemExit):
                tk.load_settings()


if __name__ == "__main__":
    unittest.main(verbosity=2)
