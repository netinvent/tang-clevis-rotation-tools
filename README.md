# Tang Clevis Rotation tools

Automatic and safe rotation of Tang keys for disks unlocked with Clevis
(Network-Bound Disk Encryption).
Designed to run on RHEL 10 and Debian 13, with LUKS2 volumes bound to one or two tang servers.

| Script | Runs on | Does |
|---|---|---|
| `tang-keyctl` | each Tang server | rotates its keys once a year, deletes retired keys once no client needs them |
| `clevis-rebind` | each client | moves the Clevis bindings to the new keys and tests them, daily |

Both are single Python files (standard library only). They export metrics
through node_exporter for Prometheus; alert rules and a Grafana dashboard are
included. Neither reads Prometheus, and the emergency passphrase of each volume
is never touched.

## How it works

1. **Rotate**, once a year on a different date per Tang server. A new key pair is
   created. The old exchange key is hidden: no longer advertised, but it still
   unlocks. The old signing key stays advertised, so clients can check the new
   advertisement with a key they already trust.
2. **Rebind and test**, daily on each client. A binding that uses a retired key
   is bound again, pinned to that trusted signing key; the old binding is
   removed only once the new one works with every server. Then every Tang pin is
   test-unlocked with its server; a disk that went missing, or whose header cannot
   be read, is still tested from its last known pins. If a Tang server is
   unreachable, or no trusted key signs its advertisement, nothing changes and the
   volume is reported as failing.
3. **Clean up**, daily on each Tang server. The daily unlock tests appear in
   the tangd journal as `client-ip POST /rec/<key id> => 200`, so each Tang
   server knows which client still uses which of its keys. Retired keys are
   deleted only when
   - they were retired at least 90 days ago and are not advertised,
   - no client used them in the last 14 days,
   - every client seen so far unlocked with the current key in the last 2 days.

   A client that is gone blocks cleanup until you run `tang-keyctl forget <its IP>`.

## Install

You need `python3` (3.9 or later) and, for monitoring, node_exporter with its
textfile collector. On a minimal Debian 13: `apt install python3 prometheus-node-exporter`.
Each Tang server tells its clients apart by IP address, so a client must always
reach it from the same address. Clients behind a NAT or a proxy share one
address: see Limits.

**Firewall.** Only your clients' addresses may reach the Tang port. Tang asks
for no credentials: anyone who can reach it while holding a disk, or a copy of
its LUKS header, can unlock that disk. The firewall is what stops a stolen disk
from being unlocked. As a second line, the `TangNewClient` alert fires when an
address unlocks with a Tang server for the first time: expected when you add a
client; otherwise, investigate that address.

**Tang servers**, after editing `config/tang-keyctl.conf`:

```bash
install -m 0700 tang-keyctl.py /usr/local/sbin/tang-keyctl
install -m 0644 config/tang-keyctl.conf /etc/tang-keyctl.conf
install -m 0644 systemd/tang-keyctl@.service systemd/tang-keyctl-*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tang-keyctl-rotate.timer tang-keyctl-cleanup.timer tang-keyctl-status.timer
```

The rotate timer fires on January 15. **Required on the second server:** move it
6 months away with `systemctl edit tang-keyctl-rotate.timer`, so that the two
servers never retire keys together:

```ini
[Timer]
OnCalendar=
OnCalendar=*-07-15 03:00:00
```

**Clients:**

```bash
install -m 0700 clevis-rebind.py /usr/local/sbin/clevis-rebind
install -m 0644 systemd/clevis-rebind.service systemd/clevis-rebind.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now clevis-rebind.timer
systemctl start clevis-rebind
```

`clevis-rebind` finds the textfile directory by itself:
`/var/lib/node_exporter/textfile_collector`, or Debian's
`/var/lib/prometheus/node-exporter`. Elsewhere, set `Environment=TEXTFILE_DIR=...`
with `systemctl edit clevis-rebind.service`.

**Prometheus and Grafana:** add `prometheus/nbde-alerts.yml` to `rule_files`
(check it with `promtool check rules`), and import `grafana/nbde-dashboard.json`
in Grafana (Dashboards, New, Import).

**Rollout.** Install `clevis-rebind` on every client before the first cleanup.
On the first run of `tang-keyctl`, each Tang server reads its whole journal, so
clients that are gone for good show up in the dashboard's "Tang clients" table
and block cleanup until you forget them. Expect `TangNewClient` alerts while you
roll out.

**Before production**, on test machines (two Tang servers and a client):
1. After `systemctl start clevis-rebind` on the client, `journalctl -t tangd -o cat`
   on a Tang server shows a line like `10.0.0.20 POST /rec/<key id> => 200` with
   the client's IP.
2. Run a full cycle: `tang-keyctl rotate` on a Tang server,
   `systemctl start clevis-rebind` on the client, and `tang-keyctl cleanup --now`
   on that server. Two days later the daily cleanup has deleted the old keys (the
   dashboard shows no pending cleanup). Then reboot the client with each Tang
   server stopped in turn (it unlocks), and with both stopped (passphrase prompt).

## Howto

**See the state.** Open the "NBDE: Tang key rotation" dashboard. On a client:
`journalctl -u clevis-rebind`. On a Tang server: `journalctl -u 'tang-keyctl@*'`.

**Rotate now.** `systemctl start tang-keyctl@rotate`. Clients move within a day;
the retired keys are deleted after 90 days, once no client uses them.

**Add a client.** Allow its address through the Tang servers' firewall, bind its
volumes to both Tang servers with the URLs exactly as in their `TANG_URLS`, and
install `clevis-rebind`. The Tang servers learn about it from its first daily
test, which fires the expected `TangNewClient` alert.

**Remove a client.** Wipe its disks with `cryptsetup luksErase` (irreversible) and
shut it down; only then run `tang-keyctl forget <its IP>` on both Tang servers.
`forget` refuses a client that unlocked in the last 2 days; add `--force` if it is
really gone. Also forget a client's old address when it moves to a new one, and
forget a client on a Tang server it stops using.

**Remove a disk from a client.** Wipe it and detach it, then delete
`/var/lib/clevis-rebind/<its LUKS UUID>.pins.json` on the client. Until then it is
reported as not seen, and its Tang servers keep the keys it needs.

**A volume is failing.** The reason is on the dashboard and in the client's journal:
- *cannot fetch .../adv* or *unlock test ... failed*: that Tang server cannot be
  reached, or cannot unlock this volume.
- *no trusted signing key*: add the server's current signing-key thumbprint
  (`tang-show-keys <port>` on the server) to `/etc/clevis-rebind/trusted` on the
  client, creating that directory if needed.
- *not seen since*: the disk is detached. Reattach it, or remove it as above.
- *cannot read the LUKS header*: the disk or its storage is failing. Its last
  known pins are still tested meanwhile, so its Tang servers keep its keys.
- *Clevis token without keyslot*: left over by an interrupted change. Find it with
  `cryptsetup luksDump <device>`, then remove it with
  `cryptsetup token remove --token-id <id> <device>`.
- *... 'clevis', 'luks', 'pass' ... returned non-zero exit status*: no Tang server
  can unlock that binding any more. If `clevis luks list -d <device>` shows a newer
  binding to the same servers, remove the old one with
  `clevis luks unbind -d <device> -s <slot>`; otherwise bind the volume again with
  its passphrase.
- *cannot read .../<uuid>.pins.json*: that file is damaged. Delete it; it is
  written again at the next run if the disk is attached.
- *non-Tang pins*, *LUKS1*: not handled automatically. Rebind or convert that
  volume by hand.

**A disk or a client is stolen.**
1. On both Tang servers: `tang-keyctl rotate`.
2. On every client: `systemctl start clevis-rebind`.
3. For a stolen client, on both Tang servers: `tang-keyctl forget --force <its IP>`.
4. On both Tang servers: `tang-keyctl cleanup --now`. It makes the rotation
   urgent: no 90-day wait, but every client is still checked, so the daily cleanup
   deletes the keys once no client has used them for 2 days, about 2 days after
   the rebinds. A client that cannot be updated in time can be forgotten too; it
   then needs its passphrase at its next boot.

**Tang keys leaked, or a Tang server compromised.** If in doubt, rebuild the
server first, from its latest backup.
1. Note the current signing-key thumbprint (`tang-show-keys <port>`), then run
   `tang-keyctl rotate --hide-sig`; it prints the new thumbprint.
2. On every client, add the new thumbprint to `/etc/clevis-rebind/trusted` and the
   old one to `/etc/clevis-rebind/revoked`, then `systemctl start clevis-rebind`.
3. On that server: `tang-keyctl cleanup --now` (urgent, as above).

**Replace a Tang server.** Install the new server like the others. On each
client, pause `clevis-rebind`, bind to the new server pair, remove the old
binding, and resume. Slot numbers change at each rebind: use the ones
`clevis luks list` shows now (here, 2):

```bash
systemctl stop clevis-rebind.timer   # then wait until `systemctl is-active clevis-rebind` says inactive
clevis luks list -d /dev/sda3
clevis luks pass -d /dev/sda3 -s 2 | clevis luks bind -d /dev/sda3 -k - sss \
  '{"t":1,"pins":{"tang":[{"url":"http://tang1:7500","thp":"..."},{"url":"http://tang3:7500","thp":"..."}]}}' &&
clevis luks unbind -d /dev/sda3 -s 2 -f   # only once the new binding is there
systemctl start clevis-rebind.timer
```

Once the dashboard's "Bindings" table no longer lists the old server, destroy its
keys and their backups.

**Back up.** After each rotation, back up `/var/db/tang` and `/var/lib/tang-keyctl`
together, keeping file dates (`tar`, or `cp -a`): the key files' dates tell when
the keys were created. Only ever restore the latest backup: an older one lacks the keys
the clients now use. After each cleanup, destroy the older backups: they hold
keys that still unlock stolen disks. Likewise, on clients, an old LUKS header
backup still opens its volume with the old passphrase, even after a passphrase
change.

## Metrics

| Metric | Meaning |
|---|---|
| `clevis_rebind_run_timestamp_seconds{hostname}` | last client run |
| `clevis_volume_ok{hostname,uuid,device}` | 1 when every binding of the volume is on current keys and passed its unlock test |
| `clevis_volume_problem_info{hostname,uuid,device,reason}` | why a volume is failing |
| `clevis_binding_kid{hostname,uuid,device,url,kid}` | the Tang key each binding uses, read from the LUKS header |
| `luks_keyslot_changed_timestamp_seconds{hostname,uuid,device,slot,kind,exact}` | when a keyslot got its key; `kind` is passphrase, clevis or token; `exact="0"` means at least that old |
| `tang_key_created_timestamp_seconds{url,kid,hash,use,state}` | when each Tang key was created; `state` is `active` or `retired` |
| `tang_rotation_pending_timestamp_seconds{rotation,rotated,urgent}` | each rotation whose retired keys are not deleted yet |
| `tang_rotation_blocked_info{rotation,rotated,urgent,blocked_by}` | why they are kept |
| `tang_client_last_unlock_timestamp_seconds{client,key}` | each client's last unlock with the `current` key, and with a `retired` one |
| `tang_client_first_unlock_timestamp_seconds{client}` | each client's first unlock seen by this server |
| `tang_advertisement_ok{url}` | 1 when tangd advertises exactly the exchange keys on disk |
| `tang_keyctl_success{command}`, `tang_keyctl_timestamp_seconds{command}` | result and time of the last rotate, cleanup and status |

## Limits

- LUKS1 volumes and bindings that mix Tang with TPM2 are reported, not rebound.
  A detached LUKS1 disk is not followed either.
- Clients behind one NAT or proxy share an address. A Tang server still sees when
  one of them uses a retired key: cleanup waits, `TangClientOnRetiredKey` fires,
  and the dashboard's "Bindings" table shows which host. It cannot see one of
  them going silent: `ClevisRebindNotRunning` and your node_exporter `up` alert
  cover that, but cleanup may go ahead without it. Retired keys are kept 90 days
  and the two servers rotate 6 months apart, so with t=1 such a client needs its
  passphrase only after about 9 months offline, or within days after
  `cleanup --now` on both servers.
- Disks never attached since `clevis-rebind` was installed, such as spares in
  storage, are unknown to the Tang servers: keep their passphrases at hand.
- Each Tang server needs its own key directory: don't share `/var/db/tang` between
  servers or put Tang behind a load balancer, and rotate keys only with
  `tang-keyctl` (not `tangd-rotate-keys`).
- A detached copy of an attached disk (clone, snapshot: same LUKS UUID) is not
  followed separately.
- LUNs visible from several hosts are out of scope: two hosts could rebind the
  same LUKS header at once.
- Clients must reach tangd directly over plain http (Tang needs no TLS). Behind a
  proxy, such as one adding https, all clients share the proxy's address, as
  behind a NAT.

## Tests

```bash
python3 tests/test_nbde.py .
```

Runs anywhere: disks, Tang servers, their journal and system commands are faked.
