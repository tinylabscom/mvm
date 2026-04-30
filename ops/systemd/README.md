# `ops/systemd/`

Systemd unit installation for Linux production hosts (the mvmd
deployment target).

| Script | Mutates | Why elevated |
|---|---|---|
| [`install.sh`](install.sh) | Writes `mvm.service` to `/etc/systemd/system/`, runs `systemctl daemon-reload`. | `/etc/systemd/system/` is root-owned. Idempotent. |
