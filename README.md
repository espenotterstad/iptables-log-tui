# iptable-log-tui

A terminal UI for monitoring iptables log entries in real time.

---

> **Proof of concept.** This project was built as an experiment using
> [Claude Code](https://claude.ai/claude-code) and is provided as-is.
> It has not been audited for production use. Use at your own risk.

---

## What it does

`iptable-log-tui` tails an iptables log file and displays entries in a
scrollable, color-coded table. It is aimed at quickly spotting DROP/ACCEPT
patterns, filtering by protocol or IP, and drilling into individual entries.

```
▶ 12:34:01   DROP      TCP       External   203.0.113.42     192.168.1.1      https
  12:34:02   ACCEPT    UDP       Internal   192.168.1.5      8.8.8.8          domain
  12:34:03   DROP      ICMP      External   198.51.100.7     192.168.1.1
```

### Tabs

| Tab     | Description |
|---------|-------------|
| Logs    | Live scrollable log table with detail overlay |
| Stats   | Running counters per action and protocol |
| Filters | Active filter summary and quick-filter key reference |

### Log table columns

`TIME` · `ACTION` · `PROTO` · `CAT` · `SRC` · `DST` · `DPT`

The **CAT** column classifies each source IP automatically:

| Value     | Meaning |
|-----------|---------|
| Internal  | IP belongs to a local subnet (auto-detected from network interfaces at startup) |
| Multicast | IP is in 224.0.0.0/4 (IPv4) or ff00::/8 (IPv6) |
| External  | Everything else |

## Requirements

- Linux with iptables configured to log packets (via `LOG` target or `NFLOG`)
- Log entries must follow the standard kernel syslog format
- Read access to the log file (see [Permissions](#permissions) below)

## Installation

Download a pre-built binary from the [Releases](../../releases) page, or build
from source:

```sh
git clone https://github.com/espenotterstad/iptables-log-tui.git
cd iptables-log-tui
go build -o iptable-log-tui .
```

Go 1.21 or later is required.

## Usage

```
iptable-log-tui [flags]

Flags:
  --file     Path to the iptables log file (default: /var/log/iptables.log)
  --history  Read from the beginning of the file instead of only new entries
```

Examples:

```sh
# Watch live entries
./iptable-log-tui

# Include existing entries in the file
./iptable-log-tui --history

# Custom log path
./iptable-log-tui --file /var/log/kern.log
```

If the log file is not readable by the current user, the binary will
re-execute itself under `sudo` automatically.

## Key bindings

### Logs tab

| Key       | Action |
|-----------|--------|
| `↑` / `↓` | Move cursor |
| `Enter`   | Open detail view for selected entry |
| `Esc`     | Close detail view / clear active filter |
| `d`       | Toggle DROP-only filter |
| `a`       | Toggle ACCEPT-only filter |
| `t`       | Toggle TCP-only filter |
| `u`       | Toggle UDP-only filter |
| `/`       | Search by IP substring |
| `c`       | Clear all filters |

### Global

| Key       | Action |
|-----------|--------|
| `1` `2` `3` | Switch tabs |
| `q` / `Ctrl+C` | Quit |

## Permissions

The log file is typically owned by `root`. Options:

```sh
# Option A — add your user to the adm group (no sudo prompt)
sudo usermod -aG adm $USER
# log out and back in for the change to take effect

# Option B — run as root directly
sudo ./iptable-log-tui
```

## License

[MIT](LICENSE)
