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
▶ 12:34:01   eth0   DROP      TCP       External   203.0.113.42     192.168.1.1      https
  12:34:02   eth0   ACCEPT    UDP       Internal   192.168.1.5      8.8.8.8          domain
  12:34:03   eth0   DROP      ICMP      External   198.51.100.7     192.168.1.1
```

### Tabs

| Tab     | Description |
|---------|-------------|
| Logs    | Live scrollable log table with detail overlay and whois enrichment |
| Stats   | Running counters per action, protocol, interface, source IP, and destination port (sorted by count) |
| Filters | Active filter summary and quick-filter key reference |

### Log table columns

`TIME` · `IN` · `ACTION` · `PROTO` · `CAT` · `SRC` · `DST` · `DPT`

The **CAT** column classifies each source IP automatically:

| Value     | Meaning |
|-----------|---------|
| Internal  | IP belongs to a local subnet (auto-detected from network interfaces at startup) |
| Multicast | IP is in 224.0.0.0/4 (IPv4) or ff00::/8 (IPv6) |
| External  | Everything else |

### Detail view

Pressing `Enter` on any row opens a full-screen detail page for that entry,
showing all parsed fields. For **External** source IPs the detail page also
queries the system `whois` binary asynchronously and displays the network
registration information once available:

| Field   | Example |
|---------|---------|
| Subnet  | 203.0.113.0 - 203.0.113.255 |
| NetName | EXAMPLE-NET |
| ASN     | AS64496 |
| Org     | Example Organisation |

Results are cached per IP so subsequent opens are instant. If `whois` is not
installed or the lookup times out (10 s), the section is silently omitted.

## Requirements

- Linux with iptables configured to log packets (via `LOG` target or `NFLOG`)
- Log entries must follow the standard kernel syslog format
- Read access to the log file (the tool will prompt for `sudo` if needed)

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
  --file     Path to the log file (default: auto-detect /var/log/ufw.log or /var/log/iptables.log)
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

| Key             | Action |
|-----------------|--------|
| `↑` / `k`       | Move cursor up |
| `↓` / `j`       | Move cursor down |
| `PgUp` / `PgDn` | Jump 20 rows |
| `Enter`         | Open detail view for selected entry |
| `Esc`           | Close detail view / clear active filter |
| `d`             | Toggle DROP-only filter |
| `a`             | Toggle ACCEPT-only filter |
| `t`             | Toggle TCP-only filter |
| `u`             | Toggle UDP-only filter |
| `/`             | Search by IP substring |
| `c`             | Clear all filters |

### Global

| Key            | Action |
|----------------|--------|
| `1` `2` `3`    | Switch to tab directly |
| `Tab`          | Cycle to next tab |
| `q` / `Ctrl+C` | Quit |

## Permissions

The log file is typically owned by `root`. If it is not readable by the
current user the tool will automatically re-execute itself under `sudo`,
prompting for your password if required. You can also invoke it with
`sudo` directly to skip the prompt:

```sh
sudo ./iptable-log-tui
```

## License

[MIT](LICENSE)
