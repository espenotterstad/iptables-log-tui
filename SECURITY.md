# Security Policy

## Supported Versions

Only the latest release receives security fixes.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Use GitHub's private vulnerability reporting instead:
**[Report a vulnerability](https://github.com/espenotterstad/iptables-log-tui/security/advisories/new)**

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations, if you have them

You can expect an acknowledgement within **7 days** and a fix or resolution
plan within **30 days** depending on severity and complexity.

## Scope

This tool runs with elevated privileges to read system log files and
re-execs itself under sudo when needed. Areas of particular interest:

- Privilege escalation via the sudo re-exec path
- Path traversal or symlink attacks on the `--file` argument
- Command injection via log file contents passed to subprocesses (e.g. whois)
