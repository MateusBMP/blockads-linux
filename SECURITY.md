# Security policy

blockads-linux runs a root helper, a system service and a D-Bus API, and it
changes the firewall. Security reports are welcome and taken seriously.

## Supported versions

The project is pre-alpha and has no releases yet. Only the latest commit on
`main` is supported; fixes are not backported.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/MateusBMP/blockads-linux/security/advisories/new)
(the *Security* tab → *Report a vulnerability*). Only the maintainers can see
the report.

Please include:

- the commit or version, the distribution and its versions of systemd,
  iptables, polkit and Python;
- what an attacker needs (local user, another user on the same machine, a
  container, a host on the LAN, a malicious list publisher, a network
  attacker) and what they gain;
- steps to reproduce, or a proof of concept;
- a diagnostics report if it helps (`blockadsctl diagnostics`; check it for
  anything you do not want to share first).

What to expect:

- an acknowledgement within 7 days;
- an assessment and a plan, discussed with you in the private advisory;
- a fix on `main`, then a published GitHub security advisory crediting you
  (unless you prefer not to be named). Please keep the details private until
  the advisory is published.

## Scope

In scope, for example:

- privilege escalation through `blockads-fw`, the systemd units, the D-Bus API
  or the polkit policy (for example a weakening action without authentication,
  or a local user making the root helper read or write files it should not);
- firewall rules that survive a stop, a crash or an uninstall, or protection
  that fails closed (DNS broken for the whole system) when it should fail open;
- port 154 (the opt-in bridge redirect) or port 153 answering hosts other than
  the local machine and the configured containers and VMs;
- reading other users' DNS queries, or the query log leaking through D-Bus
  signals, notifications, exports or file permissions;
- a malicious filter list or upstream DNS server crashing the daemon,
  escaping the sandbox, or affecting more than the answers it controls;
- network contacts beyond the documented ones (the configured DNS upstreams,
  the original publishers of enabled lists, actions the user clicks).

Out of scope (documented limitations, not vulnerabilities; normal issues are
fine for these):

- bypasses that the documentation already lists: systemd-resolved with
  `DNSOverTLS=yes` (status "partial"), DNS over TLS from bridge containers,
  applications using DNS over HTTPS servers that are not on the optional DoH
  blocklist, hardcoded IP addresses;
- anything that requires root, or the administrator password when polkit asks
  for it;
- wrong entries in third-party filter lists (report them to the list's
  publisher).

## Security design

A summary; the details are in the [Architecture](https://github.com/MateusBMP/blockads-linux/wiki/Architecture)
wiki page.

- **Least privilege.** The DNS daemon and the list updater run as the system
  user `blockads` with no capabilities, under a strict systemd sandbox
  (`systemd-analyze security` exposure about 1.2–1.4). systemd (PID 1) holds the
  privileged sockets, so no local user can take over port 153 after a crash.
- **Small root surface.** Only `blockads-fw` runs as root: one file, standard
  library only, started by systemd hooks or `pkexec`. It runs no shell, uses
  no network, checks that every binary and its config are root-owned and not
  writable by others, and never reads files the `blockads` user can write.
- **Authorization per call.** Every D-Bus method is checked with polkit:
  viewing and tightening are allowed for the active local user, weakening
  actions (pause, allow a domain, change the upstream, add a list URL, change
  firewall options) need the administrator password.
- **Fail-open with verified rollback.** Rules are applied in their own chains,
  verified with a live probe, removed on every stop and failure (also by a
  POSIX `sh` fallback), and never saved: a reboot always starts clean.
- **No open resolver.** The bridge listener answers only redirected packets
  from the subnets of the configured bridge interfaces.
- **No telemetry, local compilation.** Lists are downloaded from their original
  publishers and compiled locally; nothing is sent to the project.
