# blockads-linux

[![CI](https://github.com/MateusBMP/blockads-linux/actions/workflows/ci.yml/badge.svg)](https://github.com/MateusBMP/blockads-linux/actions/workflows/ci.yml)

System-wide blocking of ads, trackers, malware and phishing domains for Linux
desktops. It is a port of [blockads-android](https://github.com/pass-with-high-score/blockads-android)
that uses the same filter catalog and rule syntax, adapted to Linux:

- **No TUN "VPN".** A sandboxed local DNS filter (`blockadsd`) answers on the
  privileged loopback port 153. While protection is on, iptables `nat OUTPUT`
  rules redirect all outgoing port-53 DNS traffic to it. Routing,
  `/etc/resolv.conf` and NetworkManager are never modified.
- **Fail-open by design.** If the filter crashes, hangs or its rules are
  flushed, systemd removes the redirect so DNS keeps working (unfiltered), then
  retries. The tray icon turns red.
- **Nothing is persisted in the firewall.** The rules live only in the kernel
  while the service runs; a reboot always starts clean.
- **No telemetry.** The only network contacts are the DNS upstream you chose
  (Quad9 over DoH by default) and the original publishers of the filter lists
  you enabled.

> **Status:** pre-alpha. The filter engine, the DNS resolver and its upstream
> policy, list updates, the query log and statistics, the root firewall helper,
> system integration (systemd units, D-Bus API, polkit), the desktop GUI with
> its tray icon and notifications, trusted networks and the Android settings
> import all work. There are no distribution packages yet, so nothing is
> installable the normal way.

## Components

| Component | Runs as | Purpose |
|---|---|---|
| `blockadsd` | system user `blockads`, sandboxed | DNS filtering, upstream resolution, logs and statistics, D-Bus API |
| `blockads-update` | system user `blockads`, sandboxed oneshot | downloads lists from their original publishers and compiles them locally |
| `blockads-fw` | root, from systemd hooks only | applies, verifies and reverts the iptables rules |
| `blockads` | desktop user | Qt6 (QtWidgets) GUI and tray icon |
| `blockadsctl` | any user | command-line control over D-Bus |

## Supported environments

Targets are x86_64 systems with systemd, iptables 1.8.9 or later (nft or
legacy backend) and Python 3.11 or later. Every target is tested in CI with
its own packages; the "how" column says where:

| Distribution | Python | Unit tests | Firewall (namespace) suites | System integration |
|---|---|---|---|---|
| Debian 12 (bookworm) | 3.11 | container | container | qemu VM |
| Debian 13 (trixie) | 3.13 | container | container | qemu VM |
| Ubuntu 24.04 LTS | 3.12 | container | container | GitHub runner (native) |
| Ubuntu 26.04 LTS | distro | container | container | GitHub runner (native) |
| Fedora 44 | 3.14 | container | container | qemu VM |
| Arch Linux | rolling | container | container | qemu VM |

- **container**: the distribution's official image on Docker Hub, on every
  push and pull request. The unit tests run as an unprivileged user. The
  firewall suites run real iptables (nft and legacy) inside throwaway user and
  network namespaces.
- **GitHub runner (native)**: GitHub offers this distribution as a hosted
  runner, so the system-integration suite runs directly on that disposable
  machine, without a VM.
- **qemu VM**: GitHub has no runner for this distribution, so the suite runs in
  a disposable qemu/KVM VM booted from the distribution's own cloud image.
- System integration covers the systemd sandbox and socket activation,
  NetworkManager, polkit, and coexistence with Docker, firewalld or ufw. It
  needs a whole machine (its own kernel and systemd), so it runs on pushes to
  `main`, weekly and on demand, not on every push.
- Derivatives (Manjaro, Linux Mint, Pop!_OS, ...) are expected to work but are
  not tested in CI. Development happens on Manjaro.

Run the same suites locally: `python -m pytest` (unit),
`tests/netns/fw_helper.sh` and the other `tests/netns/*.sh` (rootless), and
`tests/vm/run_platform.sh IMAGE...` (qemu/KVM; the images are listed in `tests/vm/vm.sh`).

## Emergency recovery (after installation)

```sh
sudo /usr/lib/blockads-linux/blockads-fw revert --all-backends
# or, without Python:
sudo sh /usr/lib/blockads-linux/blockads-fw-emergency.sh
```

## Development

```sh
python -m pytest            # unit tests (no root, no network)

# The resolver as a normal user on port 5300 (no firewall involved):
PYTHONPATH=src python3 -m blockads_linux.daemon --dev --listen 127.0.0.1:5300 \
    --list path/to/hosts-or-adblock-list.txt --log-queries
```

Firewall integration tests run only inside throwaway rootless network
namespaces (`unshare -Urn`); they never touch the host firewall.

## Documentation

The [wiki](https://github.com/MateusBMP/blockads-linux/wiki) covers the
architecture, installation, usage, configuration, troubleshooting and
development.

## Security

Please report vulnerabilities privately through
[GitHub's vulnerability reporting](https://github.com/MateusBMP/blockads-linux/security/advisories/new),
not in a public issue. [SECURITY.md](SECURITY.md) describes the process, what
is in scope and the security design (sandboxed unprivileged daemon, a small
stdlib-only root helper, polkit on every D-Bus call, verified fail-open
rollback).

## License

Copyright (C) 2026 MateusBMP

blockads-linux is free software under the GNU General Public License,
version 3 only (`GPL-3.0-only`); see [LICENSE](LICENSE). It comes with
ABSOLUTELY NO WARRANTY, to the extent permitted by law.

It is a port of, and partly derived from,
[blockads-android](https://github.com/pass-with-high-score/blockads-android)
(GPL-3.0). [NOTICE](NOTICE) lists the derived parts and the upstream revision.
Filter lists are not redistributed: each is downloaded from its original
publisher and keeps its own licence.

Every program prints its version, copyright and licence with `--version`
(`blockadsctl`, `blockads`, `blockadsd`, `blockads-update`, `blockads-fw`);
the GUI shows them on its About page.
