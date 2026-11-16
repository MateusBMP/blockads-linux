# Changelog

All notable changes to blockads-linux. Versions follow [PEP 440](https://peps.python.org/pep-0440/);
the Debian package spells a pre-release with `~` (1.0.0rc1 is 1.0.0~rc1).

## [0.1.0] - 2026-11-16

### Added
- First release: system-wide DNS blocking of ads, trackers, malware and
  phishing domains for Linux desktops. A port of blockads-android with the
  same filter catalog and rule syntax.
- `blockadsd`, a sandboxed DNS filter, and a root firewall helper whose
  iptables rules send the system's DNS queries to it. The rules are removed
  whenever the filter stops or fails, so DNS keeps working.
- `blockads-update` downloads the filter lists from their original publishers
  and compiles them on your machine.
- `blockads`, a Qt6 desktop application with a tray icon, in English and
  Brazilian Portuguese, and `blockadsctl`, a command-line tool. Actions that
  weaken protection ask for the administrator password.
- Filter overlap: `blockadsctl filters overlap` and Filters → Overlap… show
  how much the enabled lists duplicate each other.
- A trusted Wi-Fi network can be pinned to one access point
  (`blockadsctl networks add --pin-ap`, or the checkbox on the Networks page),
  so a look-alike network with the same name is not trusted.
- Every program prints its version, copyright and licence with `--version`.

### Security
- A security policy (`SECURITY.md`) with private vulnerability reporting.

### Packaging
- Packages for Debian 12 and 13, Ubuntu 24.04 and 26.04, and Arch Linux.
- `make install` and `make uninstall` for other distributions (Fedora), with
  an install manifest and rollback.
- Nothing is enabled on install; one `systemctl enable --now` command turns
  protection on.

[0.1.0]: https://github.com/MateusBMP/blockads-linux/releases/tag/v0.1.0
