"""Tests for daemon.ntpnames (the names allowed plain DNS when the clock is wrong)."""

import pytest

from blockads_linux.daemon.ntpnames import NtpNames, normalize_host, read_system_ntp_names


@pytest.mark.parametrize(
    ("name", "allowed"),
    [
        ("pool.ntp.org", True),
        ("2.arch.pool.ntp.org", True),
        ("0.debian.pool.ntp.org", True),
        ("2.fedora.pool.ntp.org", True),
        ("ntp.ubuntu.com", True),
        ("1.ntp.ubuntu.com", True),
        ("ntp-bootstrap.ubuntu.com", True),
        ("time.google.com", True),
        ("time.cloudflare.com", True),
        ("evilpool.ntp.org", False),  # under ntp.org, not under pool.ntp.org
        ("ntp.org", False),
        ("pool.ntp.org.evil.example", False),
        ("x.time.google.com", False),  # exact names do not cover subdomains
        ("google.com", False),
        ("example.com", False),
        ("", False),
    ],
)
def test_builtin_names(name, allowed):
    assert NtpNames().matches(name) is allowed


def write(root, path, text):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def test_reads_every_time_daemon_configuration(tmp_path):
    write(tmp_path, "etc/systemd/timesyncd.conf",
          "[Time]\n#NTP=commented.example\nNTP=ntp1.corp.example 192.0.2.1\nFallbackNTP=Ntp2.Corp.Example.\n")
    write(tmp_path, "etc/systemd/timesyncd.conf.d/10-site.conf", "[Time]\nNTP=dropin.example\n")
    write(tmp_path, "usr/lib/systemd/timesyncd.conf.d/vendor.conf", "[Time]\nFallbackNTP=vendor.example\n")
    write(tmp_path, "etc/chrony/chrony.conf",
          "! comment\npool 2.debian.pool.ntp.org iburst\nserver chrony.corp.example iburst nts\npeer 10.0.0.2\n"
          "confdir /etc/chrony/conf.d\nsourcedir /etc/chrony/sources.d /run/chrony-dhcp\n")
    write(tmp_path, "etc/chrony/conf.d/extra.conf", "server confdir.example\ninclude /etc/never-followed.conf\n")
    write(tmp_path, "etc/chrony/sources.d/ubuntu.sources", "pool 1.ntp.ubuntu.com iburst maxsources 1 nts prefer\n")
    write(tmp_path, "run/chrony-dhcp/eth0.sources", "server dhcp.example iburst\n")
    write(tmp_path, "etc/never-followed.conf", "server nested.example\n")
    write(tmp_path, "etc/ntp.conf", "server 0.pool.ntp.org iburst\npool ntpd.example\nrestrict default nomodify\n")
    write(tmp_path, "etc/ntpd.conf", 'servers openntpd.example\nconstraints from "https://www.example.com"\n')
    assert read_system_ntp_names(tmp_path) == {
        "ntp1.corp.example", "ntp2.corp.example", "dropin.example", "vendor.example",
        "2.debian.pool.ntp.org", "chrony.corp.example", "confdir.example", "1.ntp.ubuntu.com", "dhcp.example",
        "0.pool.ntp.org", "ntpd.example", "openntpd.example",
    }


def test_configured_names_match_exactly(tmp_path):
    write(tmp_path, "etc/chrony.conf", "server time.corp.example iburst\n")
    names = NtpNames.load(tmp_path)
    assert names.configured == {"time.corp.example"}
    assert names.matches("time.corp.example") and not names.matches("x.time.corp.example")
    assert names.matches("0.pool.ntp.org")  # built-ins stay


def test_missing_configuration_is_fine(tmp_path):
    assert read_system_ntp_names(tmp_path) == set()


@pytest.mark.parametrize(
    ("text", "host"),
    [
        ("Pool.NTP.org.", "pool.ntp.org"),
        ('"quoted.example"', "quoted.example"),
        ("192.0.2.1", None),
        ("2001:db8::1", None),
        ("[2001:db8::1]", None),
        ("bad name", None),
        ("-leading.example", None),
        ("a" * 64 + ".example", None),
    ],
)
def test_normalize_host(text, host):
    assert normalize_host(text) == host
