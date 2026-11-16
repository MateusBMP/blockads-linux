# blockads-linux: build, install and uninstall.
#
#   make                         compile the GUI translations (.qm)
#   make check                   unit tests
#   make install DESTDIR=DIR     stage the files under DIR (packages: PKGBUILD, debian/rules)
#   sudo make install            install into the running system, with a manifest and
#                                rollback (packaging/manifest.sh); enables nothing
#   sudo make uninstall          stop the units, revert the firewall, remove exactly the
#                                installed files (state in /var/lib/blockads-linux is kept)
#   make dist                    source tarball of the working tree (blockads-linux-VERSION.tar.gz)
#   make arch-pkg                the Arch package from that tarball (packaging/arch, makepkg)
#
# Every path below is the one the launchers, units and polkit policy name, so
# the prefix is fixed to /usr. The systemd directories follow the distribution
# (Debian 12 still uses /lib/systemd/system).

NAME        := blockads-linux
VERSION     := $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' src/blockads_linux/__init__.py)
PYTHON      ?= python3
# 1: byte-compile into the staged tree (Arch, make install). Debian: 0, dh_python3 does it.
PYCOMPILE   ?= 1

PREFIX      := /usr
LIBDIR      := $(PREFIX)/lib/$(NAME)
BINDIR      := $(PREFIX)/bin
DATADIR     := $(PREFIX)/share
SYSCONFDIR  := /etc
pkgvar       = $(or $(shell pkg-config --variable=$(1) systemd 2>/dev/null),$(2))
UNITDIR     ?= $(call pkgvar,systemdsystemunitdir,$(PREFIX)/lib/systemd/system)
SYSUSERSDIR ?= $(call pkgvar,sysusersdir,$(PREFIX)/lib/sysusers.d)
TMPFILESDIR ?= $(call pkgvar,tmpfilesdir,$(PREFIX)/lib/tmpfiles.d)
# Empty: no licence files (Debian ships them as /usr/share/doc/blockads-linux/copyright).
LICENSEDIR  ?= $(DATADIR)/licenses/$(NAME)

APP_ID      := io.github.mateusbmp.blockads-linux
UNITS       := blockadsd.socket blockadsd-ipv6.socket blockadsd-bridge.socket blockadsd.service \
               blockads-update.service blockads-update.timer blockads-update.path blockads-failsafe.service
QM          := src/blockads_linux/gui/i18n/blockads_pt_BR.qm
PYFILES     := $(shell cd src && find blockads_linux -name __pycache__ -prune -o -type f \
                 \( -name '*.py' -o -path '*/data/*' \) -print | sort)

INSTALL     ?= install
STAGE_TMP   := $(shell mktemp -u /tmp/$(NAME)-stage.XXXXXX)

.PHONY: all build check install install-files uninstall dist arch-pkg clean

all: build

build: $(QM)

$(QM): src/blockads_linux/gui/i18n/blockads_pt_BR.ts
	$(PYTHON) tools/i18n/update.py --compile

check:
	$(PYTHON) -m pytest -q

ifeq ($(DESTDIR),)
# A live install: stage, then copy with a manifest and rollback.
install: build
	@[ "$$(id -u)" -eq 0 ] || { echo "make install: run as root (or set DESTDIR to stage)" >&2; exit 2; }
	$(MAKE) --no-print-directory install-files DESTDIR=$(STAGE_TMP)
	bash packaging/manifest.sh install $(STAGE_TMP); rc=$$?; rm -rf $(STAGE_TMP); exit $$rc
else
install: build install-files
endif

install-files:
	@[ -n "$(DESTDIR)" ] || { echo "install-files needs DESTDIR" >&2; exit 2; }
	@[ -f "$(QM)" ] || { echo "missing $(QM): run make first" >&2; exit 2; }
	set -e; for f in $(PYFILES); do \
	    $(INSTALL) -D -m 0644 "src/$$f" "$(DESTDIR)$(LIBDIR)/python/$$f"; done
	$(INSTALL) -D -m 0644 $(QM) "$(DESTDIR)$(LIBDIR)/python/blockads_linux/gui/i18n/$(notdir $(QM))"
	$(INSTALL) -D -m 0755 data/launchers/blockadsd        "$(DESTDIR)$(LIBDIR)/blockadsd"
	$(INSTALL) -D -m 0755 data/launchers/blockads-update  "$(DESTDIR)$(LIBDIR)/blockads-update"
	$(INSTALL) -D -m 0755 helper/blockads-fw              "$(DESTDIR)$(LIBDIR)/blockads-fw"
	$(INSTALL) -D -m 0755 helper/blockads-fw-emergency.sh "$(DESTDIR)$(LIBDIR)/blockads-fw-emergency.sh"
	$(INSTALL) -D -m 0755 data/launchers/blockadsctl      "$(DESTDIR)$(BINDIR)/blockadsctl"
	$(INSTALL) -D -m 0755 data/launchers/blockads         "$(DESTDIR)$(BINDIR)/blockads"
	set -e; for u in $(UNITS); do \
	    $(INSTALL) -D -m 0644 "data/systemd/$$u" "$(DESTDIR)$(UNITDIR)/$$u"; done
	$(INSTALL) -D -m 0644 data/sysusers.d/$(NAME).conf "$(DESTDIR)$(SYSUSERSDIR)/$(NAME).conf"
	$(INSTALL) -D -m 0644 data/tmpfiles.d/$(NAME).conf "$(DESTDIR)$(TMPFILESDIR)/$(NAME).conf"
	$(INSTALL) -D -m 0644 data/dbus-1/system.d/io.github.mateusbmp.BlockAds1.conf \
	    "$(DESTDIR)$(DATADIR)/dbus-1/system.d/io.github.mateusbmp.BlockAds1.conf"
	$(INSTALL) -D -m 0644 data/polkit-1/actions/io.github.mateusbmp.blockads.policy \
	    "$(DESTDIR)$(DATADIR)/polkit-1/actions/io.github.mateusbmp.blockads.policy"
	$(INSTALL) -D -m 0644 data/polkit-1/rules.d/50-$(NAME).rules \
	    "$(DESTDIR)$(DATADIR)/polkit-1/rules.d/50-$(NAME).rules"
	$(INSTALL) -D -m 0644 data/applications/$(APP_ID).desktop "$(DESTDIR)$(DATADIR)/applications/$(APP_ID).desktop"
	$(INSTALL) -D -m 0644 data/metainfo/$(APP_ID).metainfo.xml "$(DESTDIR)$(DATADIR)/metainfo/$(APP_ID).metainfo.xml"
	$(INSTALL) -D -m 0644 data/icons/hicolor/scalable/apps/$(APP_ID).svg \
	    "$(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/$(APP_ID).svg"
	$(INSTALL) -D -m 0644 data/firewall.conf "$(DESTDIR)$(SYSCONFDIR)/$(NAME)/firewall.conf"
ifneq ($(LICENSEDIR),)
	$(INSTALL) -D -m 0644 LICENSE "$(DESTDIR)$(LICENSEDIR)/LICENSE"
	$(INSTALL) -D -m 0644 NOTICE  "$(DESTDIR)$(LICENSEDIR)/NOTICE"
endif
ifeq ($(PYCOMPILE),1)
	$(PYTHON) -I -m compileall -q -d $(LIBDIR)/python "$(DESTDIR)$(LIBDIR)/python/blockads_linux" >/dev/null
endif

uninstall:
	@[ "$$(id -u)" -eq 0 ] || { echo "make uninstall: run as root" >&2; exit 2; }
	bash packaging/manifest.sh uninstall

# The working tree, not HEAD: a package of what is being tested (no .git needed).
dist:
	tar --exclude-vcs --exclude=./results --exclude=./.vm --exclude=./.claude --exclude=./.pytest_cache --exclude=./debian \
	    --exclude='__pycache__' --exclude='*.qm' --exclude='./$(NAME)-*.tar.gz' \
	    --exclude=./packaging/arch/src --exclude=./packaging/arch/pkg --exclude='*.pkg.tar.*' \
	    --exclude='./packaging/arch/$(NAME)-*.tar.gz' \
	    --transform 's,^\.,$(NAME)-$(VERSION),' -czf $(STAGE_TMP).tar.gz .
	mv -f $(STAGE_TMP).tar.gz $(NAME)-$(VERSION).tar.gz
	@echo $(NAME)-$(VERSION).tar.gz

arch-pkg: dist
	mv -f $(NAME)-$(VERSION).tar.gz packaging/arch/
	cd packaging/arch && makepkg -f $(MAKEPKG_FLAGS)

clean:
	rm -f $(QM) $(NAME)-*.tar.gz packaging/arch/$(NAME)-*.tar.gz packaging/arch/*.pkg.tar.*
	rm -rf packaging/arch/src packaging/arch/pkg
