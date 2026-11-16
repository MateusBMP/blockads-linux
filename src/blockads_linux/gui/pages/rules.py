"""Rules: your blocklist and allowlist, "all subdomains", import from file or clipboard, export.

Blocking is a tightening action (no password); allowing weakens and needs the
administrator password. An import is a series of ``AddBlockRule`` then
``AddAllowRule`` calls, one at a time: each edit is the daemon's own
read-modify-write, so nothing is lost, and polkit's ``auth_admin_keep`` asks
for the password once.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...filters.custom_rules import CustomRuleType, is_valid_domain, parse_rule
from .. import format as fmt
from ..dbus_client import CallError
from .base import Context, Page, error_text, heading, plain

MAX_IMPORT = 10_000
MAX_IMPORT_BYTES = 4 * 1024 * 1024


def import_domains(text: str) -> tuple[list[str], list[str]]:
    """Hosts, adblock (``||x^``, ``@@||x^``) or plain-domain lines -> (block, allow), in order, de-duplicated."""
    block: dict[str, None] = {}
    allow: dict[str, None] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("!") else ""
        if not line:
            continue
        fields = line.split()
        if len(fields) >= 2:
            try:
                ipaddress.ip_address(fields[0])
            except ValueError:
                continue
            names = fields[1:]  # hosts format: every name on the line
            for name in names:
                name = name.lower().rstrip(".")
                if name not in ("localhost", "localhost.localdomain", "local", "broadcasthost") \
                        and "." in name and is_valid_domain(name):
                    block.setdefault(name, None)
            continue
        rule = parse_rule(line)
        if rule is None or rule.rule_type is CustomRuleType.COMMENT:
            continue
        domain = rule.domain.rstrip(".")
        if "." not in domain.lstrip("*."):
            continue
        (allow if rule.rule_type is CustomRuleType.ALLOW else block).setdefault(domain, None)
    return list(block)[:MAX_IMPORT], list(allow)[:MAX_IMPORT]


def split_rules(rules: dict[str, Any]) -> tuple[list[str], list[str]]:
    """GetRules -> (blocked domains, allowed domains incl. the whitelist), in file order."""
    blocked: dict[str, None] = {}
    allowed: dict[str, None] = {}
    for text in rules.get("rules", []):
        rule = parse_rule(text)
        if rule is None or rule.rule_type is CustomRuleType.COMMENT:
            continue
        (allowed if rule.rule_type is CustomRuleType.ALLOW else blocked).setdefault(rule.domain, None)
    for domain in rules.get("whitelist", []):
        allowed.setdefault(domain, None)
    return list(blocked), list(allowed)


def export_text(blocked: list[str], allowed: list[str]) -> str:
    lines = ["! blockads-linux rules"]
    lines += [f"||{d}^" for d in blocked]
    lines += [f"@@||{d}^" for d in allowed]
    return "\n".join(lines) + "\n"


def normalize_input(text: str, subdomains_only: bool) -> str | None:
    domain = text.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):].split("/", 1)[0]
    domain = domain.rstrip(".").removeprefix("*.")
    if not domain or "." not in domain or not is_valid_domain(domain) or len(domain) > 250:
        return None
    return f"*.{domain}" if subdomains_only else domain


class DomainList(QWidget):
    def __init__(self, page: RulesPage, allow: bool) -> None:
        super().__init__()
        self.page = page
        self.allow = allow
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText(self.tr("example.com"))
        self.input.returnPressed.connect(self.add)
        self.subdomains = QCheckBox(self.tr("Only subdomains"))
        self.subdomains.setToolTip(self.tr("*.example.com: every subdomain, but not example.com itself"))
        add = QPushButton(self.tr("Allow") if allow else self.tr("Block"))
        add.clicked.connect(self.add)
        row.addWidget(self.input, 1)
        row.addWidget(self.subdomains)
        row.addWidget(add)
        layout.addLayout(row)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(self.tr("Search"))
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self._filter)
        layout.addWidget(self.filter)
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        layout.addWidget(self.list, 1)
        remove = QPushButton(self.tr("Remove selected"))
        remove.clicked.connect(self.remove)
        bottom = QHBoxLayout()
        bottom.addWidget(remove)
        bottom.addStretch(1)
        self.count = plain(wrap=False)
        bottom.addWidget(self.count)
        layout.addLayout(bottom)

    def set_domains(self, domains: list[str]) -> None:
        self.list.clear()
        for domain in domains:
            item = QListWidgetItem(fmt.safe(domain, 260))
            item.setData(Qt.ItemDataRole.UserRole, domain)
            self.list.addItem(item)
        self.count.setText(self.tr("%1 domains").replace("%1", fmt.number(len(domains))))
        self._filter(self.filter.text())

    def _filter(self, text: str) -> None:
        needle = text.strip().lower()
        for i in range(self.list.count()):
            item = self.list.item(i)
            item.setHidden(bool(needle) and needle not in item.data(Qt.ItemDataRole.UserRole))

    def add(self) -> None:
        domain = normalize_input(self.input.text(), self.subdomains.isChecked())
        if domain is None:
            self.page.ctx.messages.error(self.tr("Not a valid domain."))
            return
        self.input.clear()
        if self.allow:
            self.page.act("AddAllowRule", domain, done=self.tr("Added to the allowlist."))
        else:
            self.page.act("AddBlockRule", domain, done=self.tr("Added to the blocklist."))

    def remove(self) -> None:
        domains = [item.data(Qt.ItemDataRole.UserRole) for item in self.list.selectedItems()]
        method = "RemoveAllowRule" if self.allow else "RemoveBlockRule"
        for domain in domains:
            self.page.act(method, domain, done=self.tr("Removed."))


class RulesPage(Page):
    title = "Rules"
    icon = "view-list-text"

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("Rules")
        self.rules: dict[str, Any] = {"rules": [], "whitelist": []}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addWidget(heading(self.tr("Your rules")))
        layout.addWidget(plain(self.tr("Your rules win over every filter list. Blocking needs no password; "
                                       "allowing a domain asks for the administrator password.")))
        self.tabs = QTabWidget()
        self.block_list = DomainList(self, allow=False)
        self.allow_list = DomainList(self, allow=True)
        self.tabs.addTab(self.block_list, self.tr("Blocklist"))
        self.tabs.addTab(self.allow_list, self.tr("Allowlist"))
        layout.addWidget(self.tabs, 1)
        row = QHBoxLayout()
        for label, slot in ((self.tr("Import file…"), self.import_file),
                            (self.tr("Import from clipboard"), self.import_clipboard),
                            (self.tr("Export…"), self.export_file)):
            button = QPushButton(label)
            button.clicked.connect(slot)
            row.addWidget(button)
        row.addStretch(1)
        layout.addLayout(row)
        self._pending = 0

    def refresh(self) -> None:
        self.load("GetRules", then=self.show_rules)

    def show_rules(self, result: dict[str, Any]) -> None:
        self.rules = result.get("rules", {"rules": [], "whitelist": []})
        blocked, allowed = split_rules(self.rules)
        self.block_list.set_domains(blocked)
        self.allow_list.set_domains(allowed)

    # --- import/export -------------------------------------------------------------

    def import_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, self.tr("Import rules"), "",
                                              self.tr("Text files (*.txt *.hosts *.list);;All files (*)"))
        if not path:
            return
        try:
            with open(path, "rb") as handle:
                data = handle.read(MAX_IMPORT_BYTES + 1)
        except OSError as exc:
            self.ctx.messages.error(self.tr("Cannot read the file: %1").replace("%1", exc.strerror or str(exc)))
            return
        if len(data) > MAX_IMPORT_BYTES:
            self.ctx.messages.error(self.tr("The file is too large (at most 4 MB)."))
            return
        self.import_text(data.decode("utf-8", "replace"))

    def import_clipboard(self) -> None:
        self.import_text(QApplication.clipboard().text()[:MAX_IMPORT_BYTES])

    def import_text(self, text: str) -> None:
        block, allow = import_domains(text)
        existing_block, existing_allow = split_rules(self.rules)
        block = [d for d in block if d not in set(existing_block)]
        allow = [d for d in allow if d not in set(existing_allow)]
        if not block and not allow:
            self.ctx.messages.info(self.tr("Nothing new to import."))
            return
        queue = [("AddBlockRule", d) for d in block] + [("AddAllowRule", d) for d in allow]
        added = {"AddBlockRule": 0, "AddAllowRule": 0}
        errors: list[CallError] = []

        def next_one() -> None:
            if not queue or (errors and errors[-1].kind in ("denied", "not_running", "read_only")):
                text = self.tr("Imported: %1 blocked, %2 allowed.").replace(
                    "%1", str(added["AddBlockRule"])).replace("%2", str(added["AddAllowRule"]))
                if errors:
                    self.ctx.messages.error(text + " " + error_text(errors[-1]))
                else:
                    self.ctx.messages.info(text)
                self.refresh()
                return
            method, domain = queue.pop(0)

            def ok(_r: Any) -> None:
                added[method] += 1
                next_one()

            def failed(error: CallError) -> None:
                errors.append(error)
                next_one()

            self.client.call(method, domain).then(ok, failed)

        next_one()

    def export_file(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Export rules"), "blockads-rules.txt",
                                              self.tr("Text files (*.txt)"))
        if not path:
            return
        blocked, allowed = split_rules(self.rules)
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(export_text(blocked, allowed))
        except OSError as exc:
            self.ctx.messages.error(self.tr("Cannot write the file: %1").replace("%1", exc.strerror or str(exc)))
            return
        self.ctx.messages.info(self.tr("Rules exported."))
