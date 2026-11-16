"""Copyright and licence notices shown by every program (``--version``) and the GUI.

helper/blockads-fw is stdlib-only and standalone, so it carries its own copy of
these lines; tests/unit/test_legal.py keeps the two in step.
"""

from __future__ import annotations

import argparse
import sys

from .. import __version__

COPYRIGHT = "Copyright (C) 2026 MateusBMP"
LICENSE_ID = "GPL-3.0-only"
LICENSE_URL = "https://www.gnu.org/licenses/gpl-3.0.html"
UPSTREAM = "https://github.com/pass-with-high-score/blockads-android"


def version_text(prog: str) -> str:
    """GNU-style ``--version`` output."""
    return (
        f"{prog} (blockads-linux) {__version__}\n"
        f"{COPYRIGHT}\n"
        f"License GPLv3: GNU GPL version 3 only <{LICENSE_URL}>.\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n"
        f"Based on blockads-android <{UPSTREAM}>; see NOTICE."
    )


def add_version_option(parser: argparse.ArgumentParser, prog: str) -> None:
    """``--version``, printed as is (argparse's own action rewraps the lines)."""

    class _Version(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            sys.stdout.write(version_text(prog) + "\n")
            parser.exit()

    parser.add_argument("--version", nargs=0, action=_Version, help="show the version, copyright and licence")
