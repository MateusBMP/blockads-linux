"""polkit authorization for D-Bus callers.

* The subject is the caller's ``system-bus-name``. Every action carries the
  ``org.freedesktop.policykit.owner`` annotation (``unix-user:blockads``), so
  polkit lets the daemon check other users' subjects.
* Interactive authorization only when the caller's message has the
  ALLOW_INTERACTIVE_AUTHORIZATION flag; otherwise a challenge becomes
  :data:`Decision.INTERACTIVE_REQUIRED`.
* A check waits at most :data:`~..common.dbus_api.AUTH_TIMEOUT` (a password
  prompt), non-interactive ones 25 s. If the caller disconnects meanwhile,
  :meth:`Authorizer.forget` cancels its pending checks.
* Only ``view`` decisions are cached (60 s per unique name); a name that
  disconnects is dropped from the cache (unique names are never reused).
* Any polkit failure denies.
"""

from __future__ import annotations

import asyncio
import enum
import itertools
import logging
import time
from collections.abc import Callable
from typing import Any

from jeepney import DBusAddress, new_method_call
from jeepney.wrappers import DBusErrorResponse, unwrap_msg

from ..common.dbus_api import AUTH_TIMEOUT, VIEW, VIEW_CACHE_SECONDS

log = logging.getLogger("blockadsd.polkit")

POLKIT_BUS = "org.freedesktop.PolicyKit1"
POLKIT_PATH = "/org/freedesktop/PolicyKit1/Authority"
POLKIT_IFACE = "org.freedesktop.PolicyKit1.Authority"
ALLOW_USER_INTERACTION = 0x1
NON_INTERACTIVE_TIMEOUT = 25.0


class Decision(enum.Enum):
    AUTHORIZED = "authorized"
    DENIED = "denied"
    INTERACTIVE_REQUIRED = "interactive_required"  # a challenge, but the caller did not allow a prompt


class Authorizer:
    """polkit checks over a jeepney asyncio router (the daemon's bus connection)."""

    def __init__(self, router: Any, *, clock: Callable[[], float] = time.monotonic,
                 timeout: float = AUTH_TIMEOUT, quick_timeout: float = NON_INTERACTIVE_TIMEOUT,
                 cache_seconds: float = VIEW_CACHE_SECONDS) -> None:
        self.router = router
        self.clock = clock
        self.timeout = timeout
        self.quick_timeout = quick_timeout
        self.cache_seconds = cache_seconds
        self._cache: dict[str, float] = {}  # sender -> view authorized until
        self._pending: dict[str, set[str]] = {}  # sender -> cancellation ids
        self._ids = itertools.count(1)
        self._authority = DBusAddress(POLKIT_PATH, bus_name=POLKIT_BUS, interface=POLKIT_IFACE)

    async def check(self, sender: str, action: str, *, interactive: bool) -> Decision:
        if action == VIEW and self._cache.get(sender, 0.0) > self.clock():
            return Decision.AUTHORIZED
        cancel_id = f"blockadsd-{next(self._ids)}"
        subject = ("system-bus-name", {"name": ("s", sender)})
        flags = ALLOW_USER_INTERACTION if interactive else 0
        message = new_method_call(self._authority, "CheckAuthorization", "(sa{sv})sa{ss}us",
                                  (subject, action, {}, flags, cancel_id))
        pending = self._pending.setdefault(sender, set())
        pending.add(cancel_id)
        try:
            async with asyncio.timeout(self.timeout if interactive else self.quick_timeout):
                reply = await self.router.send_and_get_reply(message)
            (authorized, challenge, _details), = unwrap_msg(reply)
        except TimeoutError:
            log.warning("polkit: no answer for %s; denied", action.rsplit(".", 1)[-1])
            await self._cancel(cancel_id)
            return Decision.DENIED
        except DBusErrorResponse as exc:
            # Cancelled (the caller left), polkit missing, or a refused subject.
            if not exc.name.endswith(".Cancelled"):
                log.warning("polkit: %s for %s; denied", exc.name, action.rsplit(".", 1)[-1])
            return Decision.DENIED
        except (OSError, ValueError, ConnectionError) as exc:
            log.warning("polkit: %s; denied", type(exc).__name__)
            return Decision.DENIED
        finally:
            pending.discard(cancel_id)
            if not pending and self._pending.get(sender) is pending:
                del self._pending[sender]
        if authorized:
            if action == VIEW:
                self._cache[sender] = self.clock() + self.cache_seconds
            return Decision.AUTHORIZED
        if challenge and not interactive:
            return Decision.INTERACTIVE_REQUIRED
        return Decision.DENIED

    def forget(self, sender: str) -> None:
        """The caller disconnected: drop its cache entry and cancel its pending checks."""
        self._cache.pop(sender, None)
        for cancel_id in self._pending.pop(sender, set()):
            asyncio.get_running_loop().create_task(self._cancel(cancel_id))

    def expire(self) -> None:
        now = self.clock()
        for sender in [s for s, until in self._cache.items() if until <= now]:
            del self._cache[sender]

    async def _cancel(self, cancel_id: str) -> None:
        message = new_method_call(self._authority, "CancelCheckAuthorization", "s", (cancel_id,))
        try:
            async with asyncio.timeout(5):
                await self.router.send_and_get_reply(message)
        except Exception:  # best effort: polkit drops the check when it times out anyway
            pass


class AllowAll:
    """Development only (``--dev --dbus-allow-all``): every caller is authorized."""

    async def check(self, sender: str, action: str, *, interactive: bool) -> Decision:
        return Decision.AUTHORIZED

    def forget(self, sender: str) -> None:
        pass

    def expire(self) -> None:
        pass
