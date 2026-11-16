"""The forwarder: cache -> in-flight merge -> upstream tiers.

* Identical questions in flight (same name, type, DO and CD bits) share one
  upstream exchange; each caller gets its own parsed copy of the answer.
* Upstreams are tried tier by tier (configured, then fallback, ...); a
  :class:`TierPolicy` picks the tiers per question (upstream/policy.py). Each
  upstream has a circuit breaker: after ``breaker_threshold`` consecutive
  failures it is skipped for ``breaker_cooldown`` seconds, then tried again
  once (half-open). If every upstream is skipped, all are tried anyway rather
  than failing at once.
* The whole resolution has a ``deadline`` below the usual 5 s stub-resolver
  timeout, so clients get our SERVFAIL rather than their own timeout.
* A SERVFAIL or REFUSED *answer* is passed on, not retried elsewhere: a
  DNSSEC failure must not be "fixed" by asking a non-validating fallback.
* Clock rescue (the "encrypted only" exception):
  ``rescue`` tiers (plain DNS) are used only when every normal tier failed,
  an encrypted upstream rejected its certificate's validity period within
  the last ``clock_window`` seconds (a wrong clock), the question is A or
  AAAA, and ``ntp_names`` accepts the name. That lets the time daemon fix the
  clock without opening plain DNS to anything else.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Hashable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import dns.exception
import dns.message
import dns.rdatatype

from .cache import DnsCache
from .upstream.base import CertificateTimeError, Question, Resolution, ResolveError, UpstreamError

DEFAULT_DEADLINE = 4.5
#: How long a certificate time error keeps the clock rescue available.
DEFAULT_CLOCK_WINDOW = 300.0
RESCUE_TYPES = frozenset({int(dns.rdatatype.A), int(dns.rdatatype.AAAA)})


class Upstream(Protocol):
    label: str
    encrypted: bool

    async def exchange(self, question: Question) -> dns.message.Message: ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class Tier:
    name: str  # "configured", "fallback", "network", "ntp-rescue", ...
    upstreams: Sequence[Upstream]


class TierPolicy(Protocol):
    """Chooses the tiers for each question."""

    def select(self, question: Question) -> tuple[Sequence[Tier], Sequence[Tier]]:
        """(normal tiers, clock-rescue tiers) for this question."""
        ...

    def upstreams(self) -> Iterable[Upstream]:
        """Every upstream the policy may return (closed on reset and shutdown)."""
        ...


class StaticTiers:
    """The same tiers for every question."""

    def __init__(self, tiers: Sequence[Tier], rescue: Sequence[Tier] = ()) -> None:
        self.tiers = tuple(tiers)
        self.rescue = tuple(rescue)

    def select(self, question: Question) -> tuple[Sequence[Tier], Sequence[Tier]]:
        return self.tiers, self.rescue

    def upstreams(self) -> list[Upstream]:
        return [upstream for tier in self.tiers + self.rescue for upstream in tier.upstreams]


@dataclass(slots=True)
class UpstreamHealth:
    label: str
    encrypted: bool
    tier: str
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    skipped_until: float = 0.0
    last_error: str = ""


@dataclass(slots=True)
class _Fetch:
    future: asyncio.Future[tuple[bytes, str, str]]
    task: asyncio.Task[None] | None = field(default=None)


class Forwarder:
    def __init__(
        self,
        tiers: Sequence[Tier] = (),
        *,
        rescue: Sequence[Tier] = (),
        policy: TierPolicy | None = None,
        ntp_names: Callable[[str], bool] | None = None,
        cache: DnsCache | None = None,
        deadline: float = DEFAULT_DEADLINE,
        breaker_threshold: int = 3,
        breaker_cooldown: float = 30.0,
        clock_window: float = DEFAULT_CLOCK_WINDOW,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy: TierPolicy = policy if policy is not None else StaticTiers(tiers, rescue)
        self.ntp_names = ntp_names
        self.cache = cache if cache is not None else DnsCache()
        self.deadline = deadline
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown = breaker_cooldown
        self.clock_window = clock_window
        self._clock = clock
        # id(upstream) -> (upstream, health); the upstream is kept so its id stays unique.
        self._health: dict[int, tuple[Upstream, UpstreamHealth]] = {}
        self._inflight: dict[Hashable, _Fetch] = {}
        self.active: UpstreamHealth | None = None  # the upstream that answered last
        self.clock_error_at: float | None = None  # last certificate time error (monotonic)

    @property
    def health(self) -> list[UpstreamHealth]:
        return [health for _upstream, health in self._health.values()]

    def _health_of(self, upstream: Upstream, tier: str) -> UpstreamHealth:
        entry = self._health.get(id(upstream))
        if entry is None:
            entry = self._health[id(upstream)] = (upstream, UpstreamHealth(upstream.label, upstream.encrypted, tier))
        return entry[1]

    def forget(self, upstreams: Iterable[Upstream]) -> None:
        """Drop the health records of upstreams the policy no longer uses."""
        for upstream in upstreams:
            self._health.pop(id(upstream), None)

    @property
    def clock_suspect(self) -> bool:
        """An encrypted upstream recently rejected a certificate's validity period."""
        return self.clock_error_at is not None and self._clock() - self.clock_error_at <= self.clock_window

    async def resolve(self, question: Question) -> Resolution:
        key = question.key
        hit = self.cache.get(key)
        if hit is not None:
            message, label, tier = hit
            return Resolution(message, label, cached=True, tier=tier)
        fetch = self._inflight.get(key)
        if fetch is None:
            loop = asyncio.get_running_loop()
            fetch = _Fetch(loop.create_future())
            fetch.future.add_done_callback(_consume_exception)
            self._inflight[key] = fetch
            fetch.task = loop.create_task(self._fetch(question, fetch))
        # shield: one caller giving up must not cancel the exchange for the others.
        wire, label, tier = await asyncio.shield(fetch.future)
        return Resolution(dns.message.from_wire(wire, ignore_trailing=True), label, tier=tier)

    async def _fetch(self, question: Question, fetch: _Fetch) -> None:
        try:
            async with asyncio.timeout(self.deadline):
                message, upstream, tier = await self._exchange(question)
            try:
                wire = message.to_wire(max_size=65535)
            except dns.exception.DNSException as exc:
                raise ResolveError(f"answer cannot be re-encoded: {type(exc).__name__}") from None
            self.cache.put(question.key, message, wire, upstream.label, tier)
            _settle(fetch.future, result=(wire, upstream.label, tier))
        except TimeoutError:
            _settle(fetch.future, error=ResolveError("deadline exceeded"))
        except ResolveError as exc:
            _settle(fetch.future, error=exc)
        except Exception as exc:  # never leave waiters hanging
            _settle(fetch.future, error=ResolveError(f"internal error: {type(exc).__name__}"))
        finally:
            if self._inflight.get(question.key) is fetch:
                del self._inflight[question.key]

    async def _exchange(self, question: Question) -> tuple[dns.message.Message, Upstream, str]:
        tiers, rescue = self.policy.select(question)
        if not any(tier.upstreams for tier in tiers):
            raise ResolveError("no upstream configured")
        errors: list[str] = []
        found = await self._try(tiers, question, errors)
        if found is None and self._rescue_allowed(question, rescue):
            found = await self._try(rescue, question, errors)
        if found is None:
            raise ResolveError("; ".join(errors))
        return found

    async def _try(self, tiers: Sequence[Tier], question: Question,
                   errors: list[str]) -> tuple[dns.message.Message, Upstream, str] | None:
        candidates = [(tier, upstream) for tier in tiers for upstream in tier.upstreams]
        now = self._clock()
        ready = [c for c in candidates if self._health_of(c[1], c[0].name).skipped_until <= now]
        for tier, upstream in ready or candidates:
            health = self._health_of(upstream, tier.name)
            try:
                message = await upstream.exchange(question)
            except UpstreamError as exc:
                if isinstance(exc, CertificateTimeError):
                    self.clock_error_at = self._clock()
                self._failed(health, str(exc))
                errors.append(f"{upstream.label}: {exc}")
                continue
            health.successes += 1
            health.consecutive_failures = 0
            health.skipped_until = 0.0
            self.active = health
            return message, upstream, tier.name
        return None

    def _rescue_allowed(self, question: Question, rescue: Sequence[Tier]) -> bool:
        return (any(tier.upstreams for tier in rescue) and self.ntp_names is not None and question.rdtype in RESCUE_TYPES
                and self.clock_suspect and self.ntp_names(question.name))

    def _failed(self, health: UpstreamHealth, error: str) -> None:
        health.failures += 1
        health.consecutive_failures += 1
        health.last_error = error
        if health.consecutive_failures >= self.breaker_threshold:
            health.skipped_until = self._clock() + self.breaker_cooldown

    def _all_upstreams(self) -> list[Upstream]:
        unique = {id(upstream): upstream for upstream in self.policy.upstreams()}
        return list(unique.values())

    def flush(self) -> None:
        """Forget cached answers, upstream failures and the clock suspicion."""
        self.cache.clear()
        self.clock_error_at = None
        for _upstream, health in self._health.values():
            health.consecutive_failures = 0
            health.skipped_until = 0.0

    async def reset(self) -> None:
        """Network change or resume: flush, and drop every connection pool.

        Lookups in flight are not failed; transports reconnect on next use.
        """
        self.flush()
        for upstream in self._all_upstreams():
            await upstream.close()

    async def close(self) -> None:
        """Fail pending lookups and drop every upstream connection."""
        for fetch in list(self._inflight.values()):
            if fetch.task is not None:
                fetch.task.cancel()
            _settle(fetch.future, error=ResolveError("shutting down"))
        tasks = [f.task for f in self._inflight.values() if f.task is not None]
        await asyncio.gather(*tasks, return_exceptions=True)
        self._inflight.clear()
        for upstream in self._all_upstreams():
            await upstream.close()


def _settle(future: asyncio.Future[Any], *, result: Any = None, error: BaseException | None = None) -> None:
    if future.done():
        return
    if error is not None:
        future.set_exception(error)
    else:
        future.set_result(result)


def _consume_exception(future: asyncio.Future[Any]) -> None:
    """Mark the exception as retrieved: callers that gave up never will."""
    if not future.cancelled():
        future.exception()
