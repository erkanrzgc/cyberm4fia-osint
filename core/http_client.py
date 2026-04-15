"""Async HTTP client with retry, proxy, and per-host rate limiting.

Notes
-----
- HTTP/HTTPS proxies are passed at request level so we can rotate per call.
- SOCKS proxies are bound at connector level because aiohttp does not
  support per-request SOCKS. To rotate SOCKS proxies callers should
  instantiate multiple HTTPClient objects.
- A per-host semaphore prevents hammering a single domain with the full
  MAX_CONCURRENT budget.
"""

from __future__ import annotations

import asyncio
import itertools
import time
from collections import defaultdict
from urllib.parse import urlparse

import aiohttp

from core.config import (
    MAX_CONCURRENT,
    PER_HOST_CONCURRENCY,
    REQUEST_TIMEOUT,
    RETRY_COUNT,
    RETRY_DELAY,
)
from core.logging_setup import get_logger
from modules.stealth import DomainRateBucket, fingerprint_headers, pick_ua
from modules.stealth.tor_control import CircuitRotator

log = get_logger(__name__)


class HTTPClient:
    def __init__(
        self,
        proxy: str | None = None,
        proxies: list[str] | None = None,
        tor: bool = False,
        request_timeout: int | None = None,
        *,
        fingerprint: bool = True,
        rate_bucket: DomainRateBucket | None = None,
        new_circuit_every: int = 0,
        tor_control_password: str | None = None,
    ) -> None:
        if tor:
            self.proxies = ["socks5://127.0.0.1:9050"]
        elif proxies:
            self.proxies = list(proxies)
        elif proxy:
            self.proxies = [proxy]
        else:
            self.proxies = []
        self._proxy_cycle = itertools.cycle(self.proxies) if self.proxies else None
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        self._host_semaphores: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(PER_HOST_CONCURRENCY)
        )
        self._session: aiohttp.ClientSession | None = None
        self._request_timeout = request_timeout or REQUEST_TIMEOUT
        self._fingerprint = fingerprint
        self._rate_bucket = rate_bucket if rate_bucket is not None else DomainRateBucket()
        self._rotator: CircuitRotator | None = (
            CircuitRotator(every=new_circuit_every, password=tor_control_password)
            if tor and new_circuit_every > 0
            else None
        )

    async def __aenter__(self) -> HTTPClient:
        timeout = aiohttp.ClientTimeout(total=self._request_timeout)
        if self.proxies and any(p.startswith("socks") for p in self.proxies):
            try:
                from aiohttp_socks import ProxyConnector
            except ImportError as exc:
                raise RuntimeError(
                    "SOCKS/Tor support requires aiohttp-socks. "
                    "Install with: pip install aiohttp-socks"
                ) from exc
            connector: aiohttp.BaseConnector = ProxyConnector.from_url(self.proxies[0])
        else:
            connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, ssl=False)
        self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        if self._session:
            await self._session.close()

    # ── helpers ────────────────────────────────────────────────

    def _next_http_proxy(self) -> str | None:
        """Return the next HTTP/HTTPS proxy; SOCKS handled at connector level."""
        if not self._proxy_cycle:
            return None
        proxy = next(self._proxy_cycle)
        return None if proxy.startswith("socks") else proxy

    def _require_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("HTTPClient must be used as an async context manager")
        return self._session

    def _headers(self, extra: dict | None = None) -> dict:
        ua_entry = pick_ua()
        if self._fingerprint:
            merged: dict = dict(fingerprint_headers(ua_entry))
        else:
            merged = {
                "User-Agent": ua_entry.ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        if extra:
            merged.update(extra)
        return merged

    def _host(self, url: str) -> str:
        return urlparse(url).netloc or url

    def _host_lock(self, url: str) -> asyncio.Semaphore:
        return self._host_semaphores[self._host(url)]

    async def _acquire(self, url: str) -> tuple[asyncio.Semaphore, asyncio.Semaphore]:
        host_lock = self._host_lock(url)
        await self._semaphore.acquire()
        await host_lock.acquire()
        await self._rate_bucket.acquire(self._host(url))
        return self._semaphore, host_lock

    @staticmethod
    def _retry_after(resp: aiohttp.ClientResponse) -> float | None:
        raw = resp.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    async def _post_request(self, url: str, status: int, resp: aiohttp.ClientResponse | None) -> None:
        host = self._host(url)
        if status in (429, 503):
            retry_after = self._retry_after(resp) if resp is not None else None
            await self._rate_bucket.record_throttled(host, retry_after=retry_after)
        elif 200 <= status < 400:
            await self._rate_bucket.record_success(host)
        if self._rotator is not None:
            await self._rotator.tick()

    # ── request methods ────────────────────────────────────────

    async def get(
        self,
        url: str,
        headers: dict | None = None,
        allow_redirects: bool = True,
    ) -> tuple[int, str, float]:
        session = self._require_session()
        merged = self._headers(headers)
        global_lock, host_lock = await self._acquire(url)
        try:
            for attempt in range(RETRY_COUNT + 1):
                start = time.monotonic()
                try:
                    async with session.get(
                        url,
                        headers=merged,
                        allow_redirects=allow_redirects,
                        proxy=self._next_http_proxy(),
                    ) as resp:
                        elapsed = time.monotonic() - start
                        body = await resp.text(errors="replace")
                        await self._post_request(url, resp.status, resp)
                        return resp.status, body, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug("timeout on %s (attempt %d)", url, attempt + 1)
                    if attempt == RETRY_COUNT:
                        return 0, "", elapsed
                except (aiohttp.ClientError, OSError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug("network error on %s: %s", url, exc)
                    if attempt == RETRY_COUNT:
                        return -1, "", elapsed
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
            return -1, "", 0.0
        finally:
            host_lock.release()
            global_lock.release()

    async def get_json(
        self, url: str, headers: dict | None = None
    ) -> tuple[int, dict | None, float]:
        session = self._require_session()
        merged = self._headers(headers)
        merged["Accept"] = "application/json"
        global_lock, host_lock = await self._acquire(url)
        try:
            for attempt in range(RETRY_COUNT + 1):
                start = time.monotonic()
                try:
                    async with session.get(
                        url,
                        headers=merged,
                        proxy=self._next_http_proxy(),
                    ) as resp:
                        elapsed = time.monotonic() - start
                        await self._post_request(url, resp.status, resp)
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            return resp.status, data, elapsed
                        return resp.status, None, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    log.debug("json timeout on %s", url)
                    if attempt == RETRY_COUNT:
                        return 0, None, elapsed
                except (aiohttp.ClientError, OSError, ValueError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug("json error on %s: %s", url, exc)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
            return -1, None, 0.0
        finally:
            host_lock.release()
            global_lock.release()

    async def get_bytes(
        self, url: str, headers: dict | None = None
    ) -> tuple[int, bytes | None, float]:
        session = self._require_session()
        merged = self._headers(headers)
        global_lock, host_lock = await self._acquire(url)
        try:
            for attempt in range(RETRY_COUNT + 1):
                start = time.monotonic()
                try:
                    async with session.get(
                        url,
                        headers=merged,
                        proxy=self._next_http_proxy(),
                    ) as resp:
                        elapsed = time.monotonic() - start
                        await self._post_request(url, resp.status, resp)
                        if resp.status == 200:
                            data = await resp.read()
                            return resp.status, data, elapsed
                        return resp.status, None, elapsed
                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    if attempt == RETRY_COUNT:
                        return 0, None, elapsed
                except (aiohttp.ClientError, OSError) as exc:
                    elapsed = time.monotonic() - start
                    log.debug("bytes error on %s: %s", url, exc)
                    if attempt == RETRY_COUNT:
                        return -1, None, elapsed
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
            return -1, None, 0.0
        finally:
            host_lock.release()
            global_lock.release()
