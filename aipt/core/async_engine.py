import asyncio
import aiohttp
import aiofiles
import time
import hashlib
import random
import ssl
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
import logging

from .config import Config, ProxyConfig
from .models import Endpoint, Form


@dataclass
class RequestContext:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, Any]] = None
    json_data: Optional[Dict[str, Any]] = None
    params: Optional[Dict[str, str]] = None
    timeout: float = 15.0
    allow_redirects: bool = True
    max_redirects: int = 5
    retry_count: int = 0
    max_retries: int = 3
    proxy: Optional[str] = None
    priority: int = 5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseContext:
    url: str
    status: int
    headers: Dict[str, str]
    text: str
    content: bytes
    content_length: int
    content_hash: str
    response_time: float
    request: RequestContext
    cookies: Dict[str, str]
    history: List[Tuple[int, str]] = field(default_factory=list)
    is_error: bool = False
    error_message: str = ""

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status < 500

    @property
    def is_server_error(self) -> bool:
        return self.status >= 500


class RateLimiter:
    def __init__(self, rate: float = 0.1, adaptive: bool = True):
        self.rate = rate
        self.adaptive = adaptive
        self.min_rate = 0.01
        self.max_rate = 2.0
        self.error_count = 0
        self.success_count = 0
        self.last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_request_time
            if elapsed < self.rate:
                await asyncio.sleep(self.rate - elapsed)
            self.last_request_time = time.time()

    def report_success(self):
        self.success_count += 1
        if self.adaptive and self.success_count > 10:
            self.rate = max(self.min_rate, self.rate * 0.95)
            self.success_count = 0

    def report_error(self):
        self.error_count += 1
        if self.adaptive:
            self.rate = min(self.max_rate, self.rate * 1.5)
            self.error_count = 0


class ProxyRotator:
    def __init__(self, config: ProxyConfig):
        self.proxies = config.proxies
        self.rotation_strategy = config.rotation_strategy
        self.rotation_interval = config.rotation_interval
        self.max_failures = config.max_failures
        self.cooldown_period = config.cooldown_period
        self._current_index = 0
        self._failure_counts: Dict[str, int] = {}
        self._cooldown_until: Dict[str, float] = {}
        self._request_counts: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None

        async with self._lock:
            now = time.time()
            available = [
                p for p in self.proxies
                if self._failure_counts.get(p, 0) < self.max_failures
                and self._cooldown_until.get(p, 0) < now
            ]

            if not available:
                self._failure_counts.clear()
                self._cooldown_until.clear()
                available = self.proxies

            if self.rotation_strategy == "round_robin":
                proxy = available[self._current_index % len(available)]
                self._current_index += 1
            elif self.rotation_strategy == "random":
                proxy = random.choice(available)
            elif self.rotation_strategy == "least_used":
                proxy = min(available, key=lambda p: self._request_counts.get(p, 0))
            else:
                proxy = available[0]

            self._request_counts[proxy] = self._request_counts.get(proxy, 0) + 1
            return proxy

    async def report_failure(self, proxy: str):
        async with self._lock:
            self._failure_counts[proxy] = self._failure_counts.get(proxy, 0) + 1
            if self._failure_counts[proxy] >= self.max_failures:
                self._cooldown_until[proxy] = time.time() + self.cooldown_period

    async def report_success(self, proxy: str):
        async with self._lock:
            self._failure_counts[proxy] = max(0, self._failure_counts.get(proxy, 0) - 1)


class AsyncHTTPClient:
    def __init__(self, config: Config):
        self.config = config
        self.rate_limiter = RateLimiter(
            rate=config.scan.rate_limit,
            adaptive=config.scan.adaptive_rate_limit
        )
        self.proxy_rotator = ProxyRotator(config.proxy) if config.proxy.enabled else None
        self.session: Optional[aiohttp.ClientSession] = None
        self.connector: Optional[aiohttp.TCPConnector] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._default_headers = {
            "User-Agent": config.scan.headers.get("User-Agent", self._get_random_ua()),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        self._default_headers.update(config.scan.headers)
        self.logger = logging.getLogger(__name__)

    def _get_random_ua(self) -> str:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ]
        return random.choice(user_agents)

    async def __aenter__(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        self.connector = aiohttp.TCPConnector(
            limit=self.config.scan.connection_pool_size,
            limit_per_host=50,
            enable_cleanup_closed=True,
            force_close=False,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )

        timeout = aiohttp.ClientTimeout(total=self.config.scan.request_timeout)

        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers=self._default_headers,
            cookie_jar=aiohttp.CookieJar(),
        )

        self._semaphore = asyncio.Semaphore(self.config.scan.concurrency)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()

    async def request(self, ctx: RequestContext) -> ResponseContext:
        async with self._semaphore:
            await self.rate_limiter.acquire()

            proxy = ctx.proxy or (await self.proxy_rotator.get_proxy() if self.proxy_rotator else None)

            start_time = time.time()
            try:
                kwargs = {
                    "headers": ctx.headers,
                    "allow_redirects": ctx.allow_redirects,
                    "max_redirects": ctx.max_redirects,
                    "timeout": aiohttp.ClientTimeout(total=ctx.timeout),
                }

                if proxy:
                    kwargs["proxy"] = proxy

                if ctx.params:
                    kwargs["params"] = ctx.params

                if ctx.data:
                    kwargs["data"] = ctx.data

                if ctx.json_data:
                    kwargs["json"] = ctx.json_data

                async with self.session.request(ctx.method, ctx.url, **kwargs) as response:
                    content = await response.read()
                    text = content.decode('utf-8', errors='ignore')
                    content_hash = hashlib.md5(content).hexdigest()
                    response_time = time.time() - start_time

                    history = [(r.status, str(r.url)) for r in response.history]

                    resp_ctx = ResponseContext(
                        url=str(response.url),
                        status=response.status,
                        headers=dict(response.headers),
                        text=text,
                        content=content,
                        content_length=len(content),
                        content_hash=content_hash,
                        response_time=response_time,
                        request=ctx,
                        cookies={k: v.value for k, v in response.cookies.items()},
                        history=history,
                    )

                    self.rate_limiter.report_success()
                    if proxy and self.proxy_rotator:
                        await self.proxy_rotator.report_success(proxy)

                    return resp_ctx

            except asyncio.TimeoutError:
                self.rate_limiter.report_error()
                if proxy and self.proxy_rotator:
                    await self.proxy_rotator.report_failure(proxy)
                return self._create_error_response(ctx, "Request timeout", start_time)

            except aiohttp.ClientError as e:
                self.rate_limiter.report_error()
                if proxy and self.proxy_rotator:
                    await self.proxy_rotator.report_failure(proxy)
                return self._create_error_response(ctx, str(e), start_time)

            except Exception as e:
                self.rate_limiter.report_error()
                return self._create_error_response(ctx, f"Unexpected error: {e}", start_time)

    def _create_error_response(self, ctx: RequestContext, error_msg: str, start_time: float) -> ResponseContext:
        return ResponseContext(
            url=ctx.url,
            status=0,
            headers={},
            text="",
            content=b"",
            content_length=0,
            content_hash="",
            response_time=time.time() - start_time,
            request=ctx,
            cookies={},
            is_error=True,
            error_message=error_msg,
        )

    async def get(self, url: str, **kwargs) -> ResponseContext:
        ctx = RequestContext(url=url, method="GET", **kwargs)
        return await self.request(ctx)

    async def post(self, url: str, **kwargs) -> ResponseContext:
        ctx = RequestContext(url=url, method="POST", **kwargs)
        return await self.request(ctx)


class AsyncCrawler:
    def __init__(self, client: AsyncHTTPClient, config: Config):
        self.client = client
        self.config = config
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Form] = []
        self.discovered_endpoints: List[Endpoint] = []
        self._url_queue: asyncio.Queue = asyncio.Queue()
        self._visited_urls: Set[str] = set()
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger(__name__)

    async def crawl(self, start_url: str, max_depth: int = 3) -> Tuple[Set[str], List[Form], List[Endpoint]]:
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

        await self._url_queue.put((start_url, 0))
        self.discovered_urls.add(start_url)

        workers = []
        for _ in range(min(10, self.config.scan.concurrency // 10)):
            worker = asyncio.create_task(self._crawl_worker(base_domain, max_depth))
            workers.append(worker)

        await self._url_queue.join()

        for worker in workers:
            worker.cancel()

        await asyncio.gather(*workers, return_exceptions=True)

        return self.discovered_urls, self.discovered_forms, self.discovered_endpoints

    async def _crawl_worker(self, base_domain: str, max_depth: int):
        while True:
            try:
                url, depth = await asyncio.wait_for(self._url_queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                break

            try:
                if depth > max_depth:
                    continue

                async with self._lock:
                    if url in self._visited_urls:
                        continue
                    self._visited_urls.add(url)

                response = await self.client.get(url)

                if response.is_error or not response.is_success:
                    continue

                endpoint = Endpoint(
                    url=response.url,
                    method="GET",
                    response_status=response.status,
                    response_size=response.content_length,
                    response_hash=response.content_hash,
                    headers=response.headers,
                    content_type=response.headers.get("Content-Type", ""),
                )

                if self._is_api_endpoint(response):
                    endpoint.is_api = True
                if self._is_graphql_endpoint(response):
                    endpoint.is_graphql = True

                async with self._lock:
                    self.discovered_endpoints.append(endpoint)

                content_type = response.headers.get("Content-Type", "").lower()

                if "text/html" in content_type:
                    await self._parse_html(response.url, response.text, base_domain, depth)
                elif "application/json" in content_type:
                    await self._parse_json_api(response.url, response.text)

            except Exception as e:
                self.logger.error(f"Crawl error for {url}: {e}")
            finally:
                self._url_queue.task_done()

    async def _parse_html(self, base_url: str, html: str, base_domain: str, depth: int):
        soup = BeautifulSoup(html, 'lxml')

        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(base_url, link['href'])
            if self._should_crawl(absolute_url, base_domain):
                async with self._lock:
                    if absolute_url not in self.discovered_urls:
                        self.discovered_urls.add(absolute_url)
                        await self._url_queue.put((absolute_url, depth + 1))

        for form in soup.find_all('form'):
            form_data = Form(
                url=base_url,
                action=urljoin(base_url, form.get('action', '')),
                method=form.get('method', 'get').upper(),
                enctype=form.get('enctype', ''),
                id=form.get('id'),
                name=form.get('name'),
                inputs=[]
            )

            for inp in form.find_all(['input', 'textarea', 'select']):
                form_data.inputs.append({
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', ''),
                    'id': inp.get('id', ''),
                    'required': inp.get('required') is not None,
                })

            async with self._lock:
                self.discovered_forms.append(form_data)

        for script in soup.find_all('script', src=True):
            script_url = urljoin(base_url, script['src'])
            if self._should_crawl(script_url, base_domain):
                async with self._lock:
                    if script_url not in self.discovered_urls:
                        self.discovered_urls.add(script_url)

        for link in soup.find_all('link', href=True):
            if link.get('rel') in [['stylesheet'], ['icon']]:
                resource_url = urljoin(base_url, link['href'])
                if self._should_crawl(resource_url, base_domain):
                    async with self._lock:
                        if resource_url not in self.discovered_urls:
                            self.discovered_urls.add(resource_url)

    async def _parse_json_api(self, url: str, json_text: str):
        try:
            import json
            data = json.loads(json_text)
            if isinstance(data, dict):
                endpoint = Endpoint(
                    url=url,
                    method="GET",
                    is_api=True,
                    content_type="application/json",
                )
                async with self._lock:
                    self.discovered_endpoints.append(endpoint)
        except:
            pass

    def _should_crawl(self, url: str, base_domain: str) -> bool:
        parsed = urlparse(url)
        if parsed.netloc != base_domain:
            return False
        if parsed.scheme not in ('http', 'https'):
            return False
        if any(url.endswith(ext) for ext in ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.woff', '.woff2', '.ttf']):
            return False
        if len(self.discovered_urls) >= self.config.scan.max_urls:
            return False
        return True

    def _is_api_endpoint(self, response: ResponseContext) -> bool:
        content_type = response.headers.get("Content-Type", "").lower()
        return any(ct in content_type for ct in ["application/json", "application/xml", "application/graphql"])

    def _is_graphql_endpoint(self, response: ResponseContext) -> bool:
        if "graphql" in response.url.lower():
            return True
        content_type = response.headers.get("Content-Type", "").lower()
        return "application/graphql" in content_type
