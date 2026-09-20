import asyncio
import logging
import random
import re
import ssl
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple, Union

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("ProxyPool")

# httpx/httpcore 会把每一个请求都按 INFO 打出来。校验动辄几万个节点时，
# 光是写日志就能拖慢整轮刷新，这里压到 WARNING。
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# 1. 代理抓取源配置
# ---------------------------------------------------------------------------
# 实测：国内网络直连 raw.githubusercontent.com / api.proxyscrape.com 基本必然超时
# （12 个源里 11 个超时，只剩一个能返回 400 条），所以 GitHub 上的列表统一改走
# jsDelivr CDN 主通道，ghproxy 与 raw 依次兜底。改成镜像后 12 个源全部 1 秒内返回。
GITHUB_MIRRORS = (
    "https://cdn.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}",
    "https://ghproxy.net/https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}",
    "https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}",
)

# 字符串 = 直接可用的 URL；(user, repo, branch, path) = GitHub 源，会展开成多个镜像依次尝试
PROXY_SOURCES = {
    "http": [
        ("TheSpeedX", "PROXY-List", "master", "http.txt"),
        ("monosans", "proxy-list", "main", "proxies/http.txt"),
        ("iplocate", "free-proxy-list", "main", "protocols/http.txt"),
        ("ShiftyTR", "Proxy-List", "master", "http.txt"),
        ("clarketm", "proxy-list", "master", "proxy-list-raw.txt"),
        "https://openproxylist.xyz/http.txt",
    ],
    # 注意：httpx 不支持 socks4://（会直接抛 ValueError: Unknown scheme for proxy URL），
    # 所以不再抓取 socks4 列表 —— 那几千个节点是必然校验失败的纯浪费。
    "socks5": [
        ("TheSpeedX", "PROXY-List", "master", "socks5.txt"),
        ("monosans", "proxy-list", "main", "proxies/socks5.txt"),
        ("iplocate", "free-proxy-list", "main", "protocols/socks5.txt"),
        ("ShiftyTR", "Proxy-List", "master", "socks5.txt"),
        "https://openproxylist.xyz/socks5.txt",
    ],
}


def expand_source(spec: Union[str, Tuple[str, str, str, str]]) -> List[str]:
    """把源配置展开成候选 URL：GitHub 源展开成多个镜像，按顺序取第一个可用的"""
    if isinstance(spec, str):
        return [spec]
    user, repo, branch, path = spec
    return [m.format(user=user, repo=repo, branch=branch, path=path) for m in GITHUB_MIRRORS]


# 正则匹配 IP:Port
IP_PORT_REGEX = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})")

# ---------------------------------------------------------------------------
# 2. 性能与调度参数
# ---------------------------------------------------------------------------
TARGET_VALID_PROXIES = 100      # 有效代理累计到该数量就结束本轮（提前停止，不再往下测）
MAX_CONCURRENT_CHECKS = 300     # 校验并发数（同时打开的代理连接数）
CHECK_CONNECT_TIMEOUT = 2.0     # 建连超时：绝大部分死代理都卡在这一步，调短收益最大
CHECK_READ_TIMEOUT = 6.0        # 建连成功后的读超时；https 校验时 CONNECT 隧道 + TLS 握手都算在这里，需比纯 http 宽松
SCRAPE_TIMEOUT = 6.0            # 单个抓取源超时（每个源可能还要在镜像间重试）
QUEUE_MAXSIZE = 5000            # 抓取与校验之间的缓冲队列长度
PROGRESS_EVERY = 200            # 每校验多少个节点打印一次进度

# 校验目标地址，按顺序尝试，第一个能测出结果的就用它。
# 优先用 CDN 的 204 探测点：响应体几乎为空、全球可达、容量大，
# 比 httpbin.org 这种单点服务快得多，也不会在几百并发下被限流误判。
# 用 https:// 校验：代理需要支持 CONNECT 隧道才能通过，通过校验的代理
# 对 http/https 目标都可用。注意这会筛掉只支持明文转发的代理，
# 有效数量会比 http 校验少不少；若更看重数量可改回 http://。
CHECK_URLS = [
    "https://www.google.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://httpbin.org/ip",
]
OK_STATUS_CODES = (200, 204)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# 3. 代理池核心管理类
# ---------------------------------------------------------------------------
class ProxyItem(BaseModel):
    proxy: str          # 协议://IP:Port
    protocol: str       # http, socks4, socks5
    latency: float      # 响应延迟 (秒)
    last_check: float   # 上次校验时间戳

class ProxyPoolManager:
    def __init__(self):
        # 内部存储格式: { "http://1.2.3.4:8080": ProxyItem(...) }
        self.pool: Dict[str, ProxyItem] = {}
        self.is_refreshing: bool = False
        self.last_refresh_time: Optional[float] = None

        # 校验参数
        self.target_valid = TARGET_VALID_PROXIES
        self.max_concurrent_checks = MAX_CONCURRENT_CHECKS
        self.check_timeout = httpx.Timeout(CHECK_READ_TIMEOUT, connect=CHECK_CONNECT_TIMEOUT)
        # SSLContext / Limits 复用同一份：httpx 的 Client 构造是同步代码，会直接阻塞事件循环，
        # 校验几万个节点时这部分固定开销相当可观，能省则省。
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        self._client_limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)

        # 本轮校验的统计信息（避免逐条刷屏的同时不丢失线索）
        self.check_errors: Dict[str, int] = {}
        self.last_check_url: Optional[str] = None
        self.last_round_stats: Dict[str, Any] = {}

    def record_error(self, msg: str):
        """按异常类型归类统计校验失败原因"""
        key = msg.split(":")[0]
        self.check_errors[key] = self.check_errors.get(key, 0) + 1

    async def fetch_source(self, client: httpx.AsyncClient, protocol: str, spec: Union[str, Tuple[str, str, str, str]]) -> Set[str]:
        """抓取单个源；GitHub 源会在镜像之间依次重试，命中第一个可用的就返回"""
        proxies: Set[str] = set()
        for url in expand_source(spec):
            try:
                resp = await client.get(url, timeout=SCRAPE_TIMEOUT)
                if resp.status_code == 200:
                    for ip, port in IP_PORT_REGEX.findall(resp.text):
                        proxies.add(f"{protocol}://{ip}:{port}")
                    return proxies
                logger.warning(f"抓取代理源返回 {resp.status_code} [{protocol}] {url}")
            except Exception as e:
                logger.warning(f"抓取代理源失败 [{protocol}] {url}: {type(e).__name__}")
        return proxies

    # -- 数据喂入 ----------------------------------------------------------
    async def _feed_stream(self, bootstrap: List[str], collected: Set[str]) -> AsyncIterator[str]:
        """边抓边喂：先把池内已有代理喂进去（大概率仍有效，最快凑满目标），再并发抓取各源"""
        seen: Set[str] = set()
        for proxy_str in bootstrap:
            seen.add(proxy_str)
            collected.add(proxy_str)
            yield proxy_str

        tasks: List[asyncio.Task] = []
        try:
            async with httpx.AsyncClient(
                timeout=SCRAPE_TIMEOUT,
                trust_env=False,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                for proto, specs in PROXY_SOURCES.items():
                    for spec in specs:
                        tasks.append(asyncio.create_task(self.fetch_source(client, proto, spec)))
                # as_completed：哪个源先返回就先校验哪个，不用等最慢的源
                for fut in asyncio.as_completed(tasks):
                    found = list(await fut)
                    # 打散顺序，避免某条源的过期数据把队列头占满
                    random.shuffle(found)
                    for proxy_str in found:
                        if proxy_str in seen:
                            continue
                        seen.add(proxy_str)
                        collected.add(proxy_str)
                        yield proxy_str
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _feed_cached(self, bootstrap: List[str], collected: Set[str]) -> AsyncIterator[str]:
        """备用校验地址重试：直接复用已抓到的节点，不再重新下载一遍（省一次抓取开销）"""
        for proxy_str in list(collected) or bootstrap:
            yield proxy_str

    # -- 校验 --------------------------------------------------------------
    async def check_proxy(self, proxy_str: str, check_url: str) -> Optional[ProxyItem]:
        """校验单个代理的连通性与延迟"""
        protocol = proxy_str.split("://")[0]
        start_time = time.perf_counter()
        try:
            # httpx>=0.28 已移除"按请求指定 proxy"的能力，每个代理只能各建一个 Client；
            # 但 SSLContext / Limits / 超时对象都在实例上复用，构造开销降到最低。
            async with httpx.AsyncClient(
                proxy=proxy_str,
                timeout=self.check_timeout,
                verify=self._ssl_context,
                trust_env=False,         # 忽略系统环境变量里的代理，避免干扰校验结果
                follow_redirects=False,  # 只验证连通性，没必要跟随跳转多跑一趟
                limits=self._client_limits,
            ) as client:
                resp = await client.get(check_url)
                if resp.status_code in OK_STATUS_CODES:
                    return ProxyItem(
                        proxy=proxy_str,
                        protocol=protocol,
                        latency=round(time.perf_counter() - start_time, 3),
                        last_check=time.time()
                    )
                self.record_error(f"HTTPStatus:{resp.status_code}")
        except Exception as e:
            self.record_error(type(e).__name__)
        return None

    async def _run_pass(self, feed: AsyncIterator[str], check_url: str) -> Dict[str, ProxyItem]:
        """流水线单轮：抓取与校验同时进行，凑满 target_valid 立即收工"""
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        stop_event = asyncio.Event()      # 已凑满目标 -> 通知所有 worker 下班
        producer_done = asyncio.Event()   # 抓取结束 -> worker 排空队列后自行退出
        valid: Dict[str, ProxyItem] = {}
        stats = {"checked": 0, "start": time.perf_counter(), "stopped_early": False}
        self.check_errors = {}

        async def produce():
            try:
                async for proxy_str in feed:
                    if stop_event.is_set():
                        break
                    # 队列满时在这里反压，天然限流，不会把几万个节点全堆进内存任务里
                    await queue.put(proxy_str)
            except Exception as e:
                logger.error(f"抓取代理源时发生异常: {e}", exc_info=True)
            finally:
                producer_done.set()
                await feed.aclose()

        async def consume():
            while True:
                try:
                    proxy_str = await asyncio.wait_for(queue.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    if producer_done.is_set() and queue.empty():
                        return
                    continue
                if stop_event.is_set():
                    # 已凑满目标：继续排空队列但不再校验。
                    # 注意不能直接 return —— 生产者可能正卡在 queue.put() 上，
                    # 没人消费的话会死锁，导致整轮永远结束不了。
                    continue
                item = await self.check_proxy(proxy_str, check_url)
                stats["checked"] += 1
                if item is not None:
                    valid[item.proxy] = item
                    # 增量写入池子：首轮启动时不必等整轮结束，/get 立即可用；
                    # 后续轮次也能即时刷新延迟数据。失效节点仍靠轮末的整体替换清理。
                    self.pool[item.proxy] = item
                    if len(valid) >= self.target_valid:
                        stats["stopped_early"] = True
                        stop_event.set()
                        return
                if stats["checked"] % PROGRESS_EVERY == 0:
                    logger.info(
                        f"校验进度: 已测 {stats['checked']} 个, 有效 {len(valid)} 个 "
                        f"(目标 {self.target_valid})"
                    )

        workers = [asyncio.create_task(consume()) for _ in range(self.max_concurrent_checks)]
        _t0 = time.perf_counter()
        await produce()
        _t1 = time.perf_counter()
        print(f"[phase] produce done after {_t1-_t0:.2f}s, queue={queue.qsize()}, stop={stop_event.is_set()}", flush=True)
        await asyncio.gather(*workers)
        print(f"[phase] workers done after {time.perf_counter()-_t1:.2f}s", flush=True)

        duration = time.perf_counter() - stats["start"]
        speed = stats["checked"] / duration if duration > 0 else 0.0
        self.last_round_stats = {
            "check_url": check_url,
            "checked": stats["checked"],
            "valid": len(valid),
            "duration": round(duration, 1),
            "speed": round(speed, 1),
            "stopped_early": stats["stopped_early"],
        }
        logger.info(
            f"本轮校验完成: 共测 {stats['checked']} 个节点, 有效 {len(valid)} 个, "
            f"耗时 {duration:.1f}s ({speed:.1f} 个/秒)"
            + ("，已达目标提前结束" if stats["stopped_early"] else "")
        )
        return valid

    async def refresh_round(self) -> Dict[str, ProxyItem]:
        """一整轮：抓取 + 校验。若当前校验地址一个都测不出来，则换备用地址重试。"""
        collected: Set[str] = set()
        bootstrap = list(self.pool.keys())
        result: Dict[str, ProxyItem] = {}
        for idx, check_url in enumerate(CHECK_URLS):
            feed = (
                self._feed_stream(bootstrap, collected)
                if idx == 0
                else self._feed_cached(bootstrap, collected)
            )
            result = await self._run_pass(feed, check_url)
            self.last_check_url = check_url
            if result or idx == len(CHECK_URLS) - 1:
                break
            logger.warning(
                f"校验目标 {check_url} 一个有效代理都没测出来，疑似被代理网络屏蔽，"
                f"改用备用地址重试..."
            )
        return result

    async def refresh_job(self):
        """定时任务：抓取 + 校验清理"""
        if self.is_refreshing:
            logger.info("上一次刷新任务尚未结束，跳过本次执行。")
            return

        self.is_refreshing = True
        try:
            logger.info(f"开始刷新代理池 (目标 {self.target_valid} 个有效代理)...")
            new_pool = await self.refresh_round()
            if new_pool:
                self.pool = new_pool
                self.last_refresh_time = time.time()
            else:
                # 一个都没测出来时保留旧池，避免一次网络抖动把可用代理全清空
                logger.warning("本轮未校验出任何有效代理，保留原有代理池不做替换。")
            if self.check_errors:
                top = sorted(self.check_errors.items(), key=lambda kv: -kv[1])[:5]
                summary = ", ".join(f"{k} ×{v}" for k, v in top)
                logger.warning(f"校验失败原因 TOP: {summary}")
            logger.info(f"清理并更新完成！当前可用代理总数: {len(self.pool)}")
        except Exception as e:
            logger.error(f"定时刷新任务发生异常: {e}", exc_info=True)
        finally:
            self.is_refreshing = False

    def get_random_proxy(self, protocol: Optional[str] = None) -> ProxyItem:
        """从池中获取一个随机代理"""
        candidates = list(self.pool.values())
        if protocol:
            candidates = [p for p in candidates if p.protocol.lower() == protocol.lower()]
        
        if not candidates:
            raise HTTPException(status_code=404, detail="代理池为空或没有满足条件的可用代理")
        
        return random.choice(candidates)

    def pop_proxy(self, protocol: Optional[str] = None) -> ProxyItem:
        """获取并弹出（移除）一个代理"""
        item = self.get_random_proxy(protocol)
        self.pool.pop(item.proxy, None)
        return item

# 实例化全局单例
proxy_manager = ProxyPoolManager()
scheduler = AsyncIOScheduler()

# ---------------------------------------------------------------------------
# 4. FastAPI 生命周期与定时任务控制
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 服务启动：添加定时任务 (例如每 15 分钟抓取与清理一次)
    scheduler.add_job(proxy_manager.refresh_job, 'interval', minutes=15, id="refresh_proxies")
    scheduler.start()
    
    # 服务启动后后台触发一次首次抓取
    asyncio.create_task(proxy_manager.refresh_job())
    logger.info("代理池服务成功启动，已开始首次异步抓取...")
    
    yield
    
    # 服务关闭：停止调度器
    scheduler.shutdown()
    logger.info("代理池服务已关闭")

app = FastAPI(
    title="Proxy Scraper & Pool API",
    description="定时抓取、定时校验清理并提供代理获取接口的 Web 服务",
    version="1.0.0",
    lifespan=lifespan
)

# ---------------------------------------------------------------------------
# 5. API 路由定义
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "status": "online",
        "total_proxies": len(proxy_manager.pool),
        "last_refresh_time": proxy_manager.last_refresh_time,
        "endpoints": {
            "get_one": "/get?protocol=http",
            "pop_one": "/pop?protocol=http",
            "get_all": "/all",
            "stats": "/stats",
            "trigger_refresh": "/refresh [POST]"
        }
    }

@app.get("/get", response_model=dict, summary="获取一个可用代理")
def get_proxy(protocol: Optional[str] = Query(None, description="筛选协议: http, socks4, socks5")):
    """每次调用随机返回一个可用代理节点"""
    return proxy_manager.get_random_proxy(protocol).model_dump()

@app.get("/pop", response_model=dict, summary="获取并弹出一个代理")
def pop_proxy(protocol: Optional[str] = Query(None, description="筛选协议: http, socks4, socks5")):
    """获取一个代理并将该代理从当前池中移除，避免重复使用"""
    return proxy_manager.pop_proxy(protocol).model_dump()

@app.get("/all", response_model=List[dict], summary="获取所有可用代理")
def get_all_proxies(protocol: Optional[str] = Query(None, description="筛选协议: http, socks4, socks5")):
    """返回当前池内所有正常工作的代理列表"""
    items = list(proxy_manager.pool.values())
    if protocol:
        items = [p for p in items if p.protocol.lower() == protocol.lower()]
    return [item.model_dump() for item in items]

@app.get("/stats", summary="获取统计数据")
def get_stats():
    """获取代理池状态统计"""
    stats = {"http": 0, "socks4": 0, "socks5": 0}
    for item in proxy_manager.pool.values():
        if item.protocol in stats:
            stats[item.protocol] += 1
        else:
            stats[item.protocol] = 1
            
    return {
        "total": len(proxy_manager.pool),
        "target": proxy_manager.target_valid,
        "protocol_breakdown": stats,
        "is_refreshing": proxy_manager.is_refreshing,
        "last_refresh_time": proxy_manager.last_refresh_time,
        "last_round": proxy_manager.last_round_stats,
        "last_check_errors": proxy_manager.check_errors
    }

@app.post("/refresh", summary="手动触发清理与刷新")
async def trigger_refresh():
    """立即在后台启动一次代理抓取与校验清理任务"""
    if proxy_manager.is_refreshing:
        return {"status": "already_running", "message": "刷新任务正在进行中"}
    
    asyncio.create_task(proxy_manager.refresh_job())
    return {"status": "started", "message": "已在后台启动刷新任务"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8002, reload=True)