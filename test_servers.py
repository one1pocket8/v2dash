import re
import os
import json
import time
import base64
import socket
import subprocess
import urllib.request
from urllib.parse import parse_qsl
import concurrent.futures
import threading

TIMEOUT       = 4       # tcp connect timeout (s)
WORKERS       = 80      # tcp prefilter concurrency
REAL_WORKERS  = 12      # real-proxy-test concurrency (each spawns a process)
TOP_N         = 10      # final servers kept per provider
REAL_TEST_N   = 30      # how many tcp-reachable finalists get the real test
TEST_LIMIT    = 200     # how many raw candidates get the tcp prefilter
TEST_URL      = "http://www.gstatic.com/generate_204"
XRAY_BIN      = os.environ.get("XRAY_BIN", "/tmp/xray/xray")
HAS_XRAY      = os.path.isfile(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK)

PROVIDERS = [
    {"name": "Epodonios",     "slug": "epo",      "path": "/tmp/epodonios_all.txt"},
    {"name": "MatinGhanbari", "slug": "matin",     "path": "/tmp/matin_all.txt"},
    {"name": "F0rc3Run",      "slug": "f0rc3run",  "path": "/tmp/f0rc3run_all.txt"},
    {"name": "RoosterKid",    "slug": "rooster",   "path": "/tmp/rooster_all.txt"},
]

URI_RE = re.compile(r'(?:vless|vmess|trojan|ss)://\S+')


# ── fetch / extract ──

def extract_configs(raw_text):
    """Pull config URIs out of a line regardless of leading flag emoji or
    trailing 'responsetime country [isp]' metadata glued onto the line."""
    return URI_RE.findall(raw_text)


def load_raw(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def split_host_port(s, default_port=443):
    if s.startswith('['):
        m = re.match(r'\[([^\]]+)\](?::(\d+))?', s)
        return (m.group(1), int(m.group(2)) if m.group(2) else default_port) if m else (None, None)
    if ':' in s:
        h, p = s.rsplit(':', 1)
        try:
            return h, int(p)
        except ValueError:
            return s, default_port
    return s, default_port


def extract_host_port(uri):
    try:
        if uri.startswith('vmess://'):
            b64 = uri[8:].split('#')[0]
            b64 += '=' * (-len(b64) % 4)
            j = json.loads(base64.b64decode(b64))
            return str(j.get('add', '')), int(j.get('port', 0))
        no_scheme = re.sub(r'^\w+://', '', uri)
        at = no_scheme.rfind('@')
        host_part = no_scheme[at+1:] if at != -1 else no_scheme
        host_part = re.split(r'[/?#]', host_part)[0]
        host, port = split_host_port(host_part, default_port=0)
        return host or '', port or 0
    except Exception:
        return '', 0


def dedupe_by_host_port(uris):
    seen = set()
    out = []
    for u in uris:
        host, port = extract_host_port(u)
        key = (host, port)
        if key == ('', 0) or key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


def score(u):
    m = re.search(r':(\d+)[?#/]', u)
    port = int(m.group(1)) if m else 9999
    tls  = 1 if 'security=tls' in u or 'security=reality' in u else 0
    prio = 0 if port in (443, 8443, 2083, 2087, 2096) else 1
    return (prio, -tls, port)


# ── stage 1: cheap TCP reachability + rough latency ──

def tcp_ping(uri):
    host, port = extract_host_port(uri)
    if not host or not port:
        return None
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return round((time.perf_counter() - start) * 1000)
    except Exception:
        return None


def tcp_prefilter(uris, test_limit=TEST_LIMIT):
    """Return (ms, uri) pairs for everything that accepted a TCP connection,
    sorted fastest-first."""
    found = []
    lock = threading.Lock()

    def test(u):
        ms = tcp_ping(u)
        if ms is not None:
            with lock:
                found.append((ms, u))

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(test, u) for u in uris[:test_limit]]
        concurrent.futures.wait(futures, timeout=60)

    found.sort(key=lambda pair: pair[0])
    return found


# ── stage 2: real Xray-core proxy latency ──

def qdict(query):
    d = {}
    for k, v in parse_qsl(query):
        d[k] = v
    return d


def build_stream_settings(q):
    net = q.get('type') or q.get('net') or 'tcp'
    sec = q.get('security') or 'none'
    ss = {"network": net}

    if sec in ('tls', 'xtls'):
        tls = {"allowInsecure": True}
        sni = q.get('sni') or q.get('host') or q.get('peer')
        if sni: tls["serverName"] = sni
        fp = q.get('fp')
        if fp: tls["fingerprint"] = fp
        alpn = q.get('alpn')
        if alpn: tls["alpn"] = alpn.split(',')
        ss["security"] = "tls"
        ss["tlsSettings"] = tls
    elif sec == 'reality':
        reality = {"allowInsecure": True}
        sni = q.get('sni')
        if sni: reality["serverName"] = sni
        pbk = q.get('pbk')
        if pbk: reality["publicKey"] = pbk
        if 'sid' in q: reality["shortId"] = q.get('sid', '')
        spx = q.get('spx')
        if spx: reality["spiderX"] = spx
        fp = q.get('fp')
        if fp: reality["fingerprint"] = fp
        ss["security"] = "reality"
        ss["realitySettings"] = reality
    else:
        ss["security"] = "none"

    if net == 'ws':
        host_header = q.get('host', '')
        ws = {"path": q.get('path', '/')}
        if host_header: ws["headers"] = {"Host": host_header}
        ss["wsSettings"] = ws
    elif net == 'grpc':
        ss["grpcSettings"] = {"serviceName": q.get('serviceName') or q.get('servicename') or ''}
    elif net in ('h2', 'http'):
        host_header = q.get('host', '')
        ss["httpSettings"] = {"path": q.get('path', '/'), "host": [host_header] if host_header else []}
    elif net == 'tcp' and q.get('headerType') == 'http':
        ss["tcpSettings"] = {"header": {"type": "http"}}

    return ss


def uri_to_outbound(uri):
    """Best-effort URI -> Xray outbound JSON. Returns None if unparseable
    (caller falls back to the TCP-measured latency instead)."""
    try:
        if uri.startswith('vless://'):
            body = uri[8:].split('#')[0]
            userinfo, _, hostpart = body.partition('@')
            hostport, _, query = hostpart.partition('?')
            host, port = split_host_port(hostport)
            q = qdict(query)
            user = {"id": userinfo, "encryption": q.get('encryption', 'none')}
            if q.get('flow'): user["flow"] = q['flow']
            return {
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                "streamSettings": build_stream_settings(q),
            }

        if uri.startswith('vmess://'):
            b64 = uri[8:].split('#')[0]
            b64 += '=' * (-len(b64) % 4)
            j = json.loads(base64.b64decode(b64))
            host, port = j.get('add'), int(j.get('port', 443))
            net = j.get('net', 'tcp')
            sec = 'tls' if j.get('tls') == 'tls' else 'none'
            ss = {"network": net, "security": sec}
            if sec == 'tls':
                tls = {"allowInsecure": True}
                sni = j.get('sni') or j.get('host')
                if sni: tls["serverName"] = sni
                ss["tlsSettings"] = tls
            if net == 'ws':
                ws = {"path": j.get('path', '/')}
                if j.get('host'): ws["headers"] = {"Host": j['host']}
                ss["wsSettings"] = ws
            elif net == 'grpc':
                ss["grpcSettings"] = {"serviceName": j.get('path', '')}
            return {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": host, "port": port, "users": [
                    {"id": j.get('id'), "alterId": int(j.get('aid', 0) or 0), "security": j.get('scy', 'auto')}
                ]}]},
                "streamSettings": ss,
            }

        if uri.startswith('trojan://'):
            body = uri[9:].split('#')[0]
            password, _, hostpart = body.partition('@')
            hostport, _, query = hostpart.partition('?')
            host, port = split_host_port(hostport)
            q = qdict(query)
            ss = build_stream_settings(q) if q.get('security') else {
                "network": "tcp", "security": "tls",
                "tlsSettings": {"allowInsecure": True, **({"serverName": q['sni']} if q.get('sni') else {})}
            }
            return {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": password}]},
                "streamSettings": ss,
            }

        if uri.startswith('ss://'):
            body = uri[5:].split('#')[0]
            if '@' in body:
                userinfo, _, hostpart = body.partition('@')
                try:
                    ui = userinfo + '=' * (-len(userinfo) % 4)
                    dec = base64.urlsafe_b64decode(ui).decode()
                except Exception:
                    dec = userinfo
                method, _, password = dec.partition(':')
                hostport, _, _ = hostpart.partition('?')
                host, port = split_host_port(hostport)
            else:
                b = body + '=' * (-len(body) % 4)
                dec = base64.urlsafe_b64decode(b).decode()
                cred, _, hp = dec.partition('@')
                method, _, password = cred.partition(':')
                host, port = split_host_port(hp)
            return {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
            }
    except Exception:
        return None
    return None


def real_ping(uri, local_port):
    """Spin up xray with this config as the sole outbound behind a local HTTP
    inbound, fire a request through it, time it, tear down.

    Returns (status, ms):
      ('ok', ms)          - real proxy round trip succeeded
      ('broken', None)    - we could attempt the test but it failed
                             (bad server / auth / dead route) -> caller should DROP it
      ('untestable', None)- couldn't even attempt it (unparseable URI, local
                             process/environment issue) -> caller falls back to TCP time
    """
    outbound = uri_to_outbound(uri)
    if not outbound:
        return ('untestable', None)

    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "http", "settings": {}}],
        "outbounds": [outbound],
    }
    cfg_path = f"/tmp/xcfg_{local_port}.json"
    proc = None
    try:
        with open(cfg_path, 'w') as f:
            json.dump(cfg, f)

        try:
            proc = subprocess.Popen([XRAY_BIN, "run", "-c", cfg_path],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            # local environment problem (binary missing/unrunnable) - not the server's fault
            return ('untestable', None)

        ready = False
        for _ in range(15):
            time.sleep(0.1)
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.3):
                    ready = True
                    break
            except Exception:
                continue
        if not ready:
            # xray never bound its local port - config was accepted but the
            # server itself is what's failing here
            return ('broken', None)

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{local_port}"})
        )
        start = time.perf_counter()
        with opener.open(TEST_URL, timeout=6) as resp:
            resp.read()
        return ('ok', round((time.perf_counter() - start) * 1000))
    except Exception:
        # request through the proxy failed - confirmed broken, not our fault
        return ('broken', None)
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            os.remove(cfg_path)
        except Exception:
            pass


def real_test_batch_classified(pairs, port_offset):
    """pairs: list of (tcp_ms, uri). Returns list of (status, ms, uri) where
    status is 'ok' / 'broken' / 'untestable' per real_ping's contract."""
    results = [None] * len(pairs)
    lock = threading.Lock()

    def run(i, tcp_ms, uri):
        status, ms = real_ping(uri, port_offset + i)
        with lock:
            if status == 'ok':
                results[i] = ('ok', ms, uri)
            elif status == 'untestable':
                results[i] = ('untestable', tcp_ms, uri)
            else:
                results[i] = ('broken', None, uri)

    with concurrent.futures.ThreadPoolExecutor(max_workers=REAL_WORKERS) as ex:
        futures = [ex.submit(run, i, ms, u) for i, (ms, u) in enumerate(pairs)]
        concurrent.futures.wait(futures, timeout=120)

    return [r for r in results if r is not None]


# ── main ──

MAX_REAL_TESTS = 150  # safety cap: at most 5 batches of REAL_TEST_N per provider

if not HAS_XRAY:
    print(f"[warn] xray binary not found/executable at {XRAY_BIN} — "
          f"falling back to TCP-only latency for all providers.")

for p in PROVIDERS:
    raw = load_raw(p["path"])
    configs = extract_configs(raw)
    configs = dedupe_by_host_port(configs)
    configs.sort(key=score)
    print(f"{p['name']}: {len(configs)} unique candidates")

    tcp_hits = tcp_prefilter(configs, test_limit=TEST_LIMIT)
    print(f"{p['name']}: {len(tcp_hits)} reachable over TCP")

    confirmed = []   # (ms, uri) - real proxy test succeeded
    fallback = []    # (ms, uri) - untestable, using TCP time as a stand-in
    dropped = 0      # confirmed broken - excluded entirely
    idx = 0
    tested = 0

    if not HAS_XRAY:
        # no way to real-test at all - keep old TCP-only behavior
        fallback = list(tcp_hits[:REAL_TEST_N])
    else:
        while (len(confirmed) + len(fallback)) < TOP_N and idx < len(tcp_hits) and tested < MAX_REAL_TESTS:
            batch = tcp_hits[idx: idx + REAL_TEST_N]
            idx += len(batch)
            tested += len(batch)

            classified = real_test_batch_classified(batch, port_offset=20000 + idx)
            for status, ms, uri in classified:
                if status == 'ok':
                    confirmed.append((ms, uri))
                elif status == 'untestable':
                    fallback.append((ms, uri))
                # 'broken' -> dropped silently
                else:
                    dropped += 1

        print(f"{p['name']}: tested {tested} candidates -> "
              f"{len(confirmed)} confirmed working, {dropped} confirmed broken (dropped), "
              f"{len(fallback)} untestable (fallback to TCP)")

    results = confirmed + fallback
    results.sort(key=lambda pair: pair[0])
    top = results[:TOP_N]

    out_path = f"configs/{p['slug']}.txt"
    lines = [f"{ms}|{uri}" for ms, uri in top]
    with open(out_path, "w") as f:
        f.write('\n'.join(lines) if lines else 'fetch failed')

    if top:
        print(f"{p['name']}: {len(top)} servers saved (fastest {top[0][0]}ms) -> {out_path}")
    else:
        print(f"{p['name']}: 0 servers saved")
