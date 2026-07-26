import re
import socket
import time
import concurrent.futures
import threading

TIMEOUT   = 4
WORKERS   = 80
TOP_N     = 10
TEST_LIMIT = 200

# name -> (source file dropped by the workflow step, output slug used for configs/<slug>.txt)
PROVIDERS = [
    {"name": "Epodonios",    "slug": "epo",      "path": "/tmp/epodonios_all.txt"},
    {"name": "MatinGhanbari","slug": "matin",     "path": "/tmp/matin_all.txt"},
    {"name": "F0rc3Run",     "slug": "f0rc3run",  "path": "/tmp/f0rc3run_all.txt"},
    {"name": "RoosterKid",   "slug": "rooster",   "path": "/tmp/rooster_all.txt"},
]

URI_RE = re.compile(r'(?:vless|vmess|trojan|ss)://\S+')


def extract_configs(raw_text):
    """Pull config URIs out of a line regardless of leading flag emoji or
    trailing 'responsetime country [isp]' metadata glued onto the line."""
    return URI_RE.findall(raw_text)


def extract_host_port(uri):
    try:
        if uri.startswith('vmess://'):
            import base64, json
            b64 = uri[8:].split('#')[0]
            b64 += '=' * (-len(b64) % 4)
            j = json.loads(base64.b64decode(b64))
            return str(j.get('add', '')), int(j.get('port', 0))
        no_scheme = re.sub(r'^\w+://', '', uri)
        at = no_scheme.rfind('@')
        host_part = no_scheme[at+1:] if at != -1 else no_scheme
        host_part = re.split(r'[/?#]', host_part)[0]
        if host_part.startswith('['):
            m = re.match(r'\[([^\]]+)\]:(\d+)', host_part)
            return (m.group(1), int(m.group(2))) if m else ('', 0)
        parts = host_part.rsplit(':', 1)
        return (parts[0], int(parts[1])) if len(parts) == 2 else ('', 0)
    except Exception:
        return '', 0


def tcp_ping(uri):
    """Return round-trip TCP connect time in ms, or None if unreachable."""
    host, port = extract_host_port(uri)
    if not host or not port:
        return None
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=TIMEOUT):
            elapsed_ms = (time.perf_counter() - start) * 1000
            return round(elapsed_ms)
    except Exception:
        return None


def load_raw(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def dedupe_by_host_port(uris):
    """Dedupe on (host, port) rather than exact string, so the same server
    listed twice with different UUIDs/query params only counts once."""
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


def filter_live(uris, max_results, test_limit=TEST_LIMIT):
    """Test candidates concurrently, keep testing until we have enough live
    ones, then return the fastest `max_results` sorted by measured ping."""
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
    return found[:max_results]


# ── Per-provider: fetch, dedupe, score, test, save top 10 each ──
for p in PROVIDERS:
    raw = load_raw(p["path"])
    configs = extract_configs(raw)
    configs = dedupe_by_host_port(configs)
    configs.sort(key=score)
    print(f"{p['name']}: {len(configs)} unique candidates")

    live = filter_live(configs, TOP_N, test_limit=TEST_LIMIT)
    out_path = f"configs/{p['slug']}.txt"
    lines = [f"{ms}|{uri}" for ms, uri in live]
    with open(out_path, "w") as f:
        f.write('\n'.join(lines) if lines else 'fetch failed')
    print(f"{p['name']}: {len(live)} live servers saved (fastest {live[0][0]}ms)" if live
          else f"{p['name']}: 0 live servers")
