import re
import socket
import concurrent.futures
import threading

TIMEOUT  = 4
WORKERS  = 80
TOP_N    = 20

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
    except:
        return '', 0

def tcp_ok(uri):
    host, port = extract_host_port(uri)
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except:
        return False

def load_lines(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f
                    if l.strip() and not l.startswith('#')]
    except:
        return []

def dedupe(lines):
    seen = set()
    out = []
    for l in lines:
        if l not in seen:
            seen.add(l)
            out.append(l)
    return out

def is_vless(uri):
    return uri.startswith('vless://')

def score(u):
    m = re.search(r':(\d+)[?#/]', u)
    port = int(m.group(1)) if m else 9999
    tls  = 1 if 'security=tls' in u else 0
    prio = 0 if port in (443, 8443, 2083, 2087, 2096) else 1
    return (prio, -tls, port)

def filter_live(uris, max_results, test_limit=200):
    live = []
    lock = threading.Lock()

    def test(u):
        if len(live) >= max_results:
            return
        if tcp_ok(u):
            with lock:
                if len(live) < max_results:
                    live.append(u)

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(test, u) for u in uris[:test_limit]]
        concurrent.futures.wait(futures, timeout=60)

    return live[:max_results]

# ── Load all sources — no country filter, take all VLESS ──
shatak_sg  = [u for u in load_lines('/tmp/shatak_sg.txt')  if is_vless(u)]
shatak_th  = [u for u in load_lines('/tmp/shatak_th.txt')  if is_vless(u)]
epodonios  = [u for u in load_lines('/tmp/epodonios_all.txt') if is_vless(u)]
matin      = [u for u in load_lines('/tmp/matin_all.txt')  if is_vless(u)]

print(f"Raw counts — ShatakSG:{len(shatak_sg)} ShatakTH:{len(shatak_th)} Epodonios:{len(epodonios)} Matin:{len(matin)}")

# ── Latency tab — ShatakVPN SG+TH first (closest), then others ──
latency_pool = dedupe(shatak_sg + shatak_th + epodonios + matin)
latency_pool.sort(key=score)
print(f"Latency pool: {len(latency_pool)} unique candidates")
live_latency = filter_live(latency_pool, TOP_N, test_limit=200)
with open('configs/latency.txt', 'w') as f:
    f.write('\n'.join(live_latency) if live_latency else 'fetch failed')
print(f"Latency tab: {len(live_latency)} live servers saved")

# ── Top 20 tab — exclude latency results, find next 20 live ──
latency_set = set(live_latency)
top20_pool = dedupe(
    [u for u in (shatak_sg + shatak_th + epodonios + matin) if u not in latency_set]
)
top20_pool.sort(key=score)
print(f"Top20 pool: {len(top20_pool)} unique candidates")
live_top20 = filter_live(top20_pool, TOP_N, test_limit=200)
with open('configs/top20.txt', 'w') as f:
    f.write('\n'.join(live_top20) if live_top20 else 'fetch failed')
print(f"Top20 tab: {len(live_top20)} live servers saved")
