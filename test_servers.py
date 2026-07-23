import re
import socket
import concurrent.futures

TIMEOUT  = 3    # seconds per TCP test
WORKERS  = 60   # parallel threads
TOP_N    = 20   # configs to keep per tab

# Keywords that indicate Singapore or Thailand in config name/host
SG_TH_KEYWORDS = [
    'sg', 'singapore', '.sg.', '-sg-', '_sg_',
    'th', 'thailand', '.th.', '-th-', '_th_',
    'bangk', 'bangkok',
]

def is_sg_or_th(uri):
    lower = uri.lower()
    return any(k in lower for k in SG_TH_KEYWORDS)

def is_vless(uri):
    return uri.startswith('vless://')

def extract_host_port(uri):
    try:
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
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
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

def score(u):
    m = re.search(r':(\d+)[?#/]', u)
    port = int(m.group(1)) if m else 9999
    tls  = 1 if 'security=tls' in u else 0
    prio = 0 if port in (443, 8443, 2083, 2087, 2096) else 1
    return (prio, -tls, port)

def filter_live(uris, max_results, test_limit=150):
    live = []
    lock = __import__('threading').Lock()

    def test(u):
        if tcp_ok(u):
            with lock:
                if len(live) < max_results:
                    live.append(u)

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(test, u) for u in uris[:test_limit]]
        concurrent.futures.wait(futures)

    return live[:max_results]

# ── Load all sources ──
shatak_sg  = load_lines('/tmp/shatak_sg.txt')
shatak_th  = load_lines('/tmp/shatak_th.txt')
epodonios  = load_lines('/tmp/epodonios_all.txt')
matin      = load_lines('/tmp/matin_all.txt')

# ── Lowest Latency tab ──
# ShatakVPN SG+TH VLESS (already regional, already VLESS) + filter others by keyword
latency_pool = dedupe(
    shatak_sg +
    shatak_th +
    [u for u in epodonios if is_vless(u) and is_sg_or_th(u)] +
    [u for u in matin     if is_vless(u) and is_sg_or_th(u)]
)
latency_pool.sort(key=score)
live_latency = filter_live(latency_pool, TOP_N, test_limit=120)
with open('configs/latency.txt', 'w') as f:
    f.write('\n'.join(live_latency) if live_latency else 'fetch failed')
print(f"Latency tab: {len(live_latency)} live servers saved")

# ── Top 20 tab ──
# All VLESS from SG/TH keywords across all sources
top20_pool = dedupe(
    shatak_sg +
    shatak_th +
    [u for u in epodonios if is_vless(u) and is_sg_or_th(u)] +
    [u for u in matin     if is_vless(u) and is_sg_or_th(u)]
)
# Different ordering — just take unique ones not already in latency list
latency_set = set(live_latency)
top20_candidates = [u for u in top20_pool if u not in latency_set]
live_top20 = filter_live(top20_candidates, TOP_N, test_limit=150)
with open('configs/top20.txt', 'w') as f:
    f.write('\n'.join(live_top20) if live_top20 else 'fetch failed')
print(f"Top20 tab: {len(live_top20)} live servers saved")
