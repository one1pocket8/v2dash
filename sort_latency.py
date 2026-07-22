import re

with open('/tmp/combined.txt') as f:
    lines = [l.strip() for l in f if l.strip()]

def score(u):
    port_match = re.search(r':(\d+)[?#/]', u)
    port = int(port_match.group(1)) if port_match else 9999
    tls = 1 if 'security=tls' in u else 0
    prio = 0 if port in (443, 8443, 2083, 2087, 2096) else 1
    return (prio, -tls, port)

lines.sort(key=score)

with open('/tmp/latency_sorted.txt', 'w') as f:
    f.write('\n'.join(lines[:20]))
