# EXP-009 traffic agent (derived from the A1 agent). Every node runs TCP/UDP echo servers.
# Peers (role P) probe each target (role X); targets open one outbound connection to each peer.
# Long-lived probes are (re)opened only in the opening window of each wall-clock cycle, so a
# connection observed after a security-group change was established before it.
import asyncio, json, os, socket, time, random
C = json.load(open(os.environ.get('PEP_CFG', '/opt/pep/cfg.json')))
ME = C['me']; N = C['nodes']; T0 = C['t0']; CYC = C['cycle']; W0, W1 = C.get('open', [15, 55])
TP, UP = 7000, 7001
cnt = {}

def out(t, s):
    line = '%s|%s|%d|%s\n' % (t, ME, int(time.time()), s)
    for p in (os.environ.get('PEP_TTY', '/dev/ttyS0'), os.environ.get('PEP_LOG', '/var/log/pep.log')):
        try:
            with open(p, 'a') as f: f.write(line)
        except Exception: pass

def rec(k, s):  # s: 0 ok, 1 fail (timeout), 2 no connection
    b = int(time.time()) // 10 * 10
    cnt.setdefault(b, {}).setdefault(k, [0, 0, 0])[s] += 1

def gen():
    d = time.time() - T0
    return int(d // CYC) if d >= 0 else -1

def window():
    d = time.time() - T0
    return d >= 0 and W0 <= d % CYC < W1

async def dump_loop():
    while True:
        await asyncio.sleep(10)
        now = int(time.time()) // 10 * 10
        for b in sorted(x for x in cnt if x < now):
            d = cnt.pop(b)
            out('D', '%d|%d|%s' % (b, gen(), ';'.join('%s=%d,%d,%d' % (k, v[0], v[1], v[2]) for k, v in sorted(d.items()))))

class UEcho(asyncio.DatagramProtocol):
    def connection_made(self, t): self.t = t
    def datagram_received(self, d, a): self.t.sendto(d, a)

async def tcp_echo(r, w):
    try:
        while True:
            d = await r.read(64)
            if not d: break
            w.write(d); await w.drain()
    except Exception: pass
    finally:
        try: w.close()
        except Exception: pass

async def servers():
    loop = asyncio.get_running_loop()
    try:
        ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM); ts.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ts.bind(('0.0.0.0', TP)); C['_srv'] = await asyncio.start_server(tcp_echo, sock=ts)
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); us.bind(('0.0.0.0', UP))
        await loop.create_datagram_endpoint(UEcho, sock=us)
    except Exception as e:
        out('E', 'server %r' % (e,))

async def readmatch(r, b):
    while True:
        d = await r.read(1)
        if not d: return False
        if d[0] == b: return True

def close(w):
    try: w.close()
    except Exception: pass

async def tcp_est(k, host, iv):
    r = w = None; g = -2; seq = 0
    await asyncio.sleep(random.uniform(0, iv))
    while True:
        if gen() != g and window():
            if w: close(w)
            r = w = None
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, TP), 3); g = gen()
            except Exception:
                r = w = None; await asyncio.sleep(2); continue
        if w is None:
            rec(k, 2); await asyncio.sleep(iv); continue
        seq = (seq + 1) % 256
        try:
            w.write(bytes([seq])); await w.drain()
            ok = await asyncio.wait_for(readmatch(r, seq), 2)
            if ok: rec(k, 0)
            else: rec(k, 2); close(w); r = w = None
        except asyncio.TimeoutError: rec(k, 1)
        except Exception: rec(k, 2); close(w); r = w = None
        await asyncio.sleep(iv)

async def tcp_new(k, host, iv):
    await asyncio.sleep(random.uniform(0, iv))
    while True:
        t0 = time.time()
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, TP), 2)
            try:
                w.write(b'\x07'); await w.drain()
                rec(k, 0 if await asyncio.wait_for(readmatch(r, 7), 2) else 1)
            finally: close(w)
        except Exception: rec(k, 1)
        await asyncio.sleep(max(0.5, iv - (time.time() - t0)))

async def udp_match(loop, s, m):
    while True:
        if await loop.sock_recv(s, 64) == m: return True

async def udp_est(k, host, iv):  # same 5-tuple within a cycle
    loop = asyncio.get_running_loop(); s = None; g = -2; seq = 0
    await asyncio.sleep(random.uniform(0, iv))
    while True:
        if gen() != g and window():
            if s: s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False); s.connect((host, UP)); g = gen()
        if s is None: rec(k, 2); await asyncio.sleep(iv); continue
        seq += 1; m = seq.to_bytes(4, 'big')
        try:
            s.send(m); await asyncio.wait_for(udp_match(loop, s, m), 2); rec(k, 0)
        except Exception: rec(k, 1)
        await asyncio.sleep(iv)

async def ping_est(k, host, iv):  # one ping process (one ICMP identifier) within a cycle
    proc = None; g = -2
    while True:
        if gen() != g and window():
            if proc:
                try: proc.kill()
                except Exception: pass
            try:
                proc = await asyncio.create_subprocess_exec('stdbuf', '-oL', 'ping', '-n', '-O', '-i', str(iv), '-W', '2', host,
                                                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                g = gen()
            except Exception as e:
                out('E', 'ping %r' % (e,)); proc = None; await asyncio.sleep(iv); continue
        if proc is None: rec(k, 2); await asyncio.sleep(iv); continue
        try: line = await asyncio.wait_for(proc.stdout.readline(), 1)
        except asyncio.TimeoutError: continue
        if not line: proc = None; continue
        l = line.decode(errors='ignore')
        if 'bytes from' in l: rec(k, 0)
        elif 'no answer yet' in l: rec(k, 1)

async def guard(c):
    try: await c
    except Exception as e: out('E', 'task %r' % (e,))

async def main():
    await servers()
    me = N[ME]; t = [dump_loop()]
    for n, v in sorted(N.items()):
        if n == ME: continue
        if me['r'] == 'P' and v['r'] == 'X':
            p = n + '.'
            t += [tcp_est(p + 'Te', v['a'], 5), tcp_new(p + 'Tn', v['a'], 5), udp_est(p + 'Ue', v['a'], 5), ping_est(p + 'Ie', v['a'], 5)]
        elif me['r'] == 'X' and v['r'] == 'P':
            t.append(tcp_est(n + '.Oe', v['a'], 5))
    out('S', 'start %d tasks t0=%d cycle=%d' % (len(t), T0, CYC))
    await asyncio.gather(*[guard(c) for c in t])

try:
    asyncio.run(main())
except Exception as e:
    out('E', repr(e)[:300])
