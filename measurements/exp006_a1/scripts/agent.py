import asyncio, json, os, socket, time, zlib, base64, random, sys, urllib.request
C = json.load(open(os.environ.get('PEP_CFG', '/opt/pep/cfg.json')))
ME = C['me']; N = C['nodes']; TP, UP = 7000, 7001
st = {'ctl': '', 'gen': 0, 'tok': None, 'te': 0}
cnt = {}

def out(t, s):
    line = '%s|%s|%d|%s\n' % (t, ME, int(time.time()), s)
    for p in (os.environ.get('PEP_TTY', '/dev/ttyS0'), '/var/log/pep.log'):
        try:
            with open(p, 'a') as f: f.write(line)
        except Exception: pass

def rec(k, s):  # s: 0 ok, 1 fail(timeout/refused), 2 no connection
    b = int(time.time()) // 10 * 10
    d = cnt.setdefault(b, {'p': st['ctl'], 'c': {}})
    d['c'].setdefault(k, [0, 0, 0])[s] += 1

def imds_ctl():
    f = os.environ.get('PEP_CTL_FILE')
    if f:
        try: return open(f).read().strip()
        except Exception: return None
    try:
        if not st['tok'] or time.time() > st['te']:
            q = urllib.request.Request('http://169.254.169.254/latest/api/token', method='PUT',
                                       headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'})
            st['tok'] = urllib.request.urlopen(q, timeout=2).read().decode(); st['te'] = time.time() + 20000
        q = urllib.request.Request('http://169.254.169.254/latest/meta-data/tags/instance/ctl',
                                   headers={'X-aws-ec2-metadata-token': st['tok']})
        return urllib.request.urlopen(q, timeout=2).read().decode().strip()
    except Exception:
        return None

async def ctl_loop():
    loop = asyncio.get_running_loop()
    while True:
        v = await loop.run_in_executor(None, imds_ctl)
        if v is not None and v != st['ctl']:
            st['ctl'] = v
            if v.startswith('base'): st['gen'] += 1
            out('C', v)
        await asyncio.sleep(2)

async def dump_loop():
    seq = 0
    while True:
        await asyncio.sleep(60)
        now = int(time.time()) // 10 * 10
        ks = sorted(b for b in cnt if b < now)
        if not ks: continue
        p = {str(b): cnt.pop(b) for b in ks}
        seq += 1
        out('D', '%d|%s' % (seq, base64.b64encode(zlib.compress(json.dumps(p, separators=(',', ':')).encode(), 9)).decode()))

def base(): return st['ctl'].startswith('base')

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
    st['srv'] = []
    for fam, h in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
        try:
            ts = socket.socket(fam, socket.SOCK_STREAM); ts.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if fam == socket.AF_INET6: ts.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            ts.bind((h, TP)); st['srv'].append(await asyncio.start_server(tcp_echo, sock=ts))
            us = socket.socket(fam, socket.SOCK_DGRAM)
            if fam == socket.AF_INET6: us.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            us.bind((h, UP)); await loop.create_datagram_endpoint(UEcho, sock=us)
        except Exception as e:
            out('E', 'server %s %r' % (h, e))

async def readmatch(r, b):
    while True:
        d = await r.read(1)
        if not d: return False
        if d[0] == b: return True

def close(w):
    try: w.close()
    except Exception: pass

async def tcp_est(k, host, iv):  # one long-lived connection, opened only in a base phase
    r = w = None; gen = -1; seq = 0
    await asyncio.sleep(random.uniform(0, iv))
    while True:
        if st['gen'] != gen and base():
            if w: close(w)
            r = w = None; gen = st['gen']
        if w is None:
            if base() and gen == st['gen']:
                try:
                    r, w = await asyncio.wait_for(asyncio.open_connection(host, TP), 3)
                except Exception:
                    r = w = None; await asyncio.sleep(2); continue
            else:
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

async def udp_est(k, host, fam, iv):  # same 5-tuple for the whole phase
    loop = asyncio.get_running_loop(); s = None; gen = -1; seq = 0
    await asyncio.sleep(random.uniform(0, iv))
    while True:
        if st['gen'] != gen and base():
            if s: s.close()
            s = socket.socket(fam, socket.SOCK_DGRAM); s.setblocking(False); s.connect((host, UP)); gen = st['gen']
        if s is None: rec(k, 2); await asyncio.sleep(iv); continue
        seq += 1; m = seq.to_bytes(4, 'big')
        try:
            s.send(m); await asyncio.wait_for(udp_match(loop, s, m), 2); rec(k, 0)
        except Exception: rec(k, 1)
        await asyncio.sleep(iv)

async def udp_new(k, host, fam, iv):
    loop = asyncio.get_running_loop()
    await asyncio.sleep(random.uniform(0, iv))
    while True:
        s = socket.socket(fam, socket.SOCK_DGRAM); s.setblocking(False)
        try:
            s.connect((host, UP)); m = os.urandom(4); s.send(m)
            await asyncio.wait_for(udp_match(loop, s, m), 2); rec(k, 0)
        except Exception: rec(k, 1)
        finally: s.close()
        await asyncio.sleep(iv)

async def ping_est(k, host, v6, iv):  # one ping process (one ICMP identifier) per base phase
    proc = None; gen = -1
    while True:
        if st['gen'] != gen and base():
            if proc:
                try: proc.kill()
                except Exception: pass
            a = ['stdbuf', '-oL', 'ping', '-n', '-O', '-i', str(iv), '-W', '2', host]
            if v6: a.insert(3, '-6')
            proc = await asyncio.create_subprocess_exec(*a, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            gen = st['gen']
        if proc is None: rec(k, 2); await asyncio.sleep(iv); continue
        try: line = await asyncio.wait_for(proc.stdout.readline(), 1)
        except asyncio.TimeoutError: continue
        if not line: proc = None; continue
        l = line.decode(errors='ignore')
        if 'bytes from' in l: rec(k, 0)
        elif 'no answer yet' in l: rec(k, 1)

async def ping_new(k, host, v6, iv):
    await asyncio.sleep(random.uniform(0, iv))
    while True:
        a = ['ping', '-n', '-c', '1', '-W', '2', host]
        if v6: a.insert(1, '-6')
        p = await asyncio.create_subprocess_exec(*a, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        rec(k, 0 if await p.wait() == 0 else 1)
        await asyncio.sleep(iv)

async def main():
    await servers()
    me = N[ME]; t = [ctl_loop(), dump_loop()]
    peers = [n for n, v in N.items() if v['g'] == me['g'] and n != ME]
    for n in peers:
        v = N[n]
        for fam, a, af, v6 in (('4', v['a4'], socket.AF_INET, False), ('6', v['a6'], socket.AF_INET6, True)):
            if me['r'] == 'X' and v['r'] == 'P':
                t.append(tcp_est('%s.%s.Oe' % (n, fam), a, 5))
            elif me['r'] == 'P' and v['r'] == 'X':
                p = '%s.%s.' % (n, fam)
                t += [tcp_est(p + 'Te', a, 5), tcp_new(p + 'Tn', a, 10), tcp_est(p + 'Ti', a, 90),
                      udp_est(p + 'Ue', a, af, 5), udp_new(p + 'Un', a, af, 10),
                      ping_est(p + 'Ie', a, v6, 5), ping_new(p + 'In', a, v6, 10)]
    out('S', 'start %d tasks' % len(t))
    await asyncio.gather(*[guard(c) for c in t])

async def guard(c):
    try: await c
    except Exception as e: out('E', 'task %r' % (e,))

try:
    asyncio.run(main())
except Exception as e:
    out('E', repr(e)[:300])
