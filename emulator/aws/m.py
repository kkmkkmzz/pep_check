#!/usr/bin/env python3
# Traffic generator for the AWS measurement (runs on each instance from user data).
# Long-lived connections are opened once and never reopened; short probes open a new connection each time.
import os, socket, threading, time

ROLE = os.environ["ROLE"]
X, P1, P2 = "10.77.1.10", "10.77.2.10", "10.77.1.20"
stat = {}
lock = threading.Lock()


def bump(name, ok):
    with lock:
        s = stat.setdefault(name, [0, 0])
        s[0 if ok else 1] += 1


def server(port):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port)); srv.listen(64)

    def handle(c):
        try:
            while True:
                d = c.recv(64)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def long_client(name, dst, dport, sport, period):
    while True:                      # retry only until the first successful connect
        try:
            s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", sport)); s.settimeout(4); s.connect((dst, dport)); break
        except OSError:
            s.close(); time.sleep(3)
    while True:
        ok = False
        try:
            s.sendall(b"p"); ok = s.recv(8) == b"p"
        except OSError:
            ok = False
        bump(name, ok)
        time.sleep(period)


def new_client(name, dst, dport, period):
    while True:
        ok = False
        s = socket.socket(); s.settimeout(3)
        try:
            s.connect((dst, dport)); s.sendall(b"n"); ok = s.recv(8) == b"n"
        except OSError:
            ok = False
        finally:
            s.close()
        bump(name, ok)
        time.sleep(period)


PLAN = {
    "X": dict(servers=[5001, 5003, 5005, 5010, 5011],
              longs=[("c2", P1, 5002, 40002, 5), ("c4", P2, 5004, 40004, 5)],
              news=[("n3", P1, 5012, 10)]),
    "P1": dict(servers=[5002, 5012],
               longs=[("c1", X, 5001, 40001, 5), ("c5", X, 5005, 40005, 240)],
               news=[("n1", X, 5010, 10)]),
    "P2": dict(servers=[5004],
               longs=[("c3", X, 5003, 40003, 5)],
               news=[("n2", X, 5011, 10)]),
}[ROLE]

for p in PLAN["servers"]:
    threading.Thread(target=server, args=(p,), daemon=True).start()
time.sleep(1)
for a in PLAN["longs"]:
    threading.Thread(target=long_client, args=a, daemon=True).start()
for a in PLAN["news"]:
    threading.Thread(target=new_client, args=a, daemon=True).start()

while True:                           # one summary line per 30 s on the serial console
    time.sleep(30)
    with lock:
        snap = {k: tuple(v) for k, v in stat.items()}
        for v in stat.values():
            v[0] = v[1] = 0
    line = " ".join(f"{k}={v[0]}/{v[1]}" for k, v in sorted(snap.items()))
    print(f"PEPM {ROLE} {int(time.time())} {line}", flush=True)
