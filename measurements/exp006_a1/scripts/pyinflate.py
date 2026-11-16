_B64 = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}
def b64d(s):
    s = "".join(s.split()).rstrip("=")
    out = bytearray(); acc = 0; n = 0
    for ch in s:
        acc = (acc << 6) | _B64[ch]; n += 6
        if n >= 8:
            n -= 8; out.append((acc >> n) & 255)
    return bytes(out)
_LB = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
_LE = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
_DB = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
_DE = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]
_CL = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]
def _huff(lens):
    mx = max(lens) if lens else 0
    cnt = [0]*(mx+1)
    for l in lens:
        if l: cnt[l] += 1
    code = 0; nxt = [0]*(mx+2)
    for b in range(1, mx+1):
        code = (code + cnt[b-1]) << 1 if b > 1 else 0
        nxt[b] = code
    t = {}
    for sym, l in enumerate(lens):
        if l:
            t[(l, nxt[l])] = sym; nxt[l] += 1
    return t, mx
def inflate(data):
    pos = [0, 0]  # byte, bit
    def bits(n):
        v = 0
        for i in range(n):
            b = (data[pos[0]] >> pos[1]) & 1
            v |= b << i
            pos[1] += 1
            if pos[1] == 8: pos[1] = 0; pos[0] += 1
        return v
    def sym(h):
        t, mx = h; code = 0
        for l in range(1, mx+1):
            b = (data[pos[0]] >> pos[1]) & 1
            pos[1] += 1
            if pos[1] == 8: pos[1] = 0; pos[0] += 1
            code = (code << 1) | b
            s = t.get((l, code))
            if s is not None: return s
        raise ValueError("bad code")
    out = bytearray(); final = 0
    while not final:
        final = bits(1); typ = bits(2)
        if typ == 0:
            if pos[1]: pos[1] = 0; pos[0] += 1
            ln = data[pos[0]] | (data[pos[0]+1] << 8); pos[0] += 4
            out += data[pos[0]:pos[0]+ln]; pos[0] += ln; continue
        if typ == 1:
            lit = _huff([8]*144 + [9]*112 + [7]*24 + [8]*8); dist = _huff([5]*30)
        else:
            hl = bits(5) + 257; hd = bits(5) + 1; hc = bits(4) + 4
            cl = [0]*19
            for i in range(hc): cl[_CL[i]] = bits(3)
            ch = _huff(cl); lens = []
            while len(lens) < hl + hd:
                s = sym(ch)
                if s < 16: lens.append(s)
                elif s == 16: lens += [lens[-1]] * (3 + bits(2))
                elif s == 17: lens += [0] * (3 + bits(3))
                else: lens += [0] * (11 + bits(7))
            lit = _huff(lens[:hl]); dist = _huff(lens[hl:])
        while True:
            s = sym(lit)
            if s < 256: out.append(s)
            elif s == 256: break
            else:
                s -= 257; ln = _LB[s] + bits(_LE[s])
                d = sym(dist); dd = _DB[d] + bits(_DE[d])
                st = len(out) - dd
                for i in range(ln): out.append(out[st + i])
    return bytes(out), pos[0] + (1 if pos[1] else 0)
def gunzip(b):
    res = bytearray(); i = 0
    while i < len(b) and b[i] == 0x1f and b[i+1] == 0x8b:
        flg = b[i+3]; p = i + 10
        if flg & 4: p += 2 + (b[p] | (b[p+1] << 8))
        if flg & 8:
            while b[p]: p += 1
            p += 1
        if flg & 16:
            while b[p]: p += 1
            p += 1
        if flg & 2: p += 2
        o, used = inflate(b[p:]); res += o; i = p + used + 8
    return bytes(res)
def zdecomp(b):
    return inflate(b[2:])[0]
