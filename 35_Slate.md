# Slate — Hardware / NAND forensics (500)
**Flag:** `CTF{b4d_bl0ck5_k33p_g00d_s3cr3ts_wh1l3_th3_l0g_w4pp3d_4r0und}`

> The chip was pulled before it could say goodbye. We desoldered it, read it out, and that is all we know.

## Idea (full chain)
1. **Geometry:** `slate.bin` = 6,488,064 B = 3072 pages × **2112** (2048 data + 64 OOB spare), 64 pages/block.
2. **OOB layout** (reverse-engineered): `[0]`=0xFF good / 0x00 bad-block marker; `[2:4]`='SL'; `[4]`=logical-block id; `[6:8]`=seq LE16; `[9:11]`=payload length; `[16:]`=**ECC, 3 bytes per 512-byte chunk**. The ECC is Linux `nand_ecc` (512-byte step, byte-inverted, 0xFF pad). Correcting single-bit errors with the syndrome fixes 123 chunks — needed, because the newest superblock reads `flagntxt` / `moved tn vault.bin` until corrected.
3. **SLATEFS:** block 0 is a superblock (`vault.bin 4,5,6`, `boot.cfg`, `flag.txt`, `log 8-39`). Pick each block's live copy by anchoring on the superblock with the highest `gen=` (the 16-bit seq wraps and a never-erased cold block holds stale copies, so plain "highest seq" picks wrong).
4. **Factory secret** ("bad blocks keep good secrets"): 6 intact bad-block marker pages each hold a 4-byte record at `OOB[16:20]` → 24 bytes = `fct`. `key = sha256(serial || fct)`, verified against `kcheck`.
5. **Vault:** `'VLT1' | nonce[12] | ct`, `pt = ct XOR shake_256(key || nonce)`. The live r3 vault (blocks 4/5/6) decrypts to the flag.

## How to reproduce
```bash
cd "../Slate"
$PY solve.py    # ECC-correct -> newest copies -> fct -> key (kcheck/sha256 checks) -> decrypt -> flag
```
`slate_ecc.py` = Hamming ECC encode/correct + page reader. `vault_v1/2/3.bin` are the three ECC-corrected vault versions.

## Solve script(s)

### `solve.py`
```python
# Slate: raw NAND (2048+64) -> ECC-correct -> SLATEFS -> fct from bad-block markers -> shake256 vault
import hashlib, re
from slate_ecc import read_page

d = open('slate.bin', 'rb').read()
H = lambda b: hashlib.sha256(b).digest()
PAGES, BLK = 3072, 64
oob = lambda p: d[p * 2112 + 2048:(p + 1) * 2112]

# newest copy of each logical block: highest 16-bit seq, unwrapped around the wrap point
copies = {}
for p in range(PAGES):
    o = oob(p)
    if o[0] != 0xff or o[2:4] != b'SL': continue
    copies.setdefault(o[4], []).append((int.from_bytes(o[6:8], 'little'), p))
# 16-bit seq wraps, and a never-erased cold block holds stale copies, so anchor on the
# superblock with the highest gen=: the live copy of a block is the last one written before it
sb_seq, _ = max(copies[0], key=lambda sp: int(re.search(rb'gen=(\d+)', read_page(d, sp[1])[0]).group(1)))
def newest(lb):
    return min(copies[lb], key=lambda sp: (sb_seq - sp[0]) % 0x10000)[1]

cfg = read_page(d, newest(1))[0].decode()
print(cfg)
serial = re.search(r'serial=(\S+)', cfg).group(1).encode()

# factory secret: 4 bytes in OOB[16:20] of each intact bad-block marker page (OOB[0]==0x00)
fct = b''.join(oob(b * BLK)[16:20] for b in range(PAGES // BLK)
               if oob(b * BLK)[0] == 0 and oob(b * BLK)[13:16] == b'\xff' * 3)
key = H(serial + fct)
assert H(key)[:8].hex() == re.search(r'kcheck=(\w+)', cfg).group(1), 'kcheck mismatch'

vault = b''.join(read_page(d, newest(lb))[0] for lb in (4, 5, 6))
assert hashlib.sha256(vault).hexdigest() == re.search(r'vault_sha256=(\w+)', cfg).group(1)
nonce, ct = vault[4:16], vault[16:]
pt = bytes(a ^ b for a, b in zip(ct, hashlib.shake_256(key + nonce).digest(len(ct))))
print(re.search(rb'CTF\{[^}]+\}', pt).group().decode())

```

### `slate_ecc.py`
```python
# Hamming ECC, 3 bytes per 512-byte chunk (Linux nand_ecc / SmartMedia style)
def par(x): return bin(x).count('1') & 1
def raw_bits(chunk):
    """rp[0..17]: rp[2j]=parity of bytes with addr bit j == 0, rp[2j+1]= bit j == 1; cp[0..5]"""
    rp = [0] * 18; colx = 0
    for i, b in enumerate(chunk):
        colx ^= b
        if par(b):
            for j in range(9):
                rp[2 * j + ((i >> j) & 1)] ^= 1
    cp = [par(colx & m) for m in (0x55, 0xaa, 0x33, 0xcc, 0x0f, 0xf0)]
    return rp, cp
def ecc(chunk, inv=True, swap=False):
    rp, cp = raw_bits(chunk)
    b0 = sum(rp[k] << k for k in range(8))
    b1 = sum(rp[8 + k] << k for k in range(8))
    b2 = (cp[5] << 7) | (cp[4] << 6) | (cp[3] << 5) | (cp[2] << 4) | (cp[1] << 3) | (cp[0] << 2) | (rp[17] << 1) | rp[16]
    out = bytes([b1, b0, b2] if swap else [b0, b1, b2])
    return bytes(x ^ 0xff for x in out) if inv else out

def correct(chunk, stored):
    """returns (fixed_chunk, status) status: ok | fixed | eccerr | bad"""
    calc = ecc(chunk)
    syn = int.from_bytes(bytes(a ^ b for a, b in zip(calc, stored)), 'big')
    if syn == 0: return chunk, 'ok'
    n = bin(syn).count('1')
    if n == 1: return chunk, 'eccerr'
    s0, s1, s2 = calc[0] ^ stored[0], calc[1] ^ stored[1], calc[2] ^ stored[2]
    rp = [(s0 >> k) & 1 for k in range(8)] + [(s1 >> k) & 1 for k in range(8)] + [s2 & 1, (s2 >> 1) & 1]
    cp = [(s2 >> k) & 1 for k in range(2, 8)]
    if all(rp[2 * j] != rp[2 * j + 1] for j in range(9)) and all(cp[2 * j] != cp[2 * j + 1] for j in range(3)):
        addr = sum(rp[2 * j + 1] << j for j in range(9)); bit = cp[1] | (cp[3] << 1) | (cp[5] << 2)
        if addr < len(chunk):
            c = bytearray(chunk); c[addr] ^= 1 << bit; return bytes(c), 'fixed'
    return chunk, 'bad'

def read_page(d, p):
    dat, o = d[p * 2112:p * 2112 + 2048], d[p * 2112 + 2048:(p + 1) * 2112]
    L = int.from_bytes(o[9:11], 'little'); out = b''; sts = []
    for c in range((L + 511) // 512):
        ch = dat[c * 512:min((c + 1) * 512, L)]
        padded = ch + b'\xff' * (512 - len(ch))
        fx, st = correct(padded, o[16 + 3 * c:19 + 3 * c])
        out += fx[:len(ch)]; sts.append(st)
    return out, sts, o

```
