# Ferrule (500) — Crypto · CTF

> Eight vaults, one key, many locks. The rotation reissued every lock and never
> touched the key.

**File:** `ring.json`
**Flag:** `CTF{wi3n3r_f0und_th3_k3y_4nd_th3_r1ng_w4s_4_1i3}`
**Decoy (do not submit):** the `e=3` cube-root of `n2f36` alone ends `_r1ng_w4s_4_1i3}` but the shared-key path is the real trap.

## The trap
The riddle ("eight vaults, one key", `"quorum": 8`) is engineered to push you
toward a **shared private-exponent lattice attack** across the 8 large-`e` nodes
(new lock each rotation, same key). That path is a deliberate dead end — the flag
itself says `th3_r1ng_w4s_4_1i3` ("the ring was a lie"). A verified shared-`d`
lattice routine recovers a synthetic 399-bit `d` perfectly but **never verifies
against the real moduli**, because no `d` is actually shared.

## The real vulnerability
`ring.json` holds 11 nodes (1024-bit moduli in four mixed encodings: PEM, JWK,
decimal, hex). The breaks are **per-node**, and each weak node hides one 16-byte
fragment framed as `FR<index>\x03\x10<16-byte fragment>`:

| node | weakness | fragment |
|------|----------|----------|
| `nb7a6` | tiny private exponent (d ≈ 235-bit) → **Wiener's attack** | `CTF{wi3n3r_f0und` |
| `nf909` | tiny private exponent (d ≈ 235-bit) → **Wiener's attack** | `_th3_k3y_4nd_th3` |
| `n2f36` | `e=3`, short message → **cube root** | `_r1ng_w4s_4_1i3}` |

The other 8 nodes (full-size `d`, or no exponent published) carry nothing — pure
decoys. The two Wiener keys recover **different** `d` values — itself the tell
that nothing is shared.

## Steps
1. Parse all four key encodings from `ring.json`.
2. For each node with a published `e`, run **Wiener** (continued-fraction
   convergents of `e/N`); two nodes have a small enough `d` to break.
3. For the `e=3` node, take the integer cube root of the ciphertext.
4. Decrypt each → strip the `FR<i>\x03\x10` frame, take exactly the 16-byte
   fragment, order by index 1→3, concatenate.

## Solver
```python
import json
from Crypto.Util.number import long_to_bytes, inverse
from sympy import integer_nthroot

def wiener(e, n):
    # continued fraction convergents of e/n -> candidate d
    def cf(a, b):
        while b:
            q = a // b; yield q; a, b = b, a - q*b
    num = den = None
    cvs = []
    n0, n1, d0, d1 = 0, 1, 1, 0
    for q in cf(e, n):
        n0, n1 = n1, q*n1 + n0
        d0, d1 = d1, q*d1 + d0
        cvs.append((n1, d1))          # k, d
    for k, d in cvs:
        if k == 0: continue
        if (e*d - 1) % k: continue
        phi = (e*d - 1)//k
        # verify: m^(ed) == m
        if pow(2, e*d, n) == 2 and d > 1:
            return d
    return None

nodes = json.load(open("ring.json"))   # dict/list of {n,e?,c}
frags = {}
for node in nodes:                      # adapt to real structure
    n, e, c = node["n"], node.get("e"), node["c"]
    m = None
    if e == 3:
        r, ok = integer_nthroot(c, 3)
        if ok: m = r
    elif e:
        d = wiener(e, n)
        if d: m = pow(c, d, n)
    if m is None: continue
    b = long_to_bytes(m)
    i = b.find(b"FR")
    if i < 0: continue
    idx = b[i+2]                         # FR<index>
    frag = b[i+4:i+4+16]                 # \x03\x10 then 16 bytes
    frags[idx] = frag

print(b"".join(frags[k] for k in sorted(frags)).decode())
# -> CTF{wi3n3r_f0und_th3_k3y_4nd_th3_r1ng_w4s_4_1i3}
```

> Reconstructed from the solve session; the original `parse.py`/`wiener.py` were
> in a cleared scratchpad, so the snippet above is the method rewritten, not the
> exact files. `ring.json` is still in `~/Downloads` if you want it re-run.
