# Moult (crypto, 500)

> The appliance sheds its old self on every firmware upgrade, but the audit log never lies about what it signed. One seal was cut on the bench, the other in the field. Open the field one.

**Flag:** `CTF{c0nst4nts_c4nc3l_wh3n_th3_gcd_g03s_l1n34r}`

## Files

- `audit.json` — exported audit log: 2 keys, 2 AES-GCM "seals", 58 signed log entries.
- `fw_excerpt.txt` — annotated firmware excerpt (pseudo-asm) for the MOULT-HSM.

## Target

Each seal is `AES-256-GCM`, `key = SHA256(d.to_bytes(32,'big'))`, `aad = bytes.fromhex(kid)`,
where `d` is the ECDSA private key of that slot. So opening a seal = recovering `d`.

- **Bench** = slot 0, `kid=e6069d4c` — the `0.9-bringup` ATE image ("NOT for field", 120-bit clamped nonces).
- **Field** = slot 1, `kid=ee645b51` — the one we must open.

The curve is secp256k1 (`N = FFFF...D0364141`). ECDSA signs each log record, so every entry
leaks `(r, s, z)`. Recover `d` from the field signatures, derive the key, decrypt the field seal.

## Step 1 — Reorder the log

The export says "order not preserved", but `log_append` builds a linked list:

```
id   = SHA256(prev_id || r || s)[0:8]          # r,s as 32-byte big-endian
ptr  = rol64(s_low64, 13) XOR prev_id          # s_low64 = low 64 bits of s
```

So `prev_id = ptr XOR rol64(s_low64, 13)`. Recovering `prev_id` for every record and checking
`SHA256(prev_id||r||s)[:8] == id` validates all 58 links. Chaining `prev → id` reconstructs the
signing order. (Some records were rotated out of the store, so slot 1 breaks into fragments —
but each fragment is a run of genuinely *adjacent* signatures, which is what the attack needs.)

Recovering `prev_id` matters for a second reason: `z = SHA256(prev_id || msg) mod N`, so without
the correct `prev_id` you cannot compute the signed hash `z`.

## Step 2 — The nonce is deterministic

The nonce `k` lives in `KREG`. `entropy_mix` would inject TRNG bytes, **but** it is gated on CFG
bit 3, and `CFG = 0xA5` has bit 3 clear → nothing is mixed. So consecutive nonces are fully
determined by `ksched`.

`ksched` does `powm_mont(x, e)` with `e = 0x7B ^ 0x78 = 3`, plus `mm(A, x)`, plus `B`. The key
trap (spelled out: *"no conversion into or out of any Montgomery domain happens"*) is that `mm`
is Montgomery multiply `mm(a,b) = a·b·R⁻¹ mod N` (`R = 2²⁵⁶`) and nothing converts in/out. So:

- `powm_mont(x,3)` = two Montgomery mults on a raw value = `x³·R⁻²`
- `mm(A,x)` = `A·x·R⁻¹`

giving the recurrence between adjacent nonces:

```
k_{i+1} = R⁻²·k_i³  +  (A·R⁻¹)·k_i  +  B      (mod N)
        =    c1·k_i³ +     c2·k_i   +  c3
```

`c1 = R⁻² mod N` is known; `c2` (from fuse `A`) and `c3` (fuse `B`) are unknown constants.

## Step 3 — Cancel the constants (the GCD goes linear)

From ECDSA, each signature gives the nonce as a **linear** function of the private key:

```
k_i = (z_i + r_i·d) / s_i  =  a_i + b_i·d    (mod N)
```

Take 4 adjacent nonces `k0..k3` (one length-≥4 chain fragment, not crossing the `sys.fw_commit`
reseed). They give 3 recurrence equations, each **linear in the two unknowns** `c2, c3`:

```
c2·k_i + c3 = k_{i+1} − c1·k_i³      for i = 0,1,2
```

The 3×3 consistency determinant eliminates `c2` and `c3`:

```
| k0  1  (k1 − c1·k0³) |
| k1  1  (k2 − c1·k1³) | = 0
| k2  1  (k3 − c1·k2³) |
```

Substituting `k_i = a_i + b_i·d` makes this a **quartic in `d` over F_N**. Its roots (≤4) are the
`d` candidates; test each against the slot-1 public key `02…`/`03…` to pick the real one.

```python
import json, hashlib
from sympy import symbols, Poly, GF
from ecdsa import SigningKey, SECP256k1

N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
c1 = pow(2**256, -2, N)
rol64 = lambda v,r: ((v<<r)|((v&(1<<64)-1)>>(64-r)))&((1<<64)-1)

E = json.load(open('audit.json'))['entries']
for x in E:
    s = int(x['s'],16)
    x['prev'] = '%016x' % (int(x['ptr'],16) ^ rol64(s & (1<<64)-1, 13))

recs   = [x for x in E if x['kid']=='ee645b51']
byid   = {x['id']:x for x in recs}
byprev = {x['prev']:x for x in recs}

def lin(x):                       # k = a + b*d
    r,s = int(x['r'],16), int(x['s'],16)
    z   = int.from_bytes(hashlib.sha256(bytes.fromhex(x['prev'])+x['msg'].encode()).digest(),'big') % N
    si  = pow(s,-1,N)
    return (z*si)%N, (r*si)%N

d = symbols('d'); F = GF(N); cand=set()
heads=[x for x in recs if x['prev'] not in byid]
for h in heads:
    chain=[]; cur=h
    while cur: chain.append(cur); cur=byprev.get(cur['id'])
    for st in range(len(chain)-3):
        win=chain[st:st+4]
        k=[Poly(a+b*d,d,domain=F) for a,b in map(lin,win)]
        w=[k[i+1]-Poly(c1,d,domain=F)*k[i]**3 for i in range(3)]
        det=k[0]*(w[2]-w[1]) - (k[1]*w[2]-k[2]*w[1]) + w[0]*(k[1]-k[2])
        cand|={int(r)%N for r in det.ground_roots()}

pub=bytes.fromhex("032408e11695f49a87b286935179562e66ff090d47b48a3f29ea4f7ad2a0c20c56")
d_sol=next(c for c in cand if c and SigningKey.from_secret_exponent(c,curve=SECP256k1)
           .get_verifying_key().to_string("compressed")==pub)
print(hex(d_sol))
# 0xb64510321d0bc6290423d9e089b949d26b03eec3a22c17ab6d3675c868e0aaf2
```

## Step 4 — Open the field seal

```python
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
d   = 0xb64510321d0bc6290423d9e089b949d26b03eec3a22c17ab6d3675c868e0aaf2
seal= [s for s in json.load(open('audit.json'))['seals'] if s['slot']==1][0]
pt  = AESGCM(hashlib.sha256(d.to_bytes(32,'big')).digest()).decrypt(
        bytes.fromhex(seal['nonce']),
        bytes.fromhex(seal['ct'])+bytes.fromhex(seal['tag']),
        bytes.fromhex(seal['kid']))
print(pt.decode())   # CTF{c0nst4nts_c4nc3l_wh3n_th3_gcd_g03s_l1n34r}
```

## Why it worked

Three design "moults" line up into one break:

1. **CFG bit 3 clear** → the TRNG hook is dead, nonces are deterministic.
2. **Missing Montgomery conversions** → the nonce update is a known cubic recurrence
   `k³·R⁻² + A·k·R⁻¹ + B`, with only the two fuse constants unknown.
3. **The id/ptr chain** → records can be reordered into true signing adjacency, which is what
   lets the recurrence be applied between real neighbours.

Because each nonce is linear in `d`, a 3-equation determinant cancels both unknown fuse constants
and collapses the whole thing to a quartic in `d` — exactly what the flag names.

### Red herrings / notes
- Slot 0 (bench) has 120-bit clamped nonces — a classic small-nonce/HNP lattice break — but it's
  the *bench* seal; the prompt asks for the field one, so slot 0 is never needed.
- The `sys.fw_commit ver=2.0 reseed=1` entry reseeds `KREG` from the KDF: it breaks the recurrence
  lineage, so the attack window must stay within a single fragment that doesn't cross it.
