# Quern (500) — Crypto

> The stones keep turning.

**Files:** `quern.py`, `log.json`
**Flag:** `CTF{0n3_gl1tch3d_s4lt_r3us3_f0ld5_th3_m0dulus_1n_h4lf}`
**Decoy (do not submit):** `CTF{sh4r3d_pr1m3s_f4ll_t0_0n3_b4tch_gcd_t00_3asy}`

## Overview

- `quern.py` contains the signing service's RSA-PSS code (SHA-256, MGF1, 32-byte salt, e = 65537)
- `log.json` contains 6 RSA moduli, 42 signed log entries `{msg, s}`, plus `vault` and `decoy_vault` (`{ct, chk}`)

## Step 1: map signatures to keys

Verifying each signature against each modulus shows that 41 entries verify under exactly one key. **Log 0** (`release batch Z0 to vault`) verifies under **none**.

## Step 2: the decoy (shared prime)

Pairwise gcd of the moduli: `gcd(N0, N5) > 1`, so both factor immediately. Using that prime opens `decoy_vault` with the scheme below:

```
CTF{sh4r3d_pr1m3s_f4ll_t0_0n3_b4tch_gcd_t00_3asy}
```

The text itself says it's the too-easy bait. Still, it shows the key format: `key = SHA256(b"quern" + p.to_bytes(64))`, `pt = ct XOR MGF1(key, len(ct))`.

## Step 3: faulty signature + salt reuse factors N1

Log 0 is a glitched RSA-CRT signature: correct mod one prime of N1, wrong mod the other. The Boneh–DeMillo–Lipton / Lenstra attack needs the exact encoded message `em`, which PSS normally hides behind a random salt. However, **log 15 signs the identical message under N1 and verifies**, and log 0 reused its salt:

```
salt = 12588cf7b9b65a821fd6913d39893e92e3792f47e244d8cd049bab49d9edc5c5
em   = pss_encode(b"release batch Z0 to vault", salt, N1.bit_length()-1)
p    = gcd(s0^65537 - em, N1)
```

## Step 4: open the real vault

Same scheme as the decoy, except the key hashes **both** of N1's primes, with the cofactor `q = N1 // p` first:

```
key = SHA256(b"quern" + q.to_bytes(64, "big") + p.to_bytes(64, "big"))   # p = gcd result
pt  = vault.ct XOR MGF1(key, len(ct))
```

```
CTF{0n3_gl1tch3d_s4lt_r3us3_f0ld5_th3_m0dulus_1n_h4lf}
```

(The 8-byte `chk` field wasn't identified. I recognized the plaintext as the only printable `CTF{…}` result.)

## Solver

```python
import json, sys
from math import gcd
sys.path.insert(0, ".")
from quern import *          # pss_encode, mgf1, H, os2ip, E

d = json.load(open("log.json"))
M = [int(m, 16) for m in d["moduli"]]
N = M[1]
s0 = int(d["log"][0]["s"], 16)
salt = bytes.fromhex("12588cf7b9b65a821fd6913d39893e92e3792f47e244d8cd049bab49d9edc5c5")
em = os2ip(pss_encode(b"release batch Z0 to vault", salt, N.bit_length() - 1))
p = gcd(pow(s0, E, N) - em, N)
assert 1 < p < N

def open_vault(v, secret):
    ct = bytes.fromhex(v["ct"])
    k = H(b"quern" + secret)
    return bytes(a ^ b for a, b in zip(ct, mgf1(k, len(ct))))

q = N // p
print("vault:", open_vault(d["vault"], q.to_bytes(64, "big") + p.to_bytes(64, "big")))
p0 = gcd(M[0], M[5])
print("decoy:", open_vault(d["decoy_vault"], p0.to_bytes(64, "big")))
```

## Takeaway
RSA-CRT signing must verify a signature before releasing it. PSS's randomized salt normally blunts fault attacks, but reusing a salt (or making it predictable) makes `em` recomputable, and a single faulty signature then factors the modulus.
