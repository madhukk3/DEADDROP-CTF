# Sundial (500) — Crypto

> Fifty-three envelopes. It still keeps time.

**Files:** `ceremony.json`, `dealer.py`
**Flag:** `CTF{4ll_th3_h0urs_4dd_t0_n00n_wh3n_th3_g0lds_c4nc3l}`

## Overview

`dealer.py` implements a 53-of-53 Shamir secret sharing ceremony over prime `P`:

- `coefficients()` — `f(x) = s + c1·x + … + c52·x^52`, where `c_i = H("coef", s, i) mod P`
- `seat(j) = h^(1 + j·(P−1)/53) mod P`, so the x-coordinates are unknown (they depend on a secret `h`)
- The shares are shuffled, so we don't know which seat each envelope belongs to
- `ceremony.json` gives `P`, all 53 shares and 3 sealed `slots` (`{ct, tag}`), encrypted with a SHA-256 counter-mode keystream plus a truncated HMAC tag

## Vulnerability: seats form a coset of the 53rd roots of unity

`(P − 1) % 53 == 0`. Let `ω = h^((P−1)/53)`, a 53rd root of unity. Then

```
seat(j) = h · ω^j        for j = 0..52
```

The seats are `h` times every 53rd root of unity, i.e. 53 evenly spaced "hours" on a dial.

For any `k` with `0 < k < 53`, `Σ_j ω^(jk) = 0`. Summing the polynomial over every seat:

```
Σ_j f(h·ω^j) = Σ_k c_k · h^k · Σ_j ω^(jk) = 53 · c_0 = 53 · s
```

All non-constant terms cancel ("the golds cancel"), so

```
s = (Σ shares) · 53^(-1) mod P
```

This needs no x-coordinates, and the shuffle doesn't matter.

### Verification
I rebuilt `f` from `s` using the script's own coefficient rule. Then I found roots of `f(x) − share_i` (polynomial gcd with `x^P − x` plus Cantor–Zassenhaus). Every share gives a root `x` with the same `x^53 = h^53`, which confirms `s`. All 53 shares land on the coset `{x0·ω^k}`.

## Opening the slots

The key derivation for `seal()` isn't shipped ("secrets lived in the HSM"). I brute-forced `H(label, value)` with a wordlist of labels against the HMAC tags:

| Slot | Key | Plaintext |
|---|---|---|
| 0 | `H(b"vault", b32(s))` | `CTF{4ll_th3_h0urs_4dd_t0_n` |
| 2 | `H(b"sundial", b32(h^53))` | `00n_wh3n_th3_g0lds_c4nc3l}` |
| 1 | not found (56 bytes, likely a decoy) | — |

`h^53` is the one value every seat shares: the "time" the sundial still keeps.

## Solver

```python
import json, hashlib, hmac
d = json.load(open("ceremony.json")); P, N, S = d["P"], d["SEATS"], d["shares"]

def H(*parts):
    h = hashlib.sha256()
    for p in parts: h.update(len(p).to_bytes(2, "big") + p)
    return h.digest()
def ks(key, n):
    o, c = b"", 0
    while len(o) < n: o += hashlib.sha256(key + c.to_bytes(4, "big")).digest(); c += 1
    return o[:n]
def open_slot(key, slot):
    ct = bytes.fromhex(slot["ct"])
    if hmac.new(key, ct, hashlib.sha256).hexdigest()[:32] != slot["tag"]: return None
    return bytes(a ^ b for a, b in zip(ct, ks(key, len(ct))))

B = lambda v: v.to_bytes(32, "big")
s = sum(S) * pow(N, -1, P) % P
# x0 = a root of f(x) - S[0] (found via polynomial gcd / Cantor-Zassenhaus)
x0 = 19867186306414572232402120696417565052866266341397752951555181750575792378107
h53 = pow(x0, N, P)

print(open_slot(H(b"vault", B(s)), d["slots"][0]) +
      open_slot(H(b"sundial", B(h53)), d["slots"][2]))
```

## Takeaway
Never evaluate Shamir shares on a multiplicative subgroup (or a coset of one) whose order is at least the polynomial's degree + 1. The sum over the subgroup leaks the constant term directly.
