# Cairn — Cryptography (500)
**Flag:** `CTF{b0rr0w_0n3_st0n3_fr0m_3v3ry_c41rn_4nd_th3_p4th_1s_y0urs}`

> A heap of stones by the road.

## Idea
A hash-based (Winternitz WOTS) one-time-signature scheme under a 16-leaf Merkle tree, but the log holds **64 signatures** — so every one-time key is reused ~4 times. The vault order's R is fixed → it maps to leaf 13 with known target digits tᵢ. WOTS signs by hashing a secret forward dᵢ times; because a chain value at digit dᵢ can be **hashed forward** to any digit ≥ dᵢ, you can forge a signature for larger target digits from a reused leaf-13 signature whose digit is ≤ tᵢ.

For each of the 35 chains (32 message nibbles + 3 checksum), pick a logged leaf-13 signature with digit ≤ tᵢ and hash it forward `tᵢ − dᵢ` times. The forged signature passes `verify()`, and `h("vault", *forged)` opens slot 0.

## How to reproduce
```bash
cd "../Cairn"
$PY solve.py    # verifies all 64 log sigs, builds the forgery, checks it, unseals slot 0 -> flag
```
Slot 1's tag doesn't match this key and stays sealed (unrelated to this flag).

## Solve script(s)

### `solve.py`
```python
# Cairn solver: WOTS one-time keys reused across many logged signatures -> forge the vault order.
import json
from cairn import *

L = json.load(open("log.json")); V = json.load(open("vault.json"))
pub = {"seed": bytes.fromhex(L["seed"]), "root": bytes.fromhex(L["root"])}
seed, M, R = pub["seed"], V["order"].encode(), bytes.fromhex(V["R"])
leaf, target = leaf_index(R, M), digits(seed, R, M)
print("target leaf", leaf)

best = [None] * LEN  # per chain: (digit, value) with smallest digit <= target
auth = None
for e in L["log"]:
    m = e["msg"].encode()
    assert verify(pub, m, e), e["msg"]
    r = bytes.fromhex(e["R"])
    if leaf_index(r, m) != leaf: continue
    auth = e["auth"]
    d = digits(seed, r, m)
    for i in range(LEN):
        if d[i] <= target[i] and (best[i] is None or d[i] > best[i][0]):
            best[i] = (d[i], bytes.fromhex(e["wots"][i]))
assert all(best), "missing chains: %s" % [i for i in range(LEN) if not best[i]]

sig = [walk(seed, leaf, i, v, d, target[i] - d) for i, (d, v) in enumerate(best)]
s = {"R": V["R"], "wots": [x.hex() for x in sig], "auth": auth}
assert verify(pub, M, s), "forgery failed"
key = h(b"vault", *sig)
for slot in V["slots"]:
    print(unseal(key, slot))

```
