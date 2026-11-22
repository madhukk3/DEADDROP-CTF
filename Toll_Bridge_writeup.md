# Toll Bridge (500) — Crypto · CTF

> A cross-chain bridge locks coins on chain A and mints wrapped coins on chain B.
> Both keys live in one HSM. Its TRNG is slow, so the firmware authors were proud
> that every bridge transfer costs only a single draw from it.
>
> The treasury vault is encrypted as
> `vault XOR shake_256(d_A.to_bytes(32,'big') + d_B.to_bytes(32,'big'))`.
> We scraped everything public about the bridge, including an old operator key
> that was retired a while ago.

**File:** `bridge.json`
**Flag:** `CTF{0n3_n0nc3_tw0_curv3s_z3r0_s3cr3ts}`
**Decoy (do not submit):** `CTF{n0nc3_r3us3_1s_s0_2010_try_4g41n}`

## The trap (decoy)
The retired operator's two signatures share the same `r` → classic **nonce
reuse**, which hands you `d_legacy` instantly. That key decrypts `vault_backup`
to `CTF{n0nc3_r3us3_1s_s0_2010_try_4g41n}` — a troll that literally says "try
again." The real flag is in `treasury_vault` and needs the **current** `d_A`,
`d_B`.

## The real vulnerability
"A single TRNG draw per transfer" = the **same nonce `k` is reused across two
different curves**:
- Chain A: Schnorr / **BIP340 secp256k1** (key `d_A`)
- Chain B: **ECDSA / NIST P-256** (key `d_B`)

Each transfer produces one chain-A sig and one chain-B `mint` sig (paired by
`bridge_id`) using the **same integer `k`**. Since `k ≈ 2^255 < n1, n2` while the
combined modulus `N = n1·n2 ≈ 2^512`, `k` is *small* relative to `N`. CRT-combining
the two per-transfer signature equations turns it into one **Hidden Number
Problem** mod `N`, solvable by an **LLL lattice** that recovers `d_A` and `d_B`
simultaneously.

### The BIP340 wrinkle
BIP340 forces an **even-Y nonce point**, negating the raw draw `k` on chain A for
~half the transfers. So the shared integer is `±k` with an **unknown sign per
transfer**. With a modest number of transfers (t≈5), brute-force all 2^t sign
patterns; the correct one yields keys that verify against the public keys.

## Steps
1. Parse `bridge.json`: 12 chain-A (secp256k1) sigs paired with 12 chain-B
   (P-256) `mint` sigs by `bridge_id`, the two public keys, plus the legacy
   operator's reused-`r` pair and `treasury_vault` / `vault_backup`.
2. (Decoy) Recover `d_legacy` from the reused nonce; it opens only `vault_backup`.
3. Confirm conventions: chain B uses `z = SHA256(msg)`; chain A is BIP340.
4. Build the cross-curve CRT lattice; validate it on a synthetic instance first.
5. Brute the per-transfer sign pattern (2^t) → recover `d_A`, `d_B`; verify vs
   both pubkeys.
6. `flag = treasury_vault XOR shake_256(d_A.to_bytes(32,'big') + d_B.to_bytes(32,'big'))`.

## Solver (structure)
```python
import json, hashlib
from itertools import product
# n1 = secp256k1 order, n2 = P-256 order
# Per transfer i, each curve gives:  k = s_i^{-1} (z_i + r_i * d)   (mod n_curve)
# => a_i + b_i * d_curve ≡ k_i (mod n_curve), linear in the curve's private key.
# With the SAME k across both curves (up to BIP340 sign), eliminate k and CRT
# the two congruences into one modulus N = n1*n2, giving a small-k HNP.

def shake_xor(vault, dA, dB):
    ks = hashlib.shake_256(dA.to_bytes(32,'big') + dB.to_bytes(32,'big')).digest(len(vault))
    return bytes(a ^ b for a, b in zip(vault, ks))

# for each sign pattern over the chosen transfers, build the lattice rows,
# LLL-reduce, read (dA, dB) from the short vector, verify dA*G==PubA & dB*G==PubB:
for signs in product((1,-1), repeat=t):
    dA, dB = solve_lattice(transfers, signs)      # returns candidates
    if verify(dA, PubA) and verify(dB, PubB):
        print(shake_xor(treasury_vault, dA, dB).decode())
        break
# -> CTF{0n3_n0nc3_tw0_curv3s_z3r0_s3cr3ts}
```

> Reconstructed from the solve session (the verified cross-curve lattice +
> sign-brute lived in a cleared scratchpad). The method is exactly as run: legacy
> nonce-reuse = decoy; same `k` on two curves → CRT-HNP lattice; BIP340 even-Y
> sign brute; `shake_256(d_A‖d_B)` XOR opens the treasury. `bridge.json` is still
> in `~/Downloads` to re-run.
