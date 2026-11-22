# Trivet (500) — Crypto · CTF

> One exponent, several rooms. Each room shows you a different shadow of it, and
> no room shows enough. An older vault was keyed from a room that has since been
> closed off.

**Files:** `rooms.py` (firmware excerpt), `rooms.json` (public params + two sealed vaults)
**Flag:** `CTF{f0ur_sh4d0ws_0n3_3xp0n3nt_n0_r00m_w4s_3n0ugh}`
**Decoy (do not submit):** `CTF{4ll_r00ms_s4y_th3_0ld_k3y_w4s_sm00th_4nd_wr0ng}`
**Verified:** `solve.py` runs in ~7 s and prints the flag (re-run 2026-11-20).

## Setup
One secret `x < 2^344` keys the vault (`key = sha256(x.to_bytes(43,'big'))`).
Four live rooms each publish a different function of the **same** `x`:

| Room | Group | Order | Published exponent |
|---|---|---|---|
| A | `Z_p^*` 768-bit | `(p-1)/2` | `x` |
| B | `Z_p^*` 896-bit | `(p-1)/2` | `x^2` |
| C | norm-1 torus of `GF(p^2)` 704-bit | `(p+1)/2` | `x^-1` |
| D | `Z_p^*` 1024-bit | `(p-1)/2` | `x^2 + K·x` |
| E | `Z_p^*` 294-bit | `(p-1)/2` | its **own** secret `x_E` (closed-off room) |

## Vulnerability: every order is partly smooth
Each group order has a smooth part, so **Pohlig–Hellman** (BSGS per prime
subgroup) leaks the exponent modulo ~103–104 bits — deliberately short of 344,
so no single room is enough:
```
A: (p-1)/2 = 44673527·55887563·58106101·59304481 · (664-bit prime)  -> 103 bits
B: (p-1)/2 = ten ~11-bit primes (1061…1423)       · (791-bit prime)  -> 104 bits
C: (p+1)/2 = 47308133·54199363·57703279·59830999  · (600-bit prime)  -> 103 bits
D: (p-1)/2 = ten ~11-bit primes (1039…1409)        · (920-bit prime) -> 103 bits
E: (p-1)/2 = twelve ~25-bit primes                                   -> FULLY smooth
```

## Turning each shadow back into `x` (per prime q)
- **A**: residue *is* `x mod q`.
- **C**: residue is `x^-1 mod q` → invert it.
- **B**: residue is `x^2 mod q` → `sqrt_mod` gives **2** candidates for `x mod q`.
- **D**: residue `c` solves `x^2 + Kx ≡ c` → `x ≡ (-K ± sqrt(K^2+4c))/2 mod q`,
  again 2 candidates.

B and D sit on different primes from each other, so you can't subtract to isolate `Kx`.

## Recombination (CRT + meet-in-the-middle root search)
A and C pin `x` exactly mod `M_A·M_C` (206 bits). B and D add another 206 bits but
with `2^10 · 2^10 = 2^20` root combinations. CRT over all 28 small primes gives a
412-bit modulus `N`:
```
x = (base_AC + contrib_B + contrib_D) mod N ,  keep only lifts with x < 2^344
```
412 − 344 = 68 bits of slack, so a wrong combo survives with prob 2^-68; over
2^20 combos exactly **one** candidate remains. Enumerate the two halves separately
(1024 + 1024 precomputed CRT partial sums, then 2^20 adds) → seconds. Verify
against room A's `y`, then `unseal(x, vault)`.
```
x = 30141065926934141686427756423573968646064495800018526730108552628897425296504531639493704543599211253190
```

## The decoy (room E)
Room E is the "closed-off room" that keyed `vault_v1`. Its order is **fully**
smooth, so plain Pohlig–Hellman recovers `x_E` outright (~30 s) and opens
`vault_v1` → `CTF{4ll_r00ms_s4y_th3_0ld_k3y_w4s_sm00th_4nd_wr0ng}` — which the
text itself calls the wrong key. The real flag is in `vault`, under `x`.

## Solver
Full verified solver: `~/ctf/trivet/solve.py` (pure Python + sympy). Key pieces:
```python
# per prime q of each room's smooth order, BSGS the dlog:
#   A -> x mod q ;  C -> inverse ;  B -> sqrt (2 roots) ;  D -> (-K±sqrt(K^2+4c))/2
# CRT all 28 primes to modulus N (412 bits), split into:
base = A|C exact (206 bits)          # single value
Bp   = partial CRT sums over B primes (1024 combos)
Dp   = partial CRT sums over D primes (1024 combos)
for b in Bp:
    for d in Dp:
        x = (base+b+d) % N
        if x < 2**344 and pow(gA,x,pA)==yA:
            unseal(x, vault)         # -> CTF{f0ur_sh4d0ws_0n3_3xp0n3nt_n0_r00m_w4s_3n0ugh}
```

## Takeaway
Reusing one secret across groups is only as strong as the *union* of what leaks.
Each room leaked a legal, individually useless ~100 bits; CRT across four rooms
plus a 2^20 root search covered the whole 344-bit key. Algebraic relations
(`x^2`, `x^-1`, `x^2+Kx`) don't hide a secret — they only change which root you
have to guess.

> Working copies (`solve.py`, `rooms.py`, `rooms.json`, original `WRITEUP.md`)
> are in `~/ctf/trivet/`; `rooms.json` is also in `~/Downloads`.
