# Tiny Key, Big Ego (500) — Crypto

> My friend said regular RSA is boring, so he "upgraded" it by stuffing his
> secret message into a polynomial. Unfortunately, he got lazy when picking his
> private key d and chose a tiny number so it would run faster on his laptop.

**File:** `chall.py`  ·  `nc 20.244.105.226 1337`
**Flag format:** `AIT{<secret>_<blake2s(secret)[:12]>}`
**Flag:** `AIT{p0lyn0m14ls_c4nt_s4v3_a_t1ny_pr1v4t3_k3y_b48ff6e6acf3}`

## Vulnerability
RSA over the ring `Z_N[x]/(x^8 - 1337)`, which splits into `GF(p^8) × GF(q^8)`,
so the group order is `phi = (p^8 - 1)(q^8 - 1) ≈ N^8`. The key satisfies
`e·d ≡ -1 (mod phi)` with `d` only **256 bits** → classic **Wiener small
private-exponent attack** (just over the giant modulus N^8).

## Steps
1. Pull `N`, `e`, and ciphertext `C` (polynomial) from the server.
2. Take continued-fraction convergents of `e / N^8`. Each `k/d` candidate gives
   `phi = (e·d + 1) / k`.
3. For the correct convergent, `C^d = m^{-1}` in the ring; invert via
   `m^{-1}^(phi-1)` to recover the 8×5-byte message chunks = the 40-byte secret.
   The printable-ASCII check confirms the right convergent.
4. Format: `AIT{secret_blake2s(secret)[:12]}`.

> Note: `p`/`q` are never recovered — the convergent directly yields a working
> `d` and `phi`. The server rekeys per connection, so this flag is tied to the
> data pulled during the solve.
