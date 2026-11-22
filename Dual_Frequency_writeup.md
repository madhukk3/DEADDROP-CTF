# Dual Frequency (350) — Crypto

> We intercepted two short transmissions sent minutes apart by the same field
> operator. Neither message is long enough for statistical frequency analysis,
> and we suspect the operator reused the same session key for both transmissions.

**Files:** `intercept_1.txt`, `intercept_2.txt`
**Flag:** `AIT{tw0_m3ss4g3s_0n3_k3y}`

## Vulnerability
Vigenère cipher with a **reused key** across two short messages. The key only
advances on letters (spaces/digits/punctuation pass through unchanged), so a
guessed crib in one message reveals key bytes that decrypt the other.

## Steps
1. Key reuse means a known-plaintext guess in message 2 recovers key letters,
   which must turn message 1 into English. Tried every 7-letter dictionary word
   as the start of message 2; only `PACKAGE` produced a real word (`STATUS`) in
   message 1 → key starts `PHANTO`.
2. Guessing message 1 starts with `Status report` extended the key to
   `PHANTOMFREQU` → obviously `PHANTOMFREQUENCY`.
3. Decrypt both:
   - intercept_1: `Status report: backup relay online. Awaiting secondary key.`
   - intercept_2: `Package verified: AIT{tw0_m3ss4g3s_0n3_k3y}`

## Solver
```python
def dec(ct, key):
    out, ki = [], 0
    for ch in ct:
        if ch.isalpha():
            k = ord(key[ki % len(key)].upper()) - 65
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return ''.join(out)

key = "PHANTOMFREQUENCY"
print(dec(open("intercept_2.txt").read(), key))   # -> ... AIT{tw0_m3ss4g3s_0n3_k3y}
```
