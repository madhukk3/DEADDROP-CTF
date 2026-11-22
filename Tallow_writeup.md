# Tallow (500) — Forensics · CTF

> Nothing is ever fully melted down.

**Files:** `ledger.db`, `ledger.db-wal`
**Flag:** `CTF{th3_c4ndl3_r3m3mb3rs_th3_sh4p3_0f_th3_0ld_m0uld}`
**Decoy (do not submit):** `CTF{r0t4t3d_k3ys_0p3n_r0t4t3d_d00rs_0nly}`

## Vulnerability
A rotated encryption key whose **old key parts were deleted from SQLite but
survive as freed cells** in the raw database/WAL pages. "Deleting" a row in
SQLite only unlinks its cell; the bytes stay on the page until overwritten.

## The scheme (from the `meta` table)
```
sealed = ('TLW1' || plaintext) XOR sha256(K || be32(ctr))
K      = sha256(b'tallow' || material of every part of the slot, in order)
# "parts are wiped on rotation"
```

## Steps
1. **Preserve evidence first.** Copy both `ledger.db` and `ledger.db-wal` and
   `chmod 444` them. Opening the live DB with `sqlite3` triggers a WAL checkpoint
   that **deletes the -wal file** — losing the deleted data you need.
2. **The decoy.** The live `keyring` table only holds slot `active` (the 32-byte
   *post-rotation* material). Its key `K=sha256('tallow'+active)` opens vault
   row 2 (`archive`) → `CTF{r0t4t3d_k3ys_0p3n_r0t4t3d_d00rs_0nly}` — the decoy
   that literally tells you rotated keys only open rotated doors.
3. **The wiped parts.** The real slot was split into parts `active.a` and
   `active.b`, deleted on rotation. They do **not** appear in any WAL *logical
   snapshot* (replaying all 17 WAL prefixes shows only `active`), but they persist
   as **freed cells** in the raw page images: db **page 15** and **WAL frame 14**'s
   copy of page 15. Cell header `05 1d 2c 04 00` = `text(8) + blob(16) + int(4) +
   NULL`.
   - `active.a = 9eec88b55d9295bb2ac6d35562a2ca5c`
   - `active.b = ebfe4e64feb234c2a8dde95d1b6cd2a2`
4. **Rebuild the key and decrypt.** `K = sha256(b'tallow' + a + b)`, counter from
   0 → vault row 1 (`batch-17`) decrypts with the `TLW1` magic intact → flag.

## Solver
```python
import hashlib, struct

# --- carved freed-cell material (db page 15 / WAL frame 14) ---
a = bytes.fromhex("9eec88b55d9295bb2ac6d35562a2ca5c")
b = bytes.fromhex("ebfe4e64feb234c2a8dde95d1b6cd2a2")

K = hashlib.sha256(b"tallow" + a + b).digest()

def unseal(sealed, K):
    out = bytearray()
    ctr = 0
    for i in range(0, len(sealed), 32):
        ks = hashlib.sha256(K + struct.pack(">I", ctr)).digest()
        out += bytes(x ^ y for x, y in zip(sealed[i:i+32], ks))
        ctr += 1
    return bytes(out)

# sealed blob of vault row 1 ('batch-17'), pulled from the DB:
sealed = bytes.fromhex("<batch-17 sealed hex from ledger.db>")
pt = unseal(sealed, K)
assert pt[:4] == b"TLW1"
print(pt[4:].decode())   # -> CTF{th3_c4ndl3_r3m3mb3rs_th3_sh4p3_0f_th3_0ld_m0uld}
```

## Carving the freed cells (how `active.a`/`active.b` were recovered)
```python
# read the raw file, slice page 15 (page_size from the 16-bit value at offset 16),
# and WAL frame 14's page image, then scan for the cell header 05 1d 2c 04 00.
# The 8-byte text is the part name ('active.a'), the following 16-byte blob is
# the material. Both appear only as freed (unlinked) cells, not in live tables.
```

> Reconstructed from the solve session (`carve2.py` / `unseal.py` were in a
> cleared scratchpad). The carved material bytes above are the exact values
> recovered. The `notes` table and the word-list in the `active` note are noise.
> Fill the `batch-17` sealed hex from your preserved `ledger.db` copy to re-run.
