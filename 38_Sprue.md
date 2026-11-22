# Sprue — Hardware / I2C (500) — PARTIAL
> Cast once, then trimmed.

## Confirmed so far
- `bus.vcd` = 2-wire I2C logic capture (SCL='!', SDA='"'). Devices: **0x48** LM75 temp (noise/red herring), **0x68** RTC-ish (four 7-byte reads), **0x50** 24Cxx EEPROM (2-byte addressing).
- EEPROM header `SPRUE fw 2.3\x00\x01\x07\x40`. Two 64-byte ciphertext blobs at 0x0200 and 0x0300. 32-byte **key region at 0xe0**.
- **"Cast once then trimmed" = 24Cxx page-write wraparound** (32-byte pages): a 20-byte write to 0xf4 wraps inside its 0xe0–0xff page (0xf4..0xff then back to 0xe0), overwriting the key. The final key is **confirmed by an EEPROM readback at t=160 ms** (read of 0xe0 returns bf d9 53 16 a8…).
- Recovered key (`key.bin`) = `bfd95316a8f4b3505d98d6e485dec48b74c9f5d5cfaec57cd3f589ea6057fc81`.

## Not solved
Decrypting the two 64-byte blobs (`ct.bin`). Tried (all non-text): XOR(key-repeat / shake_256 / sha-CTR), AES-256 ECB/CTR/CBC/CFB/OFB, ChaCha20 with assorted nonces.

## Next steps
1. Use the **0x68 reads** (4×7 bytes) as IV/CTR-nonce/ChaCha-nonce.
2. Treat the 32 bytes as **AES-128 key + 16-byte IV**, or read the header `\x01\x07\x40` as scheme/mode selectors.
3. Try lightweight/IoT ciphers whose 256-bit key fits exactly (Speck128/256, etc.).
4. Rebuild the FULL final EEPROM image honoring every write's STOP + page wrap and dump 0x000–0x3ff — the real ciphertext region may differ from 0x200/0x300.

## Files
`../Sprue/` — `bus.vcd`, `sprue_i2c.py` (I2C decoder), `sprue_dump.txt` (ordered transactions), `solve.py` (page-wrap replay), `key.bin`, `ct.bin`, `sprue_brute.py`.

## Solve script(s)

### `sprue_i2c.py`
```python
# I2C decoder for bus.vcd: '!'=SCL '"'=SDA
import re
ev = []; t = 0; scl = sda = 1
for line in open('bus.vcd').read().split('$enddefinitions $end')[1].split():
    if line[0] == '#': t = int(line[1:]); continue
    v, s = int(line[0]), line[1]
    ev.append((t, s, v))
frames = []; cur = None; bits = []
for t, s, v in ev:
    if s == '"':
        if scl == 1 and sda == 1 and v == 0:   # START / repeated start
            if cur is not None and bits: cur['bytes'].append(bits)
            cur = {'t': t, 'bytes': []}; frames.append(cur); bits = []
        elif scl == 1 and sda == 0 and v == 1:  # STOP
            if cur is not None: cur['stop'] = t
            cur = None; bits = []
        sda = v
    else:
        if v == 1 and scl == 0 and cur is not None:   # rising SCL: sample
            bits.append(sda)
            if len(bits) == 9: cur['bytes'].append(bits); bits = []
        scl = v
out = []
for f in frames:
    bs = [b for b in f['bytes'] if len(b) == 9]
    vals = [(int(''.join(map(str, b[:8])), 2), 'A' if b[8] == 0 else 'N') for b in bs]
    out.append((f['t'], vals, 'stop' in f))
if __name__ == '__main__':
    for t, vals, st in out:
        if not vals: continue
        a = vals[0][0]
        print(f'{t/1e6:10.3f}ms addr {a>>1:#04x} {"R" if a&1 else "W"} ', ' '.join(f'{v:02x}{k}' for v, k in vals[1:]), '' if st else '(no stop)')

```

### `solve.py`
```python
# Sprue: replay I2C EEPROM traffic with 24Cxx page-write wraparound ("cast once, then trimmed")
import hashlib
from sprue_i2c import out
PAGE = 32
mem = {}; dev68 = []; ptr = None
for t, vals, stop in out:
    if not vals: continue
    a = vals[0][0]; addr, rd = a >> 1, a & 1; data = [v for v, _ in vals[1:]]
    if addr == 0x68 and rd: dev68.append(bytes(data))
    if addr != 0x50: continue
    if not rd:
        if len(data) < 2: continue                 # ACK polling
        ptr = (data[0] << 8) | data[1]
        if len(data) > 2 and stop:                 # a write only programs on STOP
            base = ptr & ~(PAGE - 1)
            for i, b in enumerate(data[2:]):
                mem[base + (ptr - base + i) % PAGE] = b
    else:
        for i, b in enumerate(data): mem.setdefault(ptr + i, b)   # reads reveal existing contents
        ptr += len(data)
blob = lambda a, n: bytes(mem.get(a + i, 0xff) for i in range(n))
print('hdr', blob(0, 16))
key = blob(0xe0, 32); print('key region', key.hex())
print('0x68 reads', [x.hex() for x in dev68])
ct = blob(0x200, 64) + blob(0x300, 64)
open('ct.bin', 'wb').write(ct); open('key.bin', 'wb').write(key)

```
