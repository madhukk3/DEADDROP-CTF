# Dead Air (420/500) — Forensics / Crypto / Stego

> A television station went offline years ago. An encrypted backup was recovered
> containing hundreds of archived broadcast frames. One frame contains something
> that was never meant to air.

**Files:** `station_manifest.bin`, `offair_backup.img.gz`
**Flag:** `AIT{THE_L4ST_S!GN4L_W4S_NEVER_SENT}`
**Decoys (do not submit):** `AIT{THE_STATION_NEVER_EXISTED}`, `AIT{THE_L4ST_S!GN4L_W4S_NEVER_SENT}` is the real one.

## Vulnerability
A LUKS2 container (unlockable in userspace without root) whose ext4 holds ~851
PNG frames; one frame hides the flag as **LSB-in-blue stego confined to one
scanline**, distinguished from a decoy frame by PNG `tEXt` metadata.

## Steps
1. `station_manifest.bin` is a plain ZIP → `recovery_note.txt` gives the LUKS
   passphrase **`NightShift0417`** (Backup ID STN-0417).
2. `offair_backup.img.gz` → 345 MB **LUKS2** container. With no root, derive the
   master key in userspace: argon2id → AES-XTS decrypt keyslot 0 → AF-merge
   (4000 stripes/SHA-256) → verify vs PBKDF2 digest → AES-XTS decrypt data
   segment. (Or `cryptsetup luksOpen` / `udisksctl unlock` if you have rights.)
3. Read the ext4 with `debugfs` (no mount): 851 PNG frames + two notes.
4. PNG `tEXt` splits them:
   - `FRAME_0217` — `ArchiveNote: synthetic_signal`, comment `AIT{THE_STATION_NEVER_EXISTED}` → **decoy** (synthetic frame).
   - `FRAME_0714` — `ArchiveNote: carrier_lock`, `Comment: Unscheduled transmission` → **real** (log: "the carrier settled and held").
5. Frames are grayscale with a fixed tint (`G=R+6`, `B=R+14`). In `FRAME_0714`,
   150 pixels break it — all in **row 6** ("the picture stabilized on the
   seventh line"). Reading `B & 1` across row 6 MSB-first → flag in first 35 bytes.

## Solver (stego stage)
```python
from PIL import Image; import numpy as np
a = np.array(Image.open("FRAME_0714.png").convert("RGB"))
bits = (a[6,:,2] & 1)                     # blue LSB of row 6
by = bytes(int(''.join(map(str,bits[i:i+8])),2) for i in range(0,len(bits)//8*8,8))
print(by[:35])                            # -> AIT{THE_L4ST_S!GN4L_W4S_NEVER_SENT}
```
