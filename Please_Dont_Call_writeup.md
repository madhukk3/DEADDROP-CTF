# Please Dont Call (350) — Forensics / Stego

> An old Christmas recording, a number that was never called, and a message
> that was never sent. Some things are better left unsaid. Others are hidden in
> the noise.

**Files:** `voicemail.zip` (AES-encrypted), `please-dont-call.wav`
**Flag:** `AIT{D14L3D_BUT_N3V3R_C4LL3D}`

## Vulnerability
AES-encrypted ZIP whose password ("the number that was never called") is hidden
as **DTMF touch-tones** in the right audio channel.

## Steps
1. `voicemail.zip` is AES-encrypted → needs a password first.
2. The right channel of the WAV carries DTMF beeps (left channel is silent).
   Decode with `multimon-ng` → **`6789998212`**.
3. Use that as the ZIP password → extract `unsent_note.txt` (a Christmas-Eve
   note). Last line is the flag.

## Solver
```bash
# split right channel and decode DTMF
sox please-dont-call.wav -c 1 right.wav remix 2
multimon-ng -a DTMF -t wav right.wav        # -> 6789998212
unzip -P 6789998212 voicemail.zip
tail -n1 unsent_note.txt                     # -> AIT{D14L3D_BUT_N3V3R_C4LL3D}
```
