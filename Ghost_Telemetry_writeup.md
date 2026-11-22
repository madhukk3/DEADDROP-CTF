# Ghost Telemetry (500) — Signals / SSTV

> At 02:41 UTC, our listening post picked up an unscheduled burst from Relay 09...
> The transmission opens with an automated station voice followed by fifty seconds
> of raw carrier modulation. Analyze relay09.wav and recover the optical downlink.

**File:** `relay_09.wav`
**Flag:** `AIT{r34l_s1gn4l_1n_th3_b4s3}`

## Vulnerability
An **SSTV (Martin M1)** image hidden in the baseband carrier; drawn text up in
the high band is a decoy pointing you back to the baseband.

## Steps
1. Spectrogram of `relay_09.wav` (128 s, 48 kHz mono): station voice (0–11 s), a
   strong baseband carrier ~1200–2300 Hz from 13 s to the end, and drawn text at
   6–14 kHz (60–80 s).
2. High-band text is a **decoy**: `Nice_try_look_at_the_baseband;`
3. Baseband is SSTV: Hilbert-demodulate instantaneous frequency, find the 1900 Hz
   leader at 13.3 s, read the VIS code **172 (0xAC)** → data 44 = **Martin M1**
   (320×256, 114.3 s — matches the carrier length).
4. Decode Martin M1 (sync-pulse resync per line, G/B/R at 0.4576 ms/pixel,
   1500 Hz=black → 2300 Hz=white). Image: green terminal picture with the flag
   across the bottom.

> A hand-written ~25-line Martin M1 decoder was used (pip was blocked, no
> `qsstv`/`sstv`). Minor vertical squish from the fixed nominal line rate, but the
> flag text is sharp.
