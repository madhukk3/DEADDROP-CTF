# Undertow (500) — RF / Signals · CTF

> Our rooftop receiver at 868.1 MHz recorded all night. This is the only stretch
> anyone thought was interesting, and the loud parts were the first things we
> decoded. Those turned out to be nothing. Something else is talking under the
> surface.

**Files:** `capture.sigmf-data`, `capture.sigmf-meta`
**Flag:** `CTF{und3r_th3_n01s3_fl00r_ch1rps_s1ng}`

## Vulnerability
A faint, low-power **LoRa** packet hidden beneath two loud decoy chirp bursts,
sitting ~1.5% above the noise floor so it's invisible in the overall power level.
"Chirps sing" under the noise → LoRa CSS modulation.

## Capture
SigMF, 8-bit IQ @ **1 Msps**, ~2.6 s, tuned to **868.1 MHz** (EU LoRa channel).
- The two loud bursts (~0.1 s and ~1.9 s) are 125 kHz chirps at about −312 kHz →
  the "nothing" the description warns about.
- Between 0.3 s and 1.85 s there's a **second 125 kHz signal at ~+219 kHz** that
  only raises total power ~1.5% — the real signal.

## Steps
1. **Isolate** the faint signal: frequency-shift ~+219 kHz to baseband, low-pass /
   decimate to 125 kHz bandwidth.
2. **Identify the LoRa parameters:** test each spreading factor — **SF11** stands
   out by a wide margin.
3. **Sync:** the packet starts with 9 repeated up-chirps (preamble), 2 sync
   symbols (40 and 96 → **sync word 0x5C**), then 2.25 down-chirps. Use these to
   fix the frequency offset and symbol timing → **72 clean data symbols**.
4. **Demodulate/decode:** every symbol ≡ 1 (mod 4) ⇒ **reduced-rate mode (LDRO)**.
   No length header ⇒ **implicit header**, strongest FEC ⇒ **CR4/8**. Apply the
   LoRa pipeline: Gray decode → deinterleave → Hamming(8,4) correct → dewhiten →
   dehuffman/CRC. Result is the flag followed by 2 trailing CRC-ish bytes (`"b`).

## LoRa decode pipeline (structure)
```python
import numpy as np
x = read_sigmf("capture.sigmf-data")        # complex64 @ 1 Msps
x = shift(x, +219e3, fs=1e6)                 # move faint signal to baseband
x = resample(x, 1e6, 125e3)                  # 125 kHz BW
SF, BW = 11, 125e3
# dechirp with the down-chirp, FFT per symbol, argmax -> raw symbol
syms = demod_css(x, SF, BW, preamble=9, sync=[40,96])   # -> 72 symbols
# LDRO: drop 2 LSBs; implicit header, CR4/8:
bits = gray_deinterleave_hamming(syms, sf=SF, cr=4, ldro=True)
data = dewhiten(bits)
print(bytes(data))   # -> CTF{und3r_th3_n01s3_fl00r_ch1rps_s1ng} + CRC
```

## Notes
- The loud −312 kHz bursts are pure decoys ("the loud parts were nothing").
- Key insight: a signal only ~1.5% above the noise floor won't show in a power
  plot — you find it by scanning the spectrum for the off-center 125 kHz band and
  testing SFs, not by looking at amplitude.

> Reconstructed from the solve session (final decoder `j.py` + `c.py`/`bb.npy`
> were in a cleared scratchpad). `capture.sigmf-data` / `capture.sigmf-meta` are
> still in `~/Downloads` to re-run.
