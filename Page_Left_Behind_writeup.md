# Page Left Behind (500) — Signals / Forensics

> An old audio file... begins with a peculiar sequence of electronic tones...
> He often mentioned how connecting to the internet used to sound different.

**File:** `chall.wav`
**Flag:** `AIT{d3m0dul4t3d_4n_0ld_ch4t_succ3ssfu11y}`

## Vulnerability
Dial-up handshake audio with a **Bell 202 AFSK** (1200/2200 Hz) data burst that
demodulates to a base64-encoded captured HTTP exchange; the flag is a **ROT13'd
HTML comment** inside it.

## Steps
1. `chall.wav` is 60 s @ 48 kHz. Energy-segmentation: ring tones (440/480 Hz),
   V.8 answer tone 2100 Hz, handshake tones, then a **14.3 s data burst at
   10.0–24.3 s** with 1200/2200 Hz carriers → Bell 202 AFSK.
2. Carve + demodulate:
   ```bash
   sox chall.wav data.wav trim 10 14.3
   minimodem -r -f data.wav 1200     # -> base64 blob
   ```
   (First two chars lost in carrier lock-on; `R0` restores the `GET`.)
3. Base64-decode → a captured HTTP/1.0 request+response (a "BlueRoom Chat" page).
4. Flag is in an HTML comment, **ROT13**'d → `AIT{d3m0dul4t3d_4n_0ld_ch4t_succ3ssfu11y}`.

> A fuller walkthrough was also saved to `~/Desktop/page-left-behind-walkthrough.md`.
