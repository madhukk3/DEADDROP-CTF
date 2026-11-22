# No Plaintext on 56k (499) — Forensics / Signals

> Someone used an ancient dial-up setup to sneak a message past our monitoring...
> Plaintext inspection turned up nothing — see if you can pull their message off
> the wire. Wrap the result in AIT{...}

**File:** `chall.pcapng`
**Flag:** `AIT{56K_SECRET_BEEP}`

## Vulnerability
A UDP/5004 **RTP** stream carrying G.711 µ-law "modem" audio that is really a
single tone gated **on/off = OOK Morse code**.

## Steps
1. Decode UDP/5004 as RTP → payload type 0 (G.711 µ-law). SSRC `0x35364b00`
   spells "56K\0" (a hint).
2. Carve RTP payloads, µ-law-decode to 8 kHz PCM.
3. Spectrogram shows one carrier switched on/off → **OOK Morse**. Run-lengths:
   ~75 ms unit (dot) vs ~225 ms (dash).
4. Decode Morse → `56K_SECRET_BEEP`.

## Solver (sketch)
```bash
tshark -r chall.pcapng -d udp.port==5004,rtp -T fields -e rtp.payload > pay.hex
# -> reassemble, mu-law decode to PCM, threshold amplitude envelope,
#    measure on/off run lengths, map to Morse -> 56K_SECRET_BEEP
```
