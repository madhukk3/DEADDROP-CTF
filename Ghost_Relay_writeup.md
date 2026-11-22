# Ghost Relay (500) — Reversing

> An unrouted packet dump drop.pkt was pulled off a decommissioned 1990s backbone
> switch, paired with a stripped routing daemon relay. ... Three invalid frames
> will expire the TTL and wipe the buffer. Keep a backup copy of drop.pkt.

**Files:** `relay` (ELF binary), `drop.pkt`
**Flag:** `AIT{d34d_dr0p_b3tw33n_th3_fr4m3s}`

## Vulnerability
The whole "feed valid frames / TTL purge" protocol is theatre. The flag already
sits in `drop.pkt` in a third message blob that `relay` only reveals after two
key checks — but those checks **gate the on-screen flow, not the data**. The
blob is decryptable offline, so the live file is never touched.

## Steps
1. `drop.pkt` = `DROP` header + three XOR-obfuscated status messages + 20-byte
   hash + payload. The "invalid frame" counter / TTL-purge (overwriting
   `drop.pkt` with `/dev/urandom`) is a **trap** to destroy the file on brute force.
2. Each message is encrypted with a hardcoded 64-bit seed driving a **xorshift
   PRNG keystream** (routine at `0x401316`, hidden behind SIGILL/SIGFPE signal
   handlers so it reads like crash code in a disassembler).
3. Message 3's seed is `0x10600a7c0b7ca1c5`. XOR the blob with that keystream →
   plaintext containing the flag. The two "link key" / "routing key" checks never
   gate the data.

> Never ran `relay` or transmitted a frame → the TTL-purge never fired; a backup
> of `drop.pkt` was kept regardless. The key-validation hashes guard message
> sequencing, not the flag.
