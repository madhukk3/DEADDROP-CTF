# Writeup: Glitch Probe

## 1. Challenge Overview
* **Target:** Firmware-signing HSM using standard **ECDSA** on curve `secp256k1`.
* **Side-channel:** An EM probe captures bits 108–147 (a **40-bit middle window**) of each 256-bit nonce $k$:
  $$\text{probe}_i = (k_i \gg 108) \ \& \ (2^{40} - 1)$$
* **Data given:** 64 signatures $(r_i, s_i)$, public key $Q$, message hashes $z_i$, and an encrypted flag:
  $$\text{flag} = \text{ciphertext} \oplus \text{SHAKE-256}(d\text{.to\_bytes}(32, \text{'big'}))$$
* **Catch:** The ADC is cheap and glitches periodically—around 33% (21/64) of the captured probe values are corrupted.

---

## 2. The Vulnerability: Middle-Bit Nonce Leakage (EHNP)

In standard ECDSA, the signing equation is:
$$s_i \equiv k_i^{-1} (z_i + r_i d) \pmod n \iff k_i \equiv s_i^{-1} z_i + s_i^{-1} r_i d \pmod n$$

Let $A_i = s_i^{-1} r_i \pmod n$ and $B_i = s_i^{-1} z_i \pmod n$:
$$k_i \equiv A_i d + B_i \pmod n$$

Because the known bits are in the middle (bits 108–147), each 256-bit nonce splits into three chunks:
$$k_i = k_{i,\text{low}} + 2^{108} \cdot \text{probe}_i + 2^{148} \cdot k_{i,\text{high}}$$

* $k_{i,\text{low}}$ is **unknown** (108 bits, $< 2^{108}$)
* $\text{probe}_i$ is **known** (40 bits)
* $k_{i,\text{high}}$ is **unknown** (108 bits, $< 2^{108}$)

This is an **Extended Hidden Number Problem (EHNP)** with two small unknowns per signature instead of one.

---

## 3. Eliminating the Private Key ($d$)

The private key $d$ is 256 bits (not small), but it is shared across all signatures. We can eliminate $d$ by pairing every signature $i$ against a reference signature (signature 0):

$$d \equiv A_0^{-1}(k_0 - B_0) \pmod n$$

Substitute $d$ into signature $i$:
$$k_i - A_i A_0^{-1} k_0 \equiv B_i - A_i A_0^{-1} B_0 \pmod n$$

Let $C_i = A_i A_0^{-1} \pmod n$ and $D_i = B_i - C_i B_0 \pmod n$. Plugging in the 3-part nonce breakdown and moving all known values to the right side gives:
$$(k_{i,\text{low}} + 2^{148} k_{i,\text{high}}) - C_i (k_{0,\text{low}} + 2^{148} k_{0,\text{high}}) \equiv T_i \pmod n$$

where $T_i \equiv D_i - 2^{108} \cdot \text{probe}_i + C_i \cdot 2^{108} \cdot \text{probe}_0 \pmod n$.

Now **all unknowns are $\le 108$ bits**.

---

## 4. Lattice Reduction (LLL)

We take a small batch of $u = 10$ signatures:
* Leaked information: $10 \times 40 = 400\text{ bits} \gg 256\text{ bits}$ (the system is over-determined).
* Setting up a standard Kannan-embedding lattice of dimension $(2u + 1) \times (2u + 1) = 21 \times 21$ and running **LLL** (`fpylll`) isolates the small nonce parts $(k_{0,\text{low}}, k_{0,\text{high}})$ in the shortest vector in $< 0.1$ seconds.
* Once $k_0$ is assembled, $d$ is computed directly:
  $$d = A_0^{-1}(k_0 - B_0) \pmod n$$

---

## 5. Overcoming Glitched Probes (RANSAC)

Because ~21 out of the 64 probes are corrupt, feeding a bad probe into the lattice destroys the short-vector property.

Instead of complex error-correction math, we use **RANSAC** (Random Sample Consensus):
1. Pick 10 random signatures out of the 64.
2. Build the lattice and run LLL.
3. Check if the recovered $d$ satisfies $d \cdot G == Q$.
4. If it matches, stop! If not, pick another random 10 and retry.

**Probability of drawing 10 clean signatures in one try:**
$$P(\text{clean}) = \frac{\binom{43}{10}}{\binom{64}{10}} \approx 1.69\% \quad (\approx 1 \text{ in } 59 \text{ tries})$$

Each trial takes milliseconds, so 60–70 trials take less than **5–10 seconds** total. The algorithm hit an all-clean subset on **trial 65**.

---

## 6. Flag Recovery

1. **Recovered Private Key:**
   ```text
   d = 0x3407d20e0e634a9f9837dd4df2fa2aee4d447c822bb572fb811d028dae1305cf
   ```

2. **Flag Decryption:**
   ```python
   import hashlib

   key = hashlib.shake_256(d.to_bytes(32, "big")).digest(len(enc_flag))
   flag = bytes(c ^ k for c, k in zip(enc_flag, key))
   print(flag.decode())
   ```

3. **Flag:**
   ```text
   CTF{l4tt1c3s_d0nt_c4r3_4b0ut_y0ur_gl1tch3s}
   ```
