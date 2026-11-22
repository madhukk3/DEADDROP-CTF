# CTF Writeup — Recovered Flags

Date: 2026-11-19

This writeup covers the challenges from this session where the flag was successfully recovered.

## Recovered Flags

| Challenge | Category | Flag |
|---|---|---|
| Polynomial RSA / small private exponent | Crypto | `AIT{p0lyn0m14ls_c4nt_s4v3_a_t1ny_pr1v4t3_k3y_b48ff6e6acf3}` |
| `capture.pcap` | Network Forensics | `AIT{p4ck3t5_n3v3r_f0rg3t_0xdr0p}` |
| Big O Corp External Severance Portal | Web / Crypto | `AIT{r3pl4c3d_by_3xp1r3d_jwts_4nd_h3x}` |

---

## 1. Polynomial RSA — Small Private Exponent

**Files provided:** `chall.py`, remote service.

### Overview

The challenge implemented RSA over the polynomial ring

```text
Z_N[x] / (x^8 - 1337)
```

with `K = 8`, `R = 1337`, and public modulus `N = p*q`.

The private exponent `d` was chosen as a 256-bit number, while

```text
phi = (p^8 - 1)*(q^8 - 1) ~= N^8
```

So `d` is far too small for the size of the group.

The public exponent was generated as:

```python
e = pow(phi - d, -1, phi)
```

which means:

```text
e*d == -1 (mod phi)
```

### Attack

Since `phi ~= N^8`, the fraction `e / N^8` is extremely close to `e / phi`. Continued fractions of `e / N^8` recover the convergent `k / d`, where:

```text
e*d + 1 = k*phi
```

After recovering `d`, decryption follows from:

```text
C^d = (M^e)^d = M^(e*d) = M^(-1)
```

So the plaintext polynomial is the polynomial inverse of `C^d` modulo `x^8 - 1337`.

Each of the 8 recovered coefficients is a 5-byte big-endian chunk of the secret.

### Recovered Secret

```text
p0lyn0m14ls_c4nt_s4v3_a_t1ny_pr1v4t3_k3y
```

Blake2s of the secret, truncated to 12 hex characters:

```text
b48ff6e6acf3
```

### Flag

```text
AIT{p0lyn0m14ls_c4nt_s4v3_a_t1ny_pr1v4t3_k3y_b48ff6e6acf3}
```

---

## 2. `capture.pcap` — IRC and FTP Traffic

**File provided:** `capture.pcap`

### Traffic Analysis

Protocol hierarchy showed:

- IRC on TCP/6667
- FTP control on TCP/21
- FTP data streams

Following the IRC TCP stream revealed the conversation and FTP credentials:

```text
FTP host: 203.0.113.9
Username: drop
Password: fr33z1p2024
File: evidence.zip
```

Following the FTP control stream confirmed:

```text
USER drop
PASS fr33z1p2024
RETR evidence.zip
```

The ZIP file was extracted directly from the FTP-DATA stream:

```bash
tshark -r capture.pcap --export-objects ftp-data,ftpobjs -q
```

### ZIP Password

The ZIP was AES-encrypted. Its comment contained Base64:

```text
MW1jZWd0anc4dGhvbDBwag
```

With padding added:

```text
MW1jZWd0anc4dGhvbDBwag==
```

Decoding gives the ZIP password:

```text
1mcegtjw8thol0pj
```

### Extraction

```bash
7z x -p'1mcegtjw8thol0pj' evidence.zip -oextracted
```

The extracted `root.txt` contained the flag.

### Flag

```text
AIT{p4ck3t5_n3v3r_f0rg3t_0xdr0p}
```

---

## 3. Big O Corp External Severance Portal — JWT Forgery

**Provided:** `http://20.244.105.226:8081`, `email.jpg`

### Email Image and Steganography

The JPEG metadata contained the comment:

```text
Not all hexes are bad. steghide/openstego
```

The email image displayed the employee ID:

```text
EMP4e6f4f644c6553
```

The hex portion `4e6f4f644c6553` decodes to:

```text
NoOdLeS
```

This was also the steghide passphrase:

```bash
steghide extract -sf email.jpg -p NoOdLeS
```

The hidden `secrets.txt` contained:

```text
Claim at port 5173
```

### API Enumeration

The portal exposed:

```text
POST /api/sandbox-login
GET  /api/packet/<emp_id>
```

The sandbox login returned an HS256 JWT with payload similar to:

```json
{
  "emp_id": "EMP4775657374",
  "role": "employee"
}
```

Requesting another employee ID returned:

```text
Access denied. Active session is bound to EMP4775657374.
```

With the email employee ID, the server returned:

```text
Portal access expired (48-hour severance window exceeded).
Big O Corp Administration override required.
```

### Weak JWT Secret

The JWT was signed with the weak secret:

```text
severance
```

### Forged Token

A new token was forged with the target employee ID and an admin role:

```json
{
  "emp_id": "EMP4e6f4f644c6553",
  "role": "admin"
}
```

Requesting:

```http
GET /api/packet/EMP4e6f4f644c6553
```

returned:

```text
ADMIN_OVERRIDE_APPROVED
```

and the compensation packet contained the flag.

### Flag

```text
AIT{r3pl4c3d_by_3xp1r3d_jwts_4nd_h3x}
```

---

## Lessons

- Small private exponents remain dangerous even when the modulus is moved into a larger algebraic structure.
- Capture analysis often chains several weak points: plaintext IRC, reused FTP credentials, and a ZIP password hidden in metadata.
- JWT `role` claims must be signed server-side with a strong secret; a weak HS256 secret allows complete authorization bypass.
- Metadata and steganography are still common sources of credentials and hints.
