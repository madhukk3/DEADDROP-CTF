# InstaSnoop

The capture had an FTP session in it. The interesting file was an AES-encrypted ZIP that came across the data channel.

The ZIP comment was base64:

```
1mcegtjw8thol0pj
```

That decoded to the archive password. I used `7z` to extract it and the flag was in the extracted file:

`AIT{p4ck3t5_n3v3r_f0rg3t_0xdr0p}`

The lesson was simple: check the ZIP comment before attacking the AES. The password was sitting in plain sight in the metadata.
