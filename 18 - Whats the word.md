# What's the word?

The attachment was a malformed OLE `.doc`. `office2john` would not touch it at first because the OLE structure was broken in two places.

The fixes were:

- at offset `0x38`, change the mini-stream cutoff to `512`
- terminate the `EncryptionInfo` FAT chain, entry 3 to `0xFFFFFFFE`

After that `office2john` produced an `$office$*2013*...` hash. I ran `rockyou.txt` through John and let it sit. It took around 70 minutes before it printed:

```
chiquita123
```

Decrypting the document and unzipping the docx gave `word/media/image1.png`. The flag was rendered into that image as text:

`AIT{w0rd_t0_th3_w1s3}`

The crack was the slow part. The OLE repair was the part that actually mattered, because without it the hash never got generated.
