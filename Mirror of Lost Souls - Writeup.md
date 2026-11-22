# Mirror of Lost Souls — Writeup

- **CTF:** DeadDrop CTF
- **Category:** Forensics
- **Points:** 500
- **Flag:** `AIT{b3y0nd_th3_v3il_0f_s0uls}`

## Challenge
> Whispers tell of a cursed relic left behind by the departed. Every soul who gazes into it sees something different — a hollow reflection on the surface, a fractured shadow beneath, and a deeper truth waiting beyond the veil.

File: `mirror_of_souls` (a 370×370 PNG image).

The description maps directly to **three nested layers**:
1. "hollow reflection on the surface" → the visible PNG.
2. "fractured shadow beneath" → data appended **after** the PNG's `IEND`.
3. "deeper truth beyond the veil" → something embedded inside that appended data.

## Step 1 — Identify the file
```bash
file mirror_of_souls      # PNG image data, 370 x 370, 8-bit/color RGB
```

## Step 2 — Find the appended layer (shadow beneath)
A valid PNG ends at the `IEND` chunk. Anything after it is extra. Carving from
`IEND`+8 revealed **2697 trailing bytes** that were an SVG document:

```python
d = open('mirror_of_souls','rb').read()
i = d.find(b'IEND') + 8
svg = d[i:]                      # <?xml ... <svg ...>
open('layer2.svg','wb').write(svg)
```

The SVG contained a single `<image href="data:image/png;base64,iVBORw0K...">`.

## Step 3 — Extract the embedded image (beyond the veil)
Decode the base64 PNG embedded in the SVG:

```python
import re, base64
m = re.search(rb'base64,([A-Za-z0-9+/=\s]+)"', svg)
png = base64.b64decode(re.sub(rb'\s', b'', m.group(1)))
open('layer3.png','wb').write(png)   # 1822-byte 370x370 PNG, 2 colours only
```

`layer3.png` had exactly **2 unique colours (0 and 255)** — a black-and-white
bitmap. Rendering it showed a **QR code**.

## Step 4 — Decode the QR
```python
import cv2
img = cv2.imread('layer3.png')
data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
print(data)     # AIT{b3y0nd_th3_v3il_0f_s0uls}
```

## Flag
```
AIT{b3y0nd_th3_v3il_0f_s0uls}
```

## Key takeaways
- Always carve **after `IEND`** — appended data is a classic PNG hiding spot.
- Polyglot/nested containers: PNG → SVG → base64 PNG → QR.
- A 2-colour image is a strong signal for a rendered QR/barcode; decode it
  programmatically (OpenCV `QRCodeDetector`) rather than by eye.
