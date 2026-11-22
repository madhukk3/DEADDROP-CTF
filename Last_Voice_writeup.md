# Last Voice (75) — Stego

> Station 93.4 went silent mid-broadcast... Investigators recovered one image.
> "If the recording is gone, listen to the picture." What was the last message?

**File:** `last_transmission.png`
**Flag:** `AIT{7HR33_CH4NN3L5_0N3_M3554G3}`

## Vulnerability
Flag is drawn across the **LSB bit-planes** of the colour channels (not LSB
*audio* — the "listen to the picture" line is misdirection). Each channel/bit
carries one text fragment.

## Steps
1. PNG is clean (no appended data, no odd chunks); plain LSB extraction and raw
   pixels-as-PCM both empty.
2. Render the individual bit-planes as images → text is drawn into them:
   - R bit0 → `AIT{7HR33_`
   - G bit0 → `CH4NN3L5_`
   - R bit1 → `0N3_M3554G3}`
3. Concatenate in order → the flag ("three channels, one message").

## Solver
```python
from PIL import Image
import numpy as np
a = np.array(Image.open("last_transmission.png").convert("RGB"))
for name, plane in [("R0", a[:,:,0]&1), ("G0", a[:,:,1]&1), ("R1", (a[:,:,0]>>1)&1)]:
    Image.fromarray((plane*255).astype('uint8')).save(f"plane_{name}.png")
# open the plane_*.png images and read the drawn text
```
