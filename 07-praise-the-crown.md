# Praise the Crown — DEDSEC CTF Writeup

**Category:** Steganography / Logical Reasoning
**Difficulty:** Medium
**Flag:** `DEDSEC{V0IC3_0F_TH3_CR0WN}`

---

## The premise

> *Those who constantly repeat authority will never develop their own voice.*

Players receive `dedsec_signal.gif` — a glitchy animated GIF showing a masked hacker figure. Roughly 100 frames of looping DedSec aesthetic.

The challenge title is the answer in disguise. The flag, in leetspeak, *is* "voice of the crown" — and the GIF's whole structure is a metaphor for what that means. Most of the frames are sycophants repeating the same thing. A tiny minority carry original signal. The challenge is recognising which is which.

---

## Step 1 — Look at the GIF, notice the loop

If you watch the GIF play, it looks like a single repeating animation with mild glitches. If you extract every frame to disk:

```bash
mkdir frames && ffmpeg -i dedsec_signal.gif frames/frame_%04d.png
ls frames/ | wc -l
# 104
```

104 frames. Already a hint: 104 = 26 × 4. There are 26 letters in `DEDSEC{V0IC3_0F_TH3_CR0WN}` (count them — that's the flag). The "× 4" is the trick.

---

## Step 2 — Echo, echo, echo, signal

Open the frames side-by-side. You'll quickly notice the structure:

```
[E][E][E][U]   [E][E][E][U]   [E][E][E][U] …
```

Three near-identical frames, then a fourth that's slightly different in one specific region. Three more echoes, another unique frame. Repeat 26 times.

I called the repeated frames **echoes**, after the theme — they're the sycophants who add no original content. The fourth-of-four frames are the **unique** ones, each carrying one ASCII character of the flag.

The echo frames vary slightly between each other (small glitch overlays differ frame-to-frame), so exact pixel comparison won't dedupe them. Players must either:

- Notice the stride pattern visually (every 4th frame is the "original"), or
- Use perceptual hashing (`imagehash`) to cluster frames and pick the outliers.

---

## Step 3 — Decode the pixel binary

Each unique frame has **8 pixel blocks** in the top-left corner, starting at `(0, 0)`. Each block is 10×20 pixels. Each block is either solid red or solid blue:

| Block | x-position | Bit |
| ----- | ---------- | --- |
| 0     | 0          | 7 (MSB) |
| 1     | 10         | 6   |
| 2     | 20         | 5   |
| 3     | 30         | 4   |
| 4     | 40         | 3   |
| 5     | 50         | 2   |
| 6     | 60         | 1   |
| 7     | 70         | 0 (LSB) |

**Red = 1, blue = 0.** Eight bits → one ASCII character.

Example: `'D'` = `0x44` = `01000100`

```
Block:  0    1    2    3    4    5    6    7
Bit:    0    1    0    0    0    1    0    0
Color: BLUE  RED  BLUE BLUE BLUE RED  BLUE BLUE
```

The colours are palette-locked: I forced `(255, 0, 0)` into palette index 1 and `(0, 0, 255)` into palette index 2 on every unique frame, so GIF quantisation across platforms never corrupts the bits.

---

## Step 4 — Decode in code

```python
import os
from PIL import Image

PIXEL = 10

def read_char(path):
    img = Image.open(path).convert("RGB")
    bits = []
    for i in range(8):
        x = i * PIXEL + PIXEL // 2
        y = PIXEL
        r, _, b = img.getpixel((x, y))
        bits.append(1 if r > b else 0)
    return chr(int("".join(str(b) for b in bits), 2))

frames = sorted(f for f in os.listdir("frames") if f.endswith(".png"))
unique = frames[3::4]   # every 4th frame, starting at index 3
flag = "".join(read_char(os.path.join("frames", f)) for f in unique)
print(flag)
# DEDSEC{V0IC3_0F_TH3_CR0WN}
```

---

## The decoys

I planted three fake trails for automated solvers:

| Decoy | Where | Content |
| --- | --- | --- |
| GIF Comment Extension | metadata block | `RGVkU2VjIGlzIHdhdGNoaW5nIHlvdQ==` → `DedSec is watching you` |
| Fake base64 artist tag | image metadata | `c2VjcmV0X2tleT1ERURTRUNfRkFLRV9GTEFH` → `secret_key=DEDSEC_FAKE_FLAG` |
| Plain fake flag | description tag | `FAKEFLAG: DEDSEC{N0T_TH3_R34L_FL4G_LMAO}` |

The third is the funniest because it's labelled "fake" in plain text — and bots still submit it. Any solver that string-greps `DEDSEC{` in the GIF binary hits the third decoy and tries it before doing any actual frame analysis. That's the whole point: the literal string fakes the flag pattern but is labelled as fake, and the *real* flag is reconstructed bit by bit from pixel colour.

---

## Why this works as a challenge

There are two reasons Praise the Crown punches above its medium-difficulty weight:

1. **The "aha" is conceptual, not technical.** Once you realise the GIF is mostly noise and only every fourth frame carries information, the rest is undergraduate steganography. But you have to *notice the echo*. Automated frame extractors treat all 104 frames as equal, and decoders that scan all frames for hidden data find nothing in 75% of them.
2. **The theme matches the mechanic exactly.** "Voice of the Crown" is a flag about distinguishing signal from sycophants. The encoding *is* the metaphor — 78 sycophants, 26 voices, one message. I've never been prouder of a challenge where the title is the spoiler if you read it right.

— Murugan
