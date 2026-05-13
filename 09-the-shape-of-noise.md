# The Shape of Noise — DEDSEC CTF Writeup

**Category:** Steganography
**Difficulty:** Medium
**Flag:** `DEDSEC{n01s3_1s_0nly_p4tt3rn_w41t1ng_t0_b3_s33n}`

> *We've intercepted a corrupted data fragment from the DEDSEC network. Automated systems analyze this file as pure static or a corrupted image dump containing random noise. However, we know their operatives use these "glitch arts" to hide critical intelligence. Noise is only a pattern waiting to be seen.*
>
> *Standard steganography tools (zsteg, stegsolve, binwalk) will not help you here. This requires a human eye and logic.*

---

## The brief

Players are handed one file: `artifact.png`. It looks like a piece of glitch art — colour-banded RGB static, the kind of corrupted-CRT aesthetic you'd see as desktop wallpaper. Run it through every off-the-shelf stego tool you have:

```bash
zsteg artifact.png       # nothing
stegsolve artifact.png   # nothing useful
binwalk artifact.png     # just a PNG
strings artifact.png     # zero readable text
```

The hint says it explicitly: *standard steganography tools will not help.* This isn't an LSB extraction, it isn't an appended ZIP, it isn't EXIF metadata. The information is in the *structure* of the noise itself, and it's only visible if you understand the encoding rule.

---

## Step 1 — Realise the noise is a sample grid

Stare at the image long enough and the RGB banding starts to feel suspicious — it's "glitchy" in a too-regular way. The colour pattern shifts every ~8 pixel rows, RGB triplets get rotated through `(high, mid, low)` permutations. That's aesthetic — but the brightness of each pixel is doing actual work.

The encoding rule is straightforward once you suspect it: sample positions where `(x + y) % 7 == 0`. At every such position, the average RGB brightness is either:

- **Very dark** (brightness < 80) → bit `0`
- **Very bright** (brightness > 180) → bit `1`

Every other pixel is mid-range noise. The signal is at the diagonal sample grid; everything else is camouflage.

```python
from PIL import Image
img = Image.open("artifact.png").convert("RGB")
w, h = img.size

bits = []
for y in range(h):
    for x in range(w):
        if (x + y) % 7 != 0:
            continue
        r, g, b = img.getpixel((x, y))
        brightness = (r + g + b) // 3
        if brightness < 80:
            bits.append(0)
        elif brightness > 180:
            bits.append(1)
```

You now have a bitstream. Count it. If the carrier dimensions were chosen right, the length is a perfect square.

---

## Step 2 — The bitstream is a spiraled QR

```python
import numpy as np
N = int(np.sqrt(len(bits)))
assert N * N == len(bits)
```

Reshape into an N×N grid. The bits were written in a **spiral** during encoding — outer ring clockwise, then inwards — so reading the bitstream row-by-row gives you nonsense. You have to undo the spiral.

```python
def unspiral(stream, n):
    m = [[0] * n for _ in range(n)]
    top, bot, left, right, idx = 0, n - 1, 0, n - 1, 0
    while top <= bot and left <= right:
        for i in range(left, right + 1):
            m[top][i] = stream[idx]; idx += 1
        top += 1
        for i in range(top, bot + 1):
            m[i][right] = stream[idx]; idx += 1
        right -= 1
        if top <= bot:
            for i in range(right, left - 1, -1):
                m[bot][i] = stream[idx]; idx += 1
            bot -= 1
        if left <= right:
            for i in range(bot, top - 1, -1):
                m[i][left] = stream[idx]; idx += 1
            left += 1
    return np.array(m)

qr_bits = unspiral(bits, N)
```

You're still not done. The encoder also:

1. Rotated the QR 90° clockwise.
2. Flipped every second row (`bits[1::2, :] = 1 - bits[1::2, :]`).

So you reverse both: flip every second row, then rotate 90° counter-clockwise.

```python
qr_bits[1::2, :] = 1 - qr_bits[1::2, :]
qr_bits = np.rot90(qr_bits, k=1)
```

---

## Step 3 — Render the QR and scan it

QR convention: `1` is a black module, `0` is white. Convert and upscale so the result is scannable:

```python
qr_pixels = ((1 - qr_bits) * 255).astype(np.uint8)
qr_img = Image.fromarray(qr_pixels, mode="L").resize((N * 10, N * 10), Image.NEAREST)
qr_img.save("recovered_qr.png")
```

Open `recovered_qr.png`, scan it with any QR reader (phone camera, `zbarimg`, online decoder):

```
DEDSEC{n01s3_1s_0nly_p4tt3rn_w41t1ng_t0_b3_s33n}
```

---

## Why off-the-shelf tools fail

This is a challenge designed against the muscle reflex of "throw stego tools at it." Every classic technique fails:

| Tool / technique | Why it fails |
| ---------------- | ------------ |
| `zsteg`          | LSB analysis on RGB pixels; signal isn't in low bits, it's in pixel-wise brightness extremes at a diagonal stride |
| `stegsolve` channel views | Bitplane visuals don't reveal the structure; the signal needs `(x+y) % 7 == 0` filtering plus spiral re-ordering |
| `binwalk`        | No appended data, no embedded archive |
| `exiftool`       | No metadata payload |
| `strings`        | No readable text exists |
| LSB extractors   | Bits are in the *high-brightness* threshold, not the low-order bits |

The encoding uses three independent transformations stacked together (sample grid, spiral, row-flip+rotate), with extra colour banding on top as aesthetic camouflage. Pulling the QR back out requires understanding all three. There's no signature for an automated tool to match against.

---

## Designer's notes

This was the easiest of my challenges to *imagine* and the hardest to actually build. I wanted the player to look at glitch art and realise the static was carrying information without being told that's what they were looking at. That meant:

1. **The carrier had to look genuinely random.** Pixel positions that aren't on the sample grid use carefully randomised RGB triplets so the histogram looks like banded noise, not like a low-bit channel.
2. **The sample grid had to be invisible to common tools.** `(x + y) % 7 == 0` is a diagonal pattern — neither row-aligned nor column-aligned, so per-row / per-column scanners miss it.
3. **The recovered data had to require human reasoning past extraction.** Even after extracting the bits, players still need to spot that the result is a QR (powers-of-2 length is the giveaway) and that it's been scrambled in two more ways before being laid out.

The hint in the brief is the entire philosophy of the challenge:

> *Noise is only a pattern waiting to be seen.*

If you got the flag with no scripts firing, just careful pixel-counting and a hunch, you out-thought every tool in the standard kit.

— Murugan
