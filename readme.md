# DEDSEC CTF — All Nine Challenges, From Designer's POV

I designed and built a CTF themed around the DedSec collective — nine challenges spanning forensics, mobile reverse engineering, cryptography, steganography, and web. Every challenge was designed against the same enemy: not the player, but the automated solver. The goal was that no script, no off-the-shelf tool, and no LLM dropped a full transcript could shortcut its way to the flag.

This index links to the writeup for each one. Every writeup is written from my perspective as the author — what I built, what traps I planted, why I planted them, and what the intended solve path looks like.

If you're a player who's already solved a few of these, the writeups will tell you exactly which trap I expected you to fall into. If you're a designer looking for ideas, every writeup ends with a section on what made the challenge work.

---

## The challenges

### 🔌 [Broken Wire](01-broken-wire.md) — Forensics / Crypto · Very Hard
**Flag:** `DEDSEC{p4ck3ts_d0nt_l13_p30pl3_d0}`

A 1108-packet pcap with 11 protocols talking over each other. The "obvious" payload on UDP 9001 is a planted decoy. The real chain is a covert chat hidden in XOR-obfuscated ICMP data, a key split across three DNS TXT records ordered by TTL, and ciphertext in HTTP response bodies ordered by a custom `X-Trace-Id` header. AES-128-ECB with a null-padded 12-byte key.

> *Designed to teach: the protocol carrying the data is not the one screaming for attention.*

---

### 💾 [Deadly Downloads](02-deadly-downloads.md) — Forensics / RE · Hard

An FTK Imager `.ad1` disk capture of a workstation where a payload ran briefly and self-deleted. The Downloads folder is full of images, each with a `Zone.Identifier` ADS pointing at malicious-looking URLs. Most are decoys. The real payload is a polyglot — a meme PNG with a Win32 executable appended after IEND. Reverse the C++ to learn it was after `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, then pull that value from the registry hive inside the image.

> *The malware is gone, but the system remembers what the user doesn't.*

---

### 🐦 [Flapception](03-flapception.md) — Mobile / RE · Hard
**Flag:** `DEDSEC{m3m0ry_jump1ng_m4st3r_1337}`

A Godot-built Flappy Bird APK that contains **three flags**. Layer 1 hands you a fake one on a victory screen. Layer 2 is an elaborate AI honeypot — six scripts with five different encoding techniques that any LLM will trace and confidently assemble into a second fake flag. The real flag lives in a native `.so`, stored as an array of function pointers — never as bytes in `.rodata`, never as a string in memory.

> *The more confident a solver is that they've found the flag, the more likely it's a trap.*

---

### 🎛️ [DEDSEC — The Switch Matrix](04-dedsec-switch-matrix.md) — Mobile / RE · Hard

An Android APK that crashes silently on launch. Patch one byte in `assets/anchor.bin` (0xAB → 0xCD) to clear the integrity gate. That unlocks a 16×16 grid puzzle: 256 toggles, each one XORs four bytes into a 256-bit global state. Get the rolling checksum to `0x507b2420` to feed a 256-node graph traversal, which feeds a custom 10-opcode VM whose bytecode is *generated at runtime* from the checksum, which feeds a JNI sponge mixer, which produces the XOR key for the encrypted flag asset. Eight stages, one chain.

> *No stage produces the flag on its own. The whole chain has to run end-to-end.*

---

### 🧮 [Echoes of Silicon](05-echoes-of-silicon.md) — Crypto · Hard
**Flag:** `DEDSEC{R3S1DU4L_ENG1N3}`

Five files that look exactly like a hardware accelerator crash dump — a config with registers, a verbose log, a JSON snapshot, a binary memory fragment, a stats file. No mention of RSA, primes, or encryption anywhere. The leak is `dp = d mod (p-1)`, split across three files with three different encodings (base64 + bit-rotation, SHA-XOR at stride positions, modular residue cross-check). Once you have `dp`, the GCD attack is four lines of Python — but recognising you're in that situation is the entire puzzle.

> *The crypto is dead easy. The cryptography is the hidden problem.*

---

### 📈 [LogSight](06-logsight.md) — Web · Medium

A polished "AI-powered log analysis platform" that converts user-submitted logs into HTML reports. Pandoc pipeline, embedded charts, the works. The bug is not in the LLM, not in the markdown sanitiser, not in any clever SSTI — it's that the report assembly inlines a server-controlled image whose EXIF metadata still carries an internal watermark string. The flag.

> *Marketing copy is misdirection. "AI-powered" is a feature tag, not a threat model.*

---

### 👑 [Praise the Crown](07-praise-the-crown.md) — Stego / Logic · Medium
**Flag:** `DEDSEC{V0IC3_0F_TH3_CR0WN}`

A 104-frame GIF of a glitchy hacker figure. The structure is `[echo][echo][echo][unique]` × 26 — three sycophant frames repeating, then one original frame carrying one ASCII character of the flag in 8 colour-coded pixel blocks (red = 1, blue = 0). The title literally is the answer: most of the frames are sycophants repeating authority. Only every fourth frame has its own voice.

> *The challenge title is the spoiler if you read it right.*

---

### 🏰 [STAC Overflow](08-stac-overflow.md) — Forensics / Crypto · Hard
**Flag:** `DEDSEC{v0lunt33r5_5t4ck_th3_thr0n3}`

A fictional "Council" with a 55-member ledger, a 5-article manifesto, and a "membership seal." None of the player files use the words *XOR*, *ZIP*, *RSA*, *prime*, or *key*. Under the prose: a 4-byte XOR pattern derived from one member's stats unlocks a ZIP; that ZIP contains two RSA-2048 moduli that share a prime; the GCD attack recovers `p`; the stored private key is XOR-obfuscated with the bytes of the word `"KEY"` (the K missing from `STAC` → `STACK`); the final ciphertext is OAEP-padded so textbook decryption fails. Six puzzles stacked into one.

> *No crypto vocabulary anywhere. Every step needs you to read prose and recognise structure.*

---

### 📡 [The Shape of Noise](09-the-shape-of-noise.md) — Stego · Medium
**Flag:** `DEDSEC{n01s3_1s_0nly_p4tt3rn_w41t1ng_t0_b3_s33n}`

A piece of glitch art. `zsteg`, `stegsolve`, `binwalk`, `exiftool`, `strings` — every off-the-shelf stego tool finds nothing. The signal is the brightness of pixels where `(x + y) % 7 == 0`. The recovered bitstream is a spiral-encoded QR code, with every second row flipped and the whole thing rotated 90°. Three independent transformations stacked together; no automated tool has a signature for that combination.

> *Noise is only a pattern waiting to be seen.*

---

## The design philosophy across all nine

Every challenge in this set was designed to defeat the same set of shortcuts:

| Shortcut | How the set defends against it |
| --- | --- |
| `grep DEDSEC{` | No flag is stored as a string anywhere in any artefact |
| `strings binary.exe \| grep flag` | Flags built at runtime from numeric arrays, function pointers, registry reads, or pixel maps |
| `binwalk file.png` | No appended archives, no embedded blobs at PE offsets |
| `zsteg / stegsolve` | Signal is in non-standard sampling grids, not bitplanes |
| "Paste it into an LLM" | Decoys that an LLM can trace are real *wrong* flags — assembled by a function that exists specifically to be the AI's honeypot |
| Automated big-integer scanners | Decoy "keys" in plain sight where `gcd(decoy, n) = 1` (silent failure) |
| Naive PDF/JSON parsers | Real data split across stride-offset positions, fake arrays with crypto-sounding names |
| Single-tool extraction | Every challenge requires composing 2–8 distinct techniques |

The point of the whole set was that solving these is a *human* skill. Reading prose. Spotting that the boring file is the one that matters. Recognising that the most confident-looking output of your automated tool is the planted decoy.

If you cleared any of these, the writeups will tell you what I expected you to think — and which step you might have skipped that was meant to slow you down.

— Murugan
