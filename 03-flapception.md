# Flapception — DEDSEC CTF Writeup

**Category:** Mobile / Reverse Engineering
**Difficulty:** Hard
**Real flag:** `DEDSEC{m3m0ry_jump1ng_m4st3r_1337}`

---

## The brief

A mysterious Android application has been recovered from a DedSec dead drop. Players get `flapception.apk` and nothing else. The game inside is a Flappy Bird clone — tap to flap, dodge pipes, score points.

There are **three flags** in this APK. Two of them are wrong on purpose. The whole challenge is a layered honeypot designed to defeat both casual players and AI-assisted reverse engineers.

---

## Layer 1 — The "I won" trap

Install the APK. Play until you score 30. The game celebrates with confetti and a banner:

```
DEDSEC{y0u_4r3_f0o7e6}
```

That's fake flag #1. It's assembled at runtime in `game_manager.gd` from a numeric array — no string literal exists. A player who never opens the APK and submits this gets a polite rejection and a suspicion that maybe they need to look deeper.

Why it works as a trap:

- Confetti + celebration + correct flag format creates emotional confidence.
- "Score 30 → flag" is a believable game design.
- The flag content reads like a typical CTF leetspeak.

If you stop here you lose. The first lesson is: a flag the game *hands you* is almost certainly not the real one.

---

## Layer 2 — Static reverse engineering and the AI bait

Crack the APK open:

```bash
unzip flapception.apk -d apk_contents/
# Godot games store their data in assets/main.pack
godotpcktool apk_contents/assets/main.pack --action extract -o extracted/
```

Godot 4.x stores GDScript as **plaintext** inside the `.pck`, so once extracted you have readable source. The obvious move:

```bash
grep -Ri "DEDSEC" extracted/scripts/   # Nothing
grep -Ri "flag" extracted/scripts/     # Nothing
grep -Ri "fl4p"  extracted/scripts/    # Nothing
```

No string in the codebase contains the prefix, the word "flag," or any leetspeak fragment. Time to actually read.

`project.godot` says `GameManager` is an autoload (global singleton). Start there.

Inside `game_manager.gd` there's a function called `_sync_session_metrics()` that calls into six other scripts. Each script uses a different encoding trick:

| Script           | Technique          | Produces      |
| ---------------- | ------------------ | ------------- |
| `ground.gd`      | Subtract a constant | `DEDSEC`      |
| `game_manager.gd`| Arithmetic on score| `{`           |
| `bird.gd`        | XOR two arrays     | `fl4p_7h3`    |
| `pipe.gd`        | Modulo by 128      | `_b1n4ry_`    |
| `ui.gd`          | Stride-3 interleaving | `n07_th3_` |
| `main.gd`        | 2-bit right rotation | `b1rd}`     |

Trace it all, assemble:

```
DEDSEC{fl4p_7h3_b1n4ry_n07_th3_b1rd}
```

That's fake flag #2. Submit it. Get rejected. Again.

### Why I built this layer

This is the **AI honeypot**. If a player drops every `.gd` file into an LLM and asks "find the flag," the LLM follows `_sync_session_metrics()`, decodes all five techniques (which it's good at), and confidently outputs fake flag #2. Every single AI tool I tested on the early build did this. It feels like a victory because:

- The solver invested 30–60 minutes decoding five techniques.
- The static data is real — the code genuinely produces this string.
- Cross-file tracing makes it feel like the "golden path."

Sunk-cost psychology takes care of the rest. Players submit fake #2 and then refuse to believe it's wrong.

I also seeded the project with **10 dummy scripts** (`telemetry_processor.gd`, `physics_interpolator.gd`, `crypto_utils.gd`, etc.) that simulate plausible inter-system data flow. Their job is to inflate the context window of any LLM analyst until reasoning degrades. They produce nothing useful, but they look like they might.

---

## Layer 3 — The real flag lives in native code

If you read `game_manager.gd` more carefully, past the obvious honeypot, you find a call into a native GDExtension library:

```gdscript
_runtime_validator.derive_material(...)
```

This crosses the GDScript/native boundary. Calling `derive_material()` from GDScript returns scrambled garbage — the native code deliberately XORs the result with a caller-supplied key before handing it back, so the flag never exists as a contiguous string on the GDScript side.

That means the **only** way to recover the flag is to reverse the `.so` directly.

### Find the library

```bash
unzip -l flapception.apk | grep \.so
# lib/arm64-v8a/libflapception_native.so
```

Load it in Ghidra or IDA.

### The strings trap

Run `strings` on the library and you'll see `_integrity_payload` — a byte array that looks like an obvious flag candidate. That's a deliberate decoy. Decode it and you get nothing useful.

### The real construction — memory jumping

Look at `derive_material()` in the decompiler. It iterates over an array called `_integrity_jump_table`. The array isn't bytes — it's **function pointers**:

```cpp
NOINLINE static char _f00() { return 'D'; }
NOINLINE static char _f01() { return 'E'; }
NOINLINE static char _f02() { return 'D'; }
// … 34 of these total …
NOINLINE static char _f33() { return '}'; }

static const FlagCharFunc _integrity_jump_table[] = {
    _f00, _f01, _f02, _f03, /* … */ _f33
};
```

The flag is never stored as bytes. Each character lives as the return value of its own one-instruction function. The C++ destroys the assembled string before handing it back to GDScript, so:

1. The flag never appears in `.rodata` as a string.
2. The flag never appears in memory as contiguous bytes during runtime.
3. `strings`, YARA, frida string scans — all useless.

To recover it, you double-click into every pointer in `_integrity_jump_table`, read the `mov eax, 0x44` (D), `mov eax, 0x45` (E), `mov eax, 0x44` (D)…

Reconstruct manually:

```
DEDSEC{m3m0ry_jump1ng_m4st3r_1337}
```

That's the real flag.

---

## The three flags, side by side

| # | Flag                                            | How found                              | Real? |
| - | ----------------------------------------------- | -------------------------------------- | ----- |
| 1 | `DEDSEC{y0u_4r3_f0o7e6}`                        | Play to score 30                       | No    |
| 2 | `DEDSEC{fl4p_7h3_b1n4ry_n07_th3_b1rd}`          | Decode static data from 6 GDScripts    | No    |
| 3 | `DEDSEC{m3m0ry_jump1ng_m4st3r_1337}`            | Reverse the `.so` jump table in Ghidra | **Yes** |

---

## Design notes

The challenge has a specific philosophy: **the more confident a player is that they've found the flag, the more likely it's a trap.** Each layer is calibrated to feel like a complete solution:

- Layer 1 gives you a celebration screen.
- Layer 2 gives you a complex multi-encoding decode that feels intellectually satisfying.
- Layer 3 requires you to look past everything that's already "worked."

The AI angle wasn't an afterthought. The static-analysis layer was designed *specifically* to be an attractive AI target — a clean data-flow graph, cross-file references, multiple well-known encodings. Every modern coding assistant assembles fake flag #2 in seconds. The only way to reach layer 3 is to manually inspect the native binary, which still requires a human to spot that `derive_material()` is crossing the JNI boundary and that its output is being deliberately corrupted on the way back.

If you got the real flag without leaning on a tool to do the binary RE for you, congratulations — you out-thought the honeypot.

— Murugan
