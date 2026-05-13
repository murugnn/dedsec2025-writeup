# DEDSEC — The Switch Matrix — CTF Writeup

**Category:** Mobile / Reverse Engineering
**Difficulty:** Hard
**Tagline:** *We are DedSec. We are everywhere. We are everyone.*

---

## The brief

Players get one file: `dedsec_labyrinth.apk`. Open it. The app crashes. Or it appears to — silently finishes onCreate with no error dialog, no toast, no logcat panic. Just gone.

There are no hints. The README explicitly says so. "Hint: there are no hints."

The flag is hidden across **eight stages**, none of which produce the flag in isolation:

1. **Stage 1** — Patch the integrity gate so the app actually runs.
2. **Stage 2** — Reach the hidden grid UI revealed by the patch.
3. **Stage 3** — The 256-switch puzzle: produce a target 32-bit checksum from toggles that modify a 256-bit global state non-linearly.
4. **Stage 4** — A 256-node graph traversal whose path is determined by the global state.
5. **Stage 5–6** — A custom VM whose bytecode is generated from the checksum at runtime.
6. **Stage 7** — A native JNI sponge-permutation mixer.
7. **Stage 8** — XOR-decrypt the encrypted blob in `assets/data.bin` using the combined output.

The flag exists only when all eight stages produce values that compose correctly. The app never stores it. There is no string `DEDSEC{` anywhere on disk.

---

## Stage 1 — "The app crashed" is the first clue

Decompile with `jadx`. Open `MainActivity.onCreate()`. Three integrity checks run before the UI ever loads:

```java
int fakeHash = FakeIntegrity.computeHashA(getPackageName());
if (fakeHash == FAKE_EXPECTED) { /* … */ }   // always passes

boolean fakeB = FakeIntegrity.verifySignatureDecoy(this);
if (!fakeB) { finish(); return; }            // never triggers

int chain = IntegrityGuard.verifyChain(this);
int expected = REAL_SEGMENT_A | REAL_SEGMENT_B;  // 0x1337C0DE
if (chain != expected) { finish(); return; }
```

Two of these are pure decoys — they always pass, they exist to draw an analyst's attention to the wrong constants (`0xDEADBEEF`, `0xCAFEBABE`, the `0xFFFFFFFF` "success" trap in `IntegrityGuard.TRAP_SUCCESS`).

The real gate is `IntegrityGuard.verifyChain()`. It computes a five-stage hash:

```
step1 = seedFromContext(ctx)          // mixes package name with "DEDSEC"
step2 = foldA(step1)                  // XOR + rotate
step3 = foldB(step2)                  // CRC-like polynomial scramble
step4 = anchorFromAsset(ctx, step3)   // reads assets/anchor.bin byte[0]
step5 = finalize(step4)               // expected output: 0x1337C0DE
```

The whole chain hinges on `anchor.bin[0]`. In the shipped APK that byte is `0xAB`. The expected byte — the one that makes the chain produce `0x1337C0DE` — is `0xCD`.

Patch one byte and repack:

```bash
apktool d dedsec_labyrinth.apk -o unpacked/
# edit unpacked/assets/anchor.bin: set offset 0 to 0xCD
apktool b unpacked -o patched.apk
apksigner sign --ks debug.keystore patched.apk
adb install -r patched.apk
```

Install the patched APK. The app stops finishing onCreate. Stage 1 done.

---

## Stage 2 — A 16×16 grid appears

The patched app loads `GridActivity` — a 16×16 grid of toggle buttons (256 cells). Above the grid:

```
DEDSEC SYSTEM v0.∞
─────────────────────────────
"Every switch changes more than itself."
"State survives every move."
"The maze cannot be seen — only computed."
─────────────────────────────
```

Three lines of plain prose that are the entire spec.

- "Every switch changes more than itself" → toggling one cell mutates more than one byte of the global state.
- "State survives every move" → the state is cumulative, not a per-frame reset.
- "The maze cannot be seen — only computed" → there is no visual feedback for correctness.

There's a submit button. When you press it, the app sends the 32-byte state + 4-byte rolling checksum to `LabyrinthEngine`.

The target checksum is `0x507b2420`. The near-target checksum is `0x007b2420` (same lower 24 bits, different high byte) — if you submit the near-target, the next stage prints a fake flag:

```
DEDSEC{ALM0ST_TH3R3_TRY_H4RD3R}
```

That's the **false-success path**. It exists to punish players who brute-force the low bits.

---

## Stage 3 — Reverse the toggle update

In `GridActivity`, every toggle index `i` has a precomputed 32-bit `mask[i]`. Pressing toggle `i` does:

```java
globalState[i % 32] ^= (mask[i] >>> 24) & 0xFF
globalState[(i+1) % 32] ^= (mask[i] >>> 16) & 0xFF
globalState[(i+2) % 32] ^= (mask[i] >>> 8)  & 0xFF
globalState[(i+3) % 32] ^=  mask[i]         & 0xFF
rollingChecksum = rotateLeft(rollingChecksum ^ mask[i], 7) + i
```

So each toggle XORs 4 bytes into the 256-bit state and folds itself into the rolling checksum. Because both state and checksum are non-linear functions of the toggle order, you cannot brute-force this (`2^256` is not happening).

You **can** solve it the way I intended: extract the `mask` array, model the toggle function in Python, and search for a toggle sequence that produces `0x507b2420`. The intended sequence is `{7, 23, 42, 77, 128, 200, 255}`.

Once you submit the correct toggles, the app launches `LabyrinthEngine` with the right state + checksum.

---

## Stage 4 — The 256-node hidden maze

`LabyrinthEngine.traverseMaze()` walks a binary graph of 256 nodes for exactly 128 steps. At each step:

```java
int h = nodeHash(node ^ state[node % 32]);
int parity = Integer.bitCount(h) & 1;
node = parity == 0 ? GRAPH[node][0] : GRAPH[node][1];
```

The graph is precomputed from a fixed seed (`0xFEEDBEEF`), so it's deterministic and replicable in Python. But the **path** through the graph depends on `inputState` — which is the 32-byte state you built in stage 3. The walk must end at node `0xaf`.

If the state from stage 3 is correct, the walk lands on the target. If it's near-correct, you hit the false-success branch. If it's wrong, you get `"SYSTEM: path incomplete."`

---

## Stage 5–6 — A custom VM, bytecode generated at runtime

The challenge generates VM bytecode dynamically from the checksum:

```java
byte[] blob = { 0x6A, 0x2C, /* 48 static bytes */ … };
byte[] key = new byte[blob.length];
int ks = checksum;
for (int i = 0; i < key.length; i++) {
    ks = rotateLeft(ks ^ (i * 0x12345678), 7);
    key[i] = (byte)(ks & 0xFF);
}
byte[] code = blob ^ key;   // element-wise XOR
```

So the **executable bytecode literally does not exist** until the correct checksum arrives. Static analysis of `blob` gives you nothing — it's encrypted with a key derived from data you don't have unless you've already solved stage 3.

The VM is 10 opcodes: `XOR`, `ROT`, `MIX`, `PUSH`, `JMP_IF`, `HASH`, `LOAD`, `STORE`, `ADD`, `HALT`. Stack-based, 8 registers preloaded with the state bytes. The decoded bytecode runs against state-derived registers and produces a single 32-bit output.

To solve this offline, you replicate:
1. The XOR keystream from the correct checksum.
2. The VM in Python.
3. Feed in the correct state.

---

## Stage 7 — JNI sponge mixer

The VM output is handed to native code:

```c
JNIEXPORT jint JNICALL
Java_com_dedsec_labyrinth_NativeLayer_mix(
    JNIEnv *env, jclass cls,
    jint vmOutput, jbyteArray stateArr, jint finalNode)
```

Inside, a 4-round sponge construction (a/b/c/d state words, golden-ratio multiplication constant `0x9E3779B9`, rotate-left by 7/13/17/11) absorbs `vmOutput`, the first 4 state bytes, and `vmOutput XOR finalNode`. Then it squeezes and XORs with the state word.

`libdedsec.so` also contains:

- `FAKE_KEY_1 = 0xDEADBEEF` and `FAKE_KEY_2 = 0xCAFEBABE` — decoy constants.
- `fake_validate()` — looks load-bearing, always returns 0.
- `verifyNativeIntegrity()` — JNI export that's never called from real Java flow.

The real function is `mix()`, and it's a pure deterministic transformation. Replicate it in Python:

```python
MIX = 0x9E3779B9

def rol32(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def permute(s):
    for _ in range(4):
        s[0] = (rol32(s[0] ^ s[1], 7)  * MIX) & 0xFFFFFFFF
        s[1] = (rol32(s[1] ^ s[2], 13) + s[3]) & 0xFFFFFFFF
        s[2] = (rol32(s[2] ^ s[3], 17) ^ s[0]) & 0xFFFFFFFF
        s[3] = (rol32(s[3] ^ s[0], 11) * (s[1] | 1)) & 0xFFFFFFFF
    return s

# absorb vmOutput, stateWord, vmOutput^finalNode
# squeeze: permute, then a^b^c^d
# final ^= stateWord
```

---

## Stage 8 — XOR-decrypt the flag

The decrypt key is `vmOutput XOR nativeMix`. The challenge reads `assets/data.bin` and:

```java
int ks = decryptKey;
for (int i = 0; i < n; i++) {
    ks = rotateLeft(ks ^ 0xB5AD4ECF, 11);
    plain[i] = enc[i] ^ (ks & 0xFF);
}
```

If — and only if — the result starts with `DEDSEC{` and ends with `}`, the app prints it on screen. Otherwise `null`.

If you've reproduced every stage faithfully, the screen shows:

```
══════════════════════
DEDSEC{...}
══════════════════════
```

(Exact flag content is intentionally left for the player to discover by completing the chain.)

---

## What I wanted this challenge to teach

I wrote this one specifically against the "throw it at an AI" workflow. There are five reasons it resists that:

1. **The whole chain must be executed end-to-end.** No stage produces a flag on its own. An LLM that can read `IntegrityGuard.java` and understand the patch still can't tell you the flag — there are seven more stages.
2. **One stage is encrypted by the output of another.** The VM bytecode is XOR'd with a key derived from the checksum, which is derived from the toggle sequence, which is derived from reversing a non-linear update function. Static analysis of the encrypted blob is impossible.
3. **Native code lives outside what most static analysers can usefully chain into Java.** The JNI boundary breaks data flow for almost every off-the-shelf analyser.
4. **Decoys are everywhere and they look real.** `0xDEADBEEF`, `0xCAFEBABE`, `verifyNativeIntegrity()`, `FAKE_EXPECTED`, `TRAP_SUCCESS`, `TRAP_KEY_B64 = "This is not the key"` — analysts that follow loud constants end up nowhere.
5. **The false-success path looks like the real one.** A wrong checksum that shares 24 bits with the right one produces a fake flag in the proper format. Players who get close think they're done.

The 256-switch UI is the spine of the design — it's the moment players realise they can't solve this by reading code, they have to **reverse the update function and search for a sequence**. Everything before is a reverse-engineering task. Everything after is execution. The middle is the actual puzzle.

— Murugan
