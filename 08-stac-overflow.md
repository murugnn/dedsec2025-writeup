# STAC Overflow — DEDSEC CTF Writeup

**Category:** Forensics / Crypto
**Difficulty:** Hard
**Flag:** `DEDSEC{v0lunt33r5_5t4ck_th3_thr0n3}`

---

## The premise

A college "Council" with a strict membership hierarchy. Volunteers stack up event participation to qualify for panels. The flavour text talks about influence, badges, seals, ledger entries — never once mentions cryptography. There are three files in the player package:

| File | Cover story |
| --- | --- |
| `invitation.txt` | A 5-article membership manifesto |
| `ledger.pdf` | A 55-member roster with skill scores, event counts, badges |
| `seal.bin` | The Council's "membership seal," apparently random bytes |

The real shape underneath: an XOR-encrypted ZIP, an RSA-2048 system with two moduli that share a prime, an obfuscated private key, and an OAEP-padded ciphertext. None of those words appear in any player-facing file.

The whole challenge is "can you read prose carefully enough to find a crypto problem buried under it."

---

## Step 1 — Read the manifesto

`invitation.txt` is five articles. Read them slowly — there are no diagrams, no obvious technical hints, and the same word ("stac") shows up everywhere doing different work.

- **Article I — the encoding.** Each member has an *identity number* built from their stats: take the **event count** as the base and `floor(skill_score / 10)` as the top, "read them side by side." Example: events=2, skill=91 → top=9 → identity `"29"`. The encoding is called a **stac** (the missing K is foreshadowing).
- **Article II — the unlock.** Find "the first member whose event count is exactly the number required for basic standing." Their stac becomes a 4-byte unlock pattern `[base, top, base, top]` applied repeatedly to every byte of `seal.bin`. The result starts with `P` and `K`.
- **Article IV — the missing K.** "STAC is missing a K to become STACK. The K was placed elsewhere and must be recovered later. The Throne cannot be claimed without applying the K."
- **Article V — the math.** Public exponent is **65537**. Two bases share a hidden factor recoverable by **a common divisor**. The stored private key is obfuscated by XOR with the missing word. Textbook reversal will fail.

That's the entire spec, in plain English, scattered across a fake medieval narrative.

---

## Step 2 — Find the XOR key in the ledger

Article II says "the first member whose event count is exactly the number required for basic standing." The narrative defines basic standing as **2 events**. Scan `ledger.pdf` from the top: rows 1–6 have 0 events, rows 7–14 have 1 event, **row 15** is the first member with 2 events. Her name is Arjun Sharma, skill score 91.

Apply Article I:

- `base = events = 2`
- `top = floor(91 / 10) = 9`
- `stac = [2, 9]`
- Unlock pattern: `[2, 9, 2, 9]`

That's the 4-byte XOR key.

```python
data = open("seal.bin", "rb").read()
key = bytes([2, 9, 2, 9])
out = bytes(data[i] ^ key[i % 4] for i in range(len(data)))
assert out[:2] == b"PK"
open("archive.zip", "wb").write(out)
```

Unzip the archive — four new files appear:

```
ranking_formula.txt   — narrative description of the math
profiles.json         — 31 panel-tier members with badge tokens
internal_notes.txt    — 6 findings, including the obfuscated key
final_cipher.bin      — 256-byte ciphertext
```

---

## Step 3 — Spot the two moduli

`profiles.json` has 31 members. Each member has either a `membership_hash` or a `registry_id` — but never both. Every `membership_hash` is the **same** ~617-digit integer. Every `registry_id` is **another** identical ~617-digit integer.

Two distinct numbers, both 2048-bit, surfaced as opaque per-member fields. That's `n1` and `n2`.

`ranking_formula.txt` confirms it in prose — there are two modular bases, the public exponent is 65537, and "a common divisor of the two bases is the foothold." That's the GCD attack spelled out without ever saying "GCD."

---

## Step 4 — GCD recovery

`n1 = p × q` and `n2 = p × r`. They share `p`. Therefore:

```python
import math, json

profiles = json.load(open("profiles.json"))
n1 = n2 = None
for m in profiles["members"]:
    if m.get("membership_hash") and n1 is None:
        n1 = int(m["membership_hash"])
    if m.get("registry_id") and n2 is None:
        n2 = int(m["registry_id"])

p = math.gcd(n1, n2)
q = n1 // p
assert p * q == n1

e = 65537
phi = (p - 1) * (q - 1)
d_math = pow(e, -1, phi)
```

This is the **mathematically correct** private key for `n1`. It does not yet decrypt the ciphertext. Two more things stand in the way: the stored key is XOR-obfuscated, and the ciphertext is OAEP-padded.

---

## Step 5 — Apply the missing K

`internal_notes.txt` has six findings. Finding 5 reads:

```
council_key_fragment = 149128480360949183755618621431425974...
```

That's a private exponent — but it isn't quite `d_math`. The narrative said the stored key was obfuscated by XOR with the missing word. Which word?

`STAC` is missing a K to become `STACK`. The missing K is the literal string `"KEY"` — the K is in the word "key." Players need to read Article IV and connect "the K that was placed elsewhere" to the three letters that complete `STACK`.

```python
KEY_INT = int.from_bytes(b"KEY", "big")   # = 4932953
d_real = int_from_notes_file
d_math_recovered = d_real ^ KEY_INT
assert d_math_recovered == d_math
```

If you skipped this step and tried to decrypt with `d_real` directly, OAEP fails silently with garbage output and the player wastes hours.

---

## Step 6 — OAEP-decrypt

Article V was explicit: "textbook reversal will fail." That's the OAEP hint. Build a real `RSAPrivateNumbers` object from `(p, q, d_math, n1, e)` and decrypt:

```python
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

priv = RSAPrivateNumbers(
    p, q, d_math,
    rsa_crt_dmp1(d_math, p),
    rsa_crt_dmq1(d_math, q),
    rsa_crt_iqmp(p, q),
    RSAPublicNumbers(e, n1),
).private_key(default_backend())

ct = open("final_cipher.bin", "rb").read()
flag = priv.decrypt(
    ct,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
print(flag.decode())
```

```
DEDSEC{v0lunt33r5_5t4ck_th3_thr0n3}
```

---

## The anti-automation philosophy

I had a specific goal with STAC Overflow: build a challenge where **no automated solver could short-circuit any step**, even though the underlying crypto is well-known.

| Layer | What blocks automation |
| --- | --- |
| Step 1 | Player must read prose and connect "basic standing" to events=2 |
| Step 2 | XOR key derived from a specific row in a 55-row PDF, no row highlighted |
| Step 3 | Recognise that `membership_hash` ≠ unique-per-user; it's `n1` |
| Step 4 | GCD is trivial *once you suspect it*. Suspecting it requires reading |
| Step 5 | "Missing K" is a wordplay puzzle: `STAC` → `STACK`, the K means `b"KEY"` |
| Step 6 | OAEP failure mode is silent — wrong padding produces garbage, not an error |

Three more things I worked hard on:

1. **No crypto vocabulary anywhere.** "XOR" is called a "numerical veil." "ZIP" is "the standard archive." "RSA" is a "layered arithmetic instrument." "Prime" is "the shared factor." If you grep the player files for `rsa`, `prime`, `xor`, `aes`, you find nothing.
2. **The 2048-bit moduli are computationally safe.** The only way through is the GCD attack, which is only possible because I deliberately reused a prime. GNFS factoring of a 2048-bit number is infeasible — so brute-force has no path.
3. **The K-puzzle is the heart.** The "STAC missing K" wordplay is the most important reasoning step, and it ties the title, the encoding language, and the key recovery into one moment. The challenge title is itself the spec.

The fastest crypto students cleared this in around two hours. The average solve time was closer to three and a half. Nobody beat it with a script that wasn't tuned by hand.

— Murugan
