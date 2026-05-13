# Deadly Downloads — DEDSEC CTF Writeup

**Category:** Digital Forensics / Reverse Engineering
**Difficulty:** Hard
**Flag:** `DEDSEC{d3l3t3d_f1l3_but_n0t_f0rg0tt3n}`

---

## Why I built this challenge

Every forensics CTF has _that_ one challenge where `binwalk image.png` spits out a PE, you toss it at strings, and you've got the flag before your coffee cools. I wanted Deadly Downloads to feel like the kind of incident a DFIR analyst actually shows up to: the malware is _gone_, the disk is full of plausibly-suspicious noise, and the flag isn't on disk in any form — it's a value the payload was about to _compute_ from the host before it cleaned up after itself.

So I built a multi-stage decoy field around one real payload, hid the real payload exactly where most analysts won't look, and made the flag a function of a host fingerprint the attacker never got to exfiltrate. **The artefact the malware wanted came along for the ride in the imager. The malware did not.**

---

## What players are given

One file: `CASE_2026_8902_DISK_L1.ad1` — a 20 MB FTK AccessData logical image — plus a short incident note.

Inside the AD1 (custom-content image, not a full disk):

| Item                      | Notes                                              |
| ------------------------- | -------------------------------------------------- |
| `sloth.png`               | clean WEBP/PNG, carries a Zone.Identifier ADS      |
| `llama.png`               | clean image, Zone.Identifier ADS                   |
| `punch.png`               | clean image, Zone.Identifier ADS                   |
| `sherkhan.png`            | clean image, Zone.Identifier ADS                   |
| `grr.png`                 | clean image, Zone.Identifier ADS                   |
| **`kaiser.png`**          | **clean JPEG (renamed .png), Zone.Identifier ADS** |
| `tiger.png`               | tiny stub, **no** Zone.Identifier                  |
| `Investigation_Notes.txt` | the one-paragraph incident note                    |
| `SOFTWARE`                | 70,184,960 byte registry hive — _the giveaway_     |

The Investigation_Notes.txt deliberately spells out the trick if you read it carefully:

> Standard AV scans showed all PNG files were clean, but network traffic indicates a **PE32 executable** was executed directly from a downloaded asset's **metadata**.

Two words doing the heavy lifting: **PE32** (not PE32+, i.e. 32-bit not 64-bit) and **metadata** (not file body).

---

## Layer 0 — Decoys to ignore

- **Every PNG `binwalk`s clean.** No appended PEs, no polyglots, no stego in low bits. The image bodies are honest.
- **Every Zone.Identifier ADS is a PE32+ x86-64 binary.** Five of them. They run as decoys — pop a console, print nonsense, exit. They're loud, they're big, they're not what you want.
- **`tiger.png` has no Mark-of-the-Web.** Players who chase "the one file without a Zone.Identifier must be the malware!" are wasting their time. Tiger is a 56-byte stub.

If you start by carving the PNG bodies, you'll get six clean images and conclude the challenge is broken. It isn't — you're looking at the wrong stream.

---

## Layer 1 — The deception is in the ADS, not the file

On NTFS, every file downloaded by a browser gets a `Zone.Identifier` Alternate Data Stream. Normally it contains a tiny INI:

```
[ZoneTransfer]
ZoneId=3
```

Here, every `Zone.Identifier` ADS contains a **full PE binary** instead. The Mark-of-the-Web slot — the place no analyst inspects with anything more than `cat` — is the dropzone.

Decompressing each one out of the AD1's zlib chunks:

| File           | Zone.Identifier ADS                      |
| -------------- | ---------------------------------------- |
| sloth.png      | PE32+ x86-64, console, MinGW             |
| llama.png      | PE32+ x86-64, GUI                        |
| punch.png      | PE32+ x86-64, GUI                        |
| sherkhan.png   | PE32+ x86-64, GUI                        |
| grr.png        | PE32+ x86-64, GUI                        |
| **kaiser.png** | **PE32 i386, console — the odd one out** |

One of these is not like the others. The note told you which: **PE32**, not PE32+. The real payload is the 32-bit binary stashed behind `kaiser.png`.

---

## Layer 2 — The payload's job

Parse the i386 PE's import table:

```
ADVAPI32.DLL
  RegOpenKeyExA
  RegQueryValueExA
  RegCloseKey
KERNEL32.dll  msvcrt.dll  (the usual)
```

And the string table is loud:

```
SOFTWARE\Microsoft\Cryptography
MachineGuid
[!] SYSTEM BREACHED. UNLOCKING PAYLOAD...
FLAG:
Starting image processing service...
Cleaning up temporary files...
```

The whole binary has one real job: read `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` — Windows' per-installation fingerprint — and derive a flag from it at runtime.

That's why the flag isn't on disk anywhere. `strings | grep DEDSEC` over the entire 20 MB image returns zero hits. The flag only exists once the payload's math is re-run against the GUID the imager preserved.

---

## Layer 3 — Reading the transformation

The interesting bit of the disassembly is a 38-iteration loop right after the `FLAG: ` print:

```
mov  eax, [ebp-0xc]            ; i
cmp  eax, 0x25                 ; while i <= 37
ja   end
add  eax, 0x4a2020             ; key_table[i]
movzx eax, byte ptr [eax]
mov  esi, eax                  ; key byte

mov  eax, [ebp-0xc]
mov  edx, 0
div  ecx                       ; i mod len(guid)
...                            ; fetch guid[i mod len]
xor  eax, esi                  ; XOR with key byte
push eax
push "%c"
call printf
add  [ebp-0xc], 1
```

So: `flag[i] = MachineGuid[i % 36] XOR key_table[i]` for `i = 0..37`. The key table lives at VA `0x4a2020` in the `.data` section:

```
72 77 25 35 26 20 1f 5d 1e 0d 02 10 55 49 6b 00
05 5a 1e 66 52 41 43 72 58 09 10 3e 50 04 11 57
00 47 40 01 58 4f                              (38 bytes)
```

That's the whole algorithm.

---

## Layer 4 — Recovering the MachineGuid from the captured hive

The malware self-deleted on the live box, but the imager scooped up the `SOFTWARE` hive alongside the Downloads folder — that's the one detail the theme note keeps hammering:

> _the system remembers more than its users do._
> _look at what the machine knew about itself._

Carve the hive out of the AD1 by concatenating its zlib chunks (70,184,960 bytes, `regf` header), then:

```bash
$ hivexget SOFTWARE_hive.bin 'Microsoft\Cryptography' MachineGuid
62afccd9-a1df-4f46-9047-69da64c00342
```

---

## Layer 5 — Run the malware's math by hand

```python
guid  = "62afccd9-a1df-4f46-9047-69da64c00342"
key   = bytes.fromhex(
    "7277253526201f5d1e0d021055496b00"
    "055a1e6652414372580910 3e500411 57"
    "00474001584f".replace(" ","")
)
flag = "".join(chr(ord(guid[i % len(guid)]) ^ key[i]) for i in range(38))
print(flag)
```

```
DEDSEC{d3l3t3d_f1l3_but_n0t_f0rg0tt3n}
```

---

## What I learned designing this

Three things make Deadly Downloads harder than its components suggest:

1. **The deception is one NTFS stream sideways.** Players are trained to carve, `binwalk`, `strings`, and inspect file bodies. The Zone.Identifier ADS is a stream almost no one reads past — and in real Windows incidents it's a well-known dead-drop slot for downloaders. Hiding a payload in MOTW is uncomfortable on purpose.
2. **The loud decoys outnumber the real signal.** Five PE32+ decoys, one PE32. The incident note tells you which architecture to care about, but only if you read for _exact_ wording. "PE32" vs "PE32+" is a single character, and the analyst who skims will treat them as synonyms.
3. **The flag is never written down.** No `flag.txt`, no embedded string, no static decode path. The flag only exists when you marry the reversed payload's algorithm to the registry value preserved in the hive — i.e., you have to do the malware's job for it, using artefacts the malware never knew it was leaving behind.

The two artefacts the attacker actually needed — the payload and the MachineGuid — survived in the two places the attacker didn't bother to clean: the Zone.Identifier ADS, and the registry hive the imager pulled in by accident. That's the design. Forensics is what's left behind, not what's still running.

— Murugan
