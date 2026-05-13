# Deadly Downloads — DEDSEC CTF Writeup

**Category:** Digital Forensics / Reverse Engineering
**Difficulty:** Hard

> *You are looking for something that was never meant to stay.*
> *The attacker did not rely on stealth alone. They relied on confusion.*
> *A workstation. A handful of harmless files. A payload that existed only for a moment.*
> *It ran. It collected what it needed. Then it vanished.*

---

## The premise

A workstation was compromised. The attacker dropped a few files into the user's Downloads folder, ran something briefly, exfiltrated, and cleaned up. By the time the forensic acquisition was taken, the malware was already gone.

Players get one artefact: `CASE_2026_8902_DISK_L1.ad1` — an FTK Imager AccessData logical-image file. Their job is to walk through what looks like an ordinary Downloads folder of harmless pictures, figure out which file isn't what it claims to be, reverse-engineer the payload, and reconstruct the flag from a host-specific registry value the malware was after.

This isn't a "find the flag.txt" challenge. The flag never sat on disk in plaintext. It only exists once you understand what the malware was *trying to do* — and re-do it.

---

## Step 1 — Mount the image, look at the noise

Load the `.ad1` in FTK Imager (or any tool that speaks AccessData's container format). The user profile's `Downloads` folder is filled with normal-looking image files — a bunch of `.png`s, `.jpg`s, some screenshots. Nothing obviously hostile.

If you `strings` them or run them through `binwalk`, several appear to have an executable embedded. That's the **first trap**. Players who jump straight to "extract the PE, drop it in a sandbox" will burn the next two hours staring at decoy executables that print insults.

---

## Step 2 — Mark-of-the-Web is the giveaway

Every file downloaded by a browser on Windows gets an **NTFS Alternate Data Stream** named `Zone.Identifier`. It's the Mark-of-the-Web — that "this file came from the internet, are you sure?" prompt is driven by this ADS.

Inside the `.ad1`, the Downloads folder shows every image carrying a `:Zone.Identifier` stream — completely normal for browser downloads.

Except one of those streams *lies*.

I planted Zone.Identifier streams on several decoy images saying things like `ReferrerUrl=...malware-c2.example/payload.exe` — bait for analysts who skim the ADS contents and chase the loudest indicator. None of those files actually do anything.

The real payload is the **boring one**. `kaiser.png` looks like a meme. Its Zone.Identifier is mundane. Its image preview renders correctly. But it's a polyglot: a valid PNG with a Win32 executable appended after the IEND chunk.

The point of misdirection here is that everything looks dangerous *except* the thing that actually is.

---

## Step 3 — Carve out the embedded binary

Find the PNG IEND marker (`49 45 4E 44 AE 42 60 82`) and split:

```bash
# Quick carve — split kaiser.png at IEND
python3 - <<'PY'
data = open("kaiser.png","rb").read()
iend = data.index(b"IEND\xaeB`\x82") + 8
open("legit.png","wb").write(data[:iend])
open("payload.bin","wb").write(data[iend:])
PY

file payload.bin
# → PE32+ executable (console) x86-64, for MS Windows
```

You now have a Windows x64 executable that the malware was running before it self-deleted.

---

## Step 4 — Reverse the C++ payload

Drop the binary into Ghidra / IDA / Binary Ninja. After cutting through the CRT noise, the logic is short. The original C++ does something like:

```cpp
HKEY hKey;
char machineGuid[64] = {0};
DWORD size = sizeof(machineGuid);

RegOpenKeyExA(HKEY_LOCAL_MACHINE,
              "SOFTWARE\\Microsoft\\Cryptography",
              0, KEY_READ | KEY_WOW64_64KEY, &hKey);
RegQueryValueExA(hKey, "MachineGuid", NULL, NULL,
                 (LPBYTE)machineGuid, &size);
RegCloseKey(hKey);

// strip dashes, leetify, wrap as flag
build_flag(machineGuid);
exfil(machineGuid);
```

The takeaway: the payload's only real job was to read **`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`**. That's a per-installation identifier Windows generates at install time. The malware was fingerprinting the box.

`MachineGuid` is the secret the attacker exfiltrated. So that's what the flag is built from.

But the malware is gone — it cleaned itself up after running. How do you get the GUID back?

---

## Step 5 — The system remembers what the user doesn't

The challenge brief points right at this:

> *"But the system remembers more than its users do.*
> *If you want to understand what happened, you will need to look at what the machine knew about itself."*

`MachineGuid` is stored in the registry. The registry is on disk. The `.ad1` is a disk image. So the answer is sitting in the SOFTWARE hive of the captured system.

Mount the image, copy out `C:\Windows\System32\config\SOFTWARE`, and load it offline:

```bash
# Linux side — using regipy
pip install regipy
regipy-dump SOFTWARE | jq '.[] | select(.Path|test("Cryptography$"))'

# Or from Windows: load the hive
reg load HKLM\OFFLINE C:\path\to\SOFTWARE
reg query HKLM\OFFLINE\Microsoft\Cryptography /v MachineGuid
reg unload HKLM\OFFLINE
```

You get the GUID embedded in the disk image — for example:

```
MachineGuid    REG_SZ    1a2b3c4d-5e6f-7a8b-9c0d-e1f2a3b4c5d6
```

Now run the same transformation the payload does: strip dashes, apply the leetspeak substitution the binary's `build_flag()` performs, and wrap it in the flag format. That's the flag the malware would have exfiltrated had it not been caught mid-act.

---

## Why this design

Three things make Deadly Downloads harder than it reads:

1. **Every file is suspicious.** Stuff a folder with Zone.Identifier streams pointing at malicious URLs, embed decoy PEs in five of them, and the real payload becomes the one with the most boring metadata. Analysts trained to follow indicators learn to distrust the loud ones; the trap is that they're not yet trained to also distrust the quiet ones.
2. **No flag string exists anywhere on disk.** Static scanners, `strings`, `grep -r 'DEDSEC{'`, YARA rules — none of them will find this flag, because the flag is computed at runtime from a value that the imager preserved by accident. The flag exists only when you marry the reversed payload to the registry hive.
3. **The malware is gone, but the host remembers.** The whole point is the artefact the attacker actually wanted. Players have to think like the attacker, not like the responder cleaning up after.

This was my favourite to design because the solve path mirrors how real DFIR works: the threat is gone, the binary is half-recovered, and the question is no longer "what did it do" but "what did it learn about this machine."

— Murugan
