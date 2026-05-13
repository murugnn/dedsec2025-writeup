# Broken Wire — DEDSEC CTF Writeup

**Category:** Forensics / Crypto
**Difficulty:** Hard
**Flag:** `DEDSEC{p4ck3ts_d0nt_l13_p30pl3_d0}`

---

## Why I built this challenge

Every CTF has _that_ network forensics problem where you open Wireshark, the first packet you click is the flag, and you submit it in 90 seconds. I wanted Broken Wire to feel like real packet analysis — the kind where you're staring at 1100 packets, eleven protocols are talking over each other, and the "obvious" lead is a planted decoy that wastes your afternoon.

So I designed a three-layer covert channel. Players don't need a single crypto trick. They need the patience to recognise that **the protocol carrying the data is not the one screaming for attention.**

---

## What players are given

A single `chall.pcap` with **1108 packets**:

| Protocol      | Count | Notes                                                 |
| ------------- | ----- | ----------------------------------------------------- |
| DNS           | 522   | ~320 noise A-records + 3 key TXT + 2 decoy TXT        |
| TCP (no data) | 149   | SYN/SA/RST handshakes                                 |
| HTTP/TCP      | 144   | Mix of noise + 3 covert responses from Host B         |
| ICMP          | 91    | Noise + 7 covert chat messages                        |
| ARP           | 78    | Network noise                                         |
| NTP           | 46    | Noise                                                 |
| Syslog        | 33    | Noise                                                 |
| NetBIOS       | 18    | Noise                                                 |
| SNMP          | 14    | Noise                                                 |
| DHCP          | 8     | Noise                                                 |
| **UDP:9001**  | **5** | **Red herring — looks exactly like a covert payload** |

If you start with the UDP 9001 traffic, you'll burn an hour. The five packets contain random binary that smells like an encrypted payload. It isn't.

---

## Layer 0 — Decoys to ignore

- **UDP port 9001:** 5 packets of random bytes from Host B. The "this is obviously the flag carrier" trap.
- **DNS TXT `updates.cdn-static.net`:** returns `bm90dGhla2V5` → base64 for `"notthekey"`.
- **DNS TXT `metrics.devops-hub.io`:** returns `d3JvbmdwYXNz` → base64 for `"wrongpass"`.

The base64 decoys are deliberately friendly — easy to decode, instantly recognisable as fake. They're there to fail-fast players who automate "extract all TXT records and base64 them."

---

## Layer 1 — ICMP covert chat (XOR 0x42)

Filter in Wireshark:

```
icmp.type == 8
```

Of the 91 ICMP packets, 7 carry an ICMP ID of `0xBEEF` and unprintable payloads. XOR every byte of the data field with `0x42`:

```python
decoded = bytes(b ^ 0x42 for b in raw_data).decode()
```

Sorted by ICMP sequence number, the conversation reads:

```
[A seq=1]: channel clean?
[B seq=2]: yeah. wrapped and sealed.
[A seq=3]: blocks?
[B seq=4]: sixteen bytes. no chain.
[A seq=5]: key's in three parts. check the txt records. sequence matters.
[A seq=6]: cargo's in the server replies. look past the headers.
[B seq=7]: move.
```

That's the entire roadmap for the challenge, delivered as a chat between two operators. It tells you:

1. The key is split across TXT records, and the order matters.
2. The block size is 16 bytes with no chaining → AES-128-ECB.
3. The ciphertext is hidden inside HTTP bodies.

If you skipped ICMP because "no one hides flags in ping," you're now staring at 522 DNS records with no context.

---

## Layer 2 — DNS TXT, ordered by TTL

Filter:

```
dns.qry.type == 16
```

There are five TXT responses. Two are the base64 decoys. The other three look harmless — short English words. The trick is the TTL field. Normally TTL is "how long can a resolver cache this." Here I reused it as a sequence number:

| Domain                 | TXT value | TTL (= sequence) |
| ---------------------- | --------- | ---------------- |
| `sync.cloud-edge.io`   | `"drug"`  | 1                |
| `relay.opsec-cdn.com`  | `"drop"`  | 2                |
| `vault.secops-api.net` | `"dead"`  | 3                |

The decoy TXTs use TTL 300 — a "normal" value — so if you sort by TTL you naturally pull the real ones to the top.

Concatenate in order: `drug + drop + dead` → `drugdropdead`.

From the chat: **"sixteen bytes. no chain."** AES-128-ECB needs a 16-byte key. `drugdropdead` is 12. Null-pad it:

```python
key = b"drugdropdead" + b"\x00" * 4
```

---

## Layer 3 — Ciphertext hidden in HTTP response bodies

Filter:

```
ip.src == 10.13.37.202 && tcp.srcport == 80
```

Among all the HTTP responses from Host B, three carry a custom `X-Trace-Id` header and a JSON body shaped like a normal API response:

```
HTTP/1.1 200 OK
X-Trace-Id: 1
Content-Type: application/json

{"status":"ok","ts":1708820400,"d":"76fce9306147014f2ef0237665cae99f"}
```

Order by `X-Trace-Id` (another custom-header sequence trick):

```
Id=1: 76fce9306147014f2ef0237665cae99f
Id=2: 6441c56b455f7ceda4c7cc71e5a9fab3
Id=3: 8be6ae12f5159ce4077e4f5420e6f6e4
```

Three 16-byte AES blocks → 48 bytes of ciphertext.

---

## Layer 4 — Decrypt

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"drugdropdead\x00\x00\x00\x00"
ct  = bytes.fromhex(
    "76fce9306147014f2ef0237665cae99f"
    "6441c56b455f7ceda4c7cc71e5a9fab3"
    "8be6ae12f5159ce4077e4f5420e6f6e4"
)
print(unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16).decode())
```

```
DEDSEC{p4ck3ts_d0nt_l13_p30pl3_d0}
```

---

## What I learned designing this

Two things made this challenge work harder than its components suggest:

1. **The decoys are friendlier than the signal.** Every player automatically pulls all DNS TXT, all UDP payloads, all base64-looking strings. So I made the _obviously decodable_ paths the wrong ones, and the real channel — XOR-obfuscated ICMP echo data — looks like binary garbage on first glance.
2. **TTL and `X-Trace-Id` as ordering primitives are uncomfortable.** Players know to sort by sequence number for TCP, by ID for IP, by timestamp for everything. Reusing TTL as an index breaks the muscle memory.

The chat in ICMP is the spine of the whole solve. If you read it, the rest is mechanical. If you don't, you're guessing for hours. That's the design.

— Murugan
