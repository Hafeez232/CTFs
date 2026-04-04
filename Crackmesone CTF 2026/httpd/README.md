# httpd - Reverse Engineering CTF Write Up

<img width="649" height="460" alt="chall-info" src="https://github.com/user-attachments/assets/3586cccb-3b59-42a5-b4ff-9294ca812a8a" />

Difficulty: Medium

Category: Reverse Engineering

---
Description:

This file was found on an infected host. Can you figure out what it does?

Author: crudd

---

Files:

- `httpd`

---

### Initial Triage

 ```text
$ file httpd
httpd: ELF 64-bit LSB executable, x86-64, version 1 (FreeBSD), dynamically linked, interpreter /libexec/ld-elf.so.1, for FreeBSD 14.3, FreeBSD-style, Go BuildID=qFhGj9dLilyvUQG0jioV/pdT2CXTFFROnGyFt_iWG/4oSXKlJuQ2v7ZdSaKAaG/1odovLc3PIPvXv8LHbgL, with debug_info, not stripped
```
- A 64-bit executable compiled for x86-64 architecture
- compiled to run in FreeBSD 14.3 using the interpreter /libexec/ld-elf.so.1
- written in Golang. (Golang decompilation are really different than C/C++)
- Symbols are not stripped (thankfully!). Dealing with stripped Golang binaries is a nightmare so the author was quite helpful here.

Before jumping into the challenge, let’s try running it first (and see the error).

```text
└─$ ./httpd
zsh: no such file or directory: ./httpd
```

The binary cannot be executed directly on Kali because it expects the FreeBSD loader

---

### Main Function Static Analysis

In Golang, the main function is main.main.

<img width="1118" height="552" alt="image" src="https://github.com/user-attachments/assets/a9ebc1c9-c386-4acf-8fec-f802e8fd3a89" />

- The main function initializes a local HTTP server configured to run on port 8080.
- There are two Fprintln calls with unclear messages; this is a common side effect of how decompilers interpret Go binaries.
- Unlike C-style strings, Go strings are not null-terminated. Instead, they are defined as a `struct` 

---

### Decoy HTTP Server

<img width="652" height="423" alt="image" src="https://github.com/user-attachments/assets/fe836829-7c21-4f94-b069-4e434696a186" />

The handler logic is simple:

- If the request method is `GET`, it returns:

```text
Nothing to see here :{
```

- Otherwise it returns:

```text
Method not allowed
```

----

### Finding the Hidden Functionality

The binary imports `github.com/google/gopacket/pcap`, which is unusual for a normal HTTP daemon and a strong sign that it is sniffing packets.

<img width="728" height="371" alt="image" src="https://github.com/user-attachments/assets/209ddb92-e8bf-4b6c-b24e-1c9f6d4de751" />

Disassembly of the background goroutine shows:

- `pcap.OpenLive("re0", ...)`
- `SetBPFFilter("icmp")`
- a loop over captured packets

So the logic is:

1. Listen on network interface `re0`
2. Only capture ICMP traffic
3. Look for one very specific packet layout
4. Use values from that packet to decrypt a secret

---

### Packet Trigger Conditions

<img width="673" height="451" alt="image" src="https://github.com/user-attachments/assets/dcf6e8d3-2fdd-4f2a-b2f8-c0fa501bd7c5" />

- Packet length must be at least `0x2e`
- `raw[0x22] == 0x08`
  - ICMP type must be **Echo Request**
- `raw[0x26:0x28] == 37 13`
  - ICMP identifier bytes must be `37 13`
- `raw[0x2a:0x2e] == c6 de 5f e5`
  - First 4 bytes of ICMP payload
- `raw[0x10:0x12] == 00 20`
  - IP total length must be `0x0020`

That gives us the intended packet shape:

- IPv4
- ICMP Echo Request
- total length `0x20`
- `id=0x3713`
- payload starts with `c6 de 5f e5`

---

### Embedded Ciphertext

<img width="673" height="563" alt="image" src="https://github.com/user-attachments/assets/edc96fb0-a61d-4453-8dd5-55caf48decbd" />

There's promising key array variable being assigned some values based on the captured packet bytes.

- `crypto/aes.NewCipher(key)`
- `cipher.NewCBCDecrypter(block, iv)`
- decrypts the 32-byte blob
- prints the resulting plaintext

bytes in memory: 
```text
0xC07EDFB429A5F151 -> 51 f1 a5 29 b4 df 7e c0
0xB34E3D248F2F3B2A -> 2a 3b 2f 8f 24 3d 4e b3
0x8CDD9C0BCFB0ED5A -> 5a ed b0 cf 0b 9c dd 8c
0x0C64C43E9B0EE6CD -> cd e6 0e 9b 3e c4 64 0c
```

Result:
```text
51f1a529b4df7ec02a3b2f8f243d4eb35aedb0cf0b9cdd8ccde60e9b3ec4640c
```

---

## Reconstructing the Key Schedule

Since we saw it in the comparison against `raw[0x2a:0x2e]` before. In assembly it appears as:

`cmp dword ptr [reg+2Ah], 0E55FDEC6h`

Because x86 is little-endian, the actual packet bytes are:

`c6 de 5f e5`

The binary also reads the 2-byte ICMP checksum from `raw[0x24:0x26]`. It mixes that checksum with the constant above to derive two extra 2-byte values, then concatenates everything into the final AES key.

Tthe 16-byte AES key should assembled like this:

- 2 derived bytes from A and the checksum
- 4 bytes from `raw[0x14:0x18]`
- 2 bytes from `raw[0x24:0x26]`
- 4 bytes from `raw[0x2a:0x2e]`
- 2 bytes from `raw[0x26:0x28]`
- 2 more derived bytes from A and the checksum

The key is packet-dependent and if any of those packet fields change, the derived AES key changes too.

This produces a **16-byte AES key**.

The IV is the same 16-byte value.

---

## Recovering the Correct Packet Values

Since no `.pcap` file was provided, the solve had to come entirely from the binary.

At this point we already know most of the trigger packet:

- IP flags/fragment bytes
- TTL
- ICMP checksum
- ICMP sequence

These values are not all directly obvious, but they are constrained by the packet structure and checksum logic. By reproducing the checksum calculation and testing valid candidates offline, the correct combination is:

- IP flags/fragment field: `0x4000`
- TTL: `64`
- protocol: `1`
- ICMP checksum bytes: `9a27`
- ICMP id bytes: `3713`
- ICMP sequence: `1`
- payload prefix: `c6de5fe5`


From this, can either use GPT/Claude to create a script:

```text
import struct

def rol16(x: int, n: int = 8) -> int:
    return ((x << n) & 0xFFFF) | (x >> (16 - n))

def derive_key() -> bytes:
    flags_fragment = 0x4000
    ttl = 64
    protocol = 1
    checksum = bytes.fromhex("9a27")
    icmp_id = bytes.fromhex("3713")
    payload_prefix = bytes.fromhex("c6de5fe5")

    a = 0xE55FDEC6
    b = int.from_bytes(checksum, "little")

    t1 = rol16(((a >> 16) ^ b) & 0xFFFF, 8)
    t2 = rol16((a ^ b) & 0xFFFF, 8)

    key = (
        t1.to_bytes(2, "little")
        + struct.pack("!HBB", flags_fragment, ttl, protocol)
        + checksum
        + payload_prefix
        + icmp_id
        + t2.to_bytes(2, "little")
    )
    return key

def main() -> None:
    key = derive_key()
    print("AES key:", key.hex())

if name == "main":
    main()
```

Output:
```text
└─$ python3 derive_aes_key.py 
AES key: c2c5400040019a27c6de5fe53713f95c
```

---

## Decryption

Using the recovered key and the embedded ciphertext:

- Ciphertext:

```text
51f1a529b4df7ec02a3b2f8f243d4eb35aedb0cf0b9cdd8ccde60e9b3ec4640c
```

- Key:

```text
c2c5400040019a27c6de5fe53713f95c
```

- IV:

```text
c2c5400040019a27c6de5fe53713f95c
```

Decryption reveals:

<img width="959" height="761" alt="Screenshot 2026-02-17 110709" src="https://github.com/user-attachments/assets/fe83f13e-45d2-470e-8a08-947bea06d38c" />

```text
CMO{fUn_w1th_m4g1c_p4ck3t5}
```

---

## Notes

- The HTTP server is only a decoy.
- The actual secret is gated behind a crafted ICMP packet and packet-derived AES key material.
- Because symbols were present and the binary was not stripped, static reversing was enough to solve it completely without needing a runtime environment or packet capture.

---

## Flag

```text
CMO{fUn_w1th_m4g1c_p4ck3t5}
```
