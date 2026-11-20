# HOLLOW KNIGHT Series (1-2) - MIIT Internal CTF Write Up

Difficulty: Medium

Category: Malware Analysis


## HOLLOW KNIGHT 1


Description:

A suspicious binary was found on a compromised machine. The binary loads an encrypted file from disk, decrypts it at runtime, and executes it silently inside a legitimate Windows process. Analyze the binary and find the hidden flag.

---

Files:

- `H0LLoW_KN1GHT.exe`
- `hacked.bin`

---

### Initial Triage

```text
$ file H0LLoW_KN1GHT.exe
H0LLoW_KN1GHT.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sections

$ file hacked.bin
hacked.bin: data

$ wc -c hacked.bin
145408 hacked.bin
```

- A 64-bit Windows console executable.
- `hacked.bin` is a 145,408-byte data blob with an entropy of **7.999 bits/byte**. A strong sign that it is encrypted or compressed.
- The executable is a PE32+


Before jumping into the disassembly, running strings tells us.

<img width="719" height="148" alt="image" src="https://github.com/user-attachments/assets/5ea80891-075f-4be0-b0d4-3553ddf57bd6" />

The `hacked.bin` is the file being loaded, and `notepad.exe` is the legitimate process that will host it. While another path gives away the original project name


The import table is small, gives strong clue:

```text
CreateProcessW
VirtualAllocEx
WriteProcessMemory
ReadProcessMemory
GetThreadContext
SetThreadContext
ResumeThread
VirtualProtectEx
CreatePipe
PeekNamedPipe
ReadFile
lstrlenW
```

Creating a process, allocating memory inside it, writing to it, editing its thread context and resuming it is the classic recipe for **process hollowing**. The pipe APIs are there to capture the payload's output silently.

---

### Following main()

In this binary, the `main` flow is surprisingly readable.

<img width="830" height="538" alt="image" src="https://github.com/user-attachments/assets/cdc27bea-e8f1-4b2b-bdf5-34935c90236c" />
<img width="672" height="550" alt="image" src="https://github.com/user-attachments/assets/951175a5-0aa0-4ef1-9993-9800d09c7882" />

Roughly, `main` does this:

1. Opens `C:\payload\hacked.bin` with mode `"rb"`.
2. Reads the whole file into a heap buffer and keeps its size.
3. Decrypts the buffer with `sub_1400014F0`.
4. Walks the decrypted bytes as a PE file (`MZ`, `e_lfanew`, `PE\0\0`).
5. Creates `C:\Windows\System32\notepad.exe` in a suspended state.
6. Replaces notepad's image with the decrypted PE and resumes its main thread.
7. Reads the injected payload's output through anonymous pipes.

The suspended creation is easy to spot in the call setup:

```text
140001a5f  c7 44 24 28 14 00 00 00   movl $0x14,0x28(%rsp)
140001a67  c7 44 24 20 01 00 00 00   movl $0x1,0x20(%rsp)
140001a6f  ff 15 ...                  call CreateProcessW
```

`0x14` is `CREATE_SUSPENDED (0x4) | CREATE_NEW_CONSOLE (0x10)`, and the fifth argument at `[rsp+0x20]` is `TRUE` for handle inheritance. On top of that, the `STARTUPINFO` has `STARTF_USESHOWWINDOW` set and `wShowWindow = SW_HIDE`, so notepad never shows a window.

But before any of that happens, the encrypted file has to be decoded.

---

### Reconstructing the RC4 Key

The decryption routine is `sub_1400014F0`, called from `main`.

It builds a **64-byte key on the stack** from two separate pieces.

#### Piece 1 - IP addresses to hex

Four IP address strings are stored in `.rdata` at `0x1400244c0`:

<img width="565" height="224" alt="image" src="https://github.com/user-attachments/assets/d4d855ba-628e-44b2-bca9-2c81bb94e3b9" />

Because x86 is little-endian, the actual IP are:
```text
25.001.861.291  ->  192.168.100.52
21.01.01.01     ->  10.10.10.12
321.231.61.271  ->  172.16.132.123
151.38.77.251   ->  152.77.83.151
```

The binary runs each one through `strtok` / `atoi` / `sprintf("%02X")`, turning every octet into two uppercase hex digits:

```text
192.168.100.52   -> C0 A8 64 34
10.10.10.12      -> 0A 0A 0A 0C
172.16.132.123   -> AC 10 84 7B
152.77.83.151    -> 98 4D 53 97
```

Concatenated, that gives a 32-byte ASCII string:

```text
C0A864340A0A0A0CAC10847B984D5397
```

#### Piece 2 - the 64-byte template

<img width="593" height="109" alt="image" src="https://github.com/user-attachments/assets/cee187dd-0802-4dba-a44e-8eda91cc4777" />

A second buffer is assembled from four 16-byte blocks. In memory order it looks like this:

```text
NbQ%:SJ;]{k!WuKr
:h!8J%4@FXayMqW!
}bV]H#]Na]2qEi[R
}aJ4/*:E52%+,iT\0
```

The last block is 15 visible characters plus the string terminator, so the full key material is exactly 64 bytes.

#### Putting it together

`fcn.140001070` XORs all 64 bytes of the template with the 32-byte hex string, repeating it as needed:

```c
for (i = 0; i < 64; i++)
    key[i] = template[i] ^ hexstr[i % 32];
```

That produces the final RC4 key:

```text
0d52101d0c67790f6d3a5b6067347b317b2b1008721103027f60553d78426e
163e5217657e176e7a511c023075286b113c227b04171e0d070c0a116f195a6d37
```

The routine then performs a textbook RC4 KSA. The `0x3f` mask is the giveaway that the key is 64 bytes long:

```c
for (i = 0; i < 256; i++) {
    j = (j + S[i] + key[i & 0x3f]) & 0xff;
    swap(S[i], S[j]);
}
```

The PRGA that follows is completely standard:

```c
i = (i + 1) & 0xff;
j = (j + S[i]) & 0xff;
swap(S[i], S[j]);
plaintext[n] = ciphertext[n] ^ S[(S[i] + S[j]) & 0xff];
```

---

### Decrypting hacked.bin

Since the whole scheme is RC4 with a static key, we can decrypt the file offline. The essential part of the solver looks like this:

```python
KEY_TEMPLATE = (
    b"NbQ%:SJ;]{k!WuKr"
    b":h!8J%4@FXayMqW!"
    b"}bV]H#]Na]2qEi[R"
    b"}aJ4/*:E52%+,iT\x00"
)

IP_LIST = ["192.168.100.52", "10.10.10.12", "172.16.132.123", "152.77.83.151"]

def build_key():
    hexstr = "".join(f"{int(o):02X}" for ip in IP_LIST for o in ip.split(".")).encode()
    return bytes(t ^ hexstr[i % len(hexstr)] for i, t in enumerate(KEY_TEMPLATE))

def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xff]
    return bytes(out)
```

Running it on `hacked.bin` immediately produces a valid `MZ` header:

```text
$ python3 solve.py
[+] RC4 key (64 bytes): 0d52101d...6d37
[+] Decrypted payload: 145408 bytes, sections: .text, .rdata, .data, .pdata, .flag
[+] Flag: miit2026{r3v3rs3r_b3rj4y4_:3}
```

The decrypted bytes form another PE32+:

```text
PE32+ executable for MS Windows 6.00 (console), x86-64, 5 sections
```

Sections:

```text
.text   0x16500
.rdata  0x0aafa
.data   0x00c00
.pdata  0x01380
.flag   0x00080
```

A section literally called `.flag` is always a good sign.

---

### Inside the decrypted payload

The payload's `main` is at `0x140001010` and is short:

1. Prints `haha you've been hacked :3`.
2. Copies **29 bytes** (`0x1d`) from `.data` at virtual address `0x140023020` into `.flag` at virtual address `0x140027000`.
3. XORs every byte with `0x41` while copying.

The loop is easy to read:

```text
0x140001040  movzx ecx, byte [rax + rdx + 0x23020]
0x140001048  xor   cl, 0x41
0x14000104b  mov   byte [rax + rdx + 0x27000], cl
0x140001052  inc   rax
0x140001055  cmp   rax, 0x1d
0x140001059  jb    0x140001040
```

The obfuscated bytes in `.data` are:

```text
140023020 2c282835 73717377 3a337237 72333272
140023030 331e2372 332b7538 751e7b72 3c000000
```

Three strings in `.rdata` look like flags, but they are all decoys:

```text
miit2026{h4ck3r_w4s_h3r3_:3}
miit2026{s1k1t_l4g1_j4ng4n_give_up_:3}
miit2026{jumpa_t4k_cuba_l4g1_:3}
```

Nothing in the code references them; they exist purely to punish `strings`-only analysis. The real flag is the 29 bytes that get XORed at runtime.

---

### Recovering the flag

XOR the 29 obfuscated bytes with `0x41`:

```text
raw : 2c 28 28 35 73 71 73 77 3a 33 72 37 72 33 32 72
      33 1e 23 72 33 2b 75 38 75 1e 7b 72 3c
xor : 6d 69 69 74 32 30 32 36 7b 72 33 76 33 72 73 33
      72 5f 62 33 72 6a 34 79 34 5f 3a 33 7d
```

which gives:

```text
miit2026{r3v3rs3r_b3rj4y4_:3}
```

Flag recovered. Now, the second question in this challenge asks for the MITRE ATT&CK sub-technique used by the dropper.

---

## Part 2 - Mapping to MITRE ATT&CK

### T1055.012 - Process Injection: Process Hollowing

The binary is a clean x64 implementation of **process hollowing**:

- **Technique:** T1055 Process Injection
- **Sub-technique:** **T1055.012 Process Hollowing**
- **Tactics:** Defense Evasion (TA0005), Privilege Escalation (TA0004)
- **Platform:** Windows

It is also commonly called **RunPE** or **process replacement**.

### Evidence in the binary

| Hollowing stage | What the binary does | Address |
|---|---|---|
| Create host suspended | `CreateProcessW("C:\Windows\System32\notepad.exe", ..., dwCreationFlags = 0x14)` | `0x140001a6f` |
| Hide the window | `STARTUPINFO.dwFlags = 0x101`, `wShowWindow = SW_HIDE` | `0x1400019ae` / `0x1400019e5` |
| Allocate remote image | `VirtualAllocEx(hProcess, preferredImageBase, SizeOfImage, 0x3000, 0x04)` | `0x140002137` |
| Write PE headers | `WriteProcessMemory(hProcess, newBase, headers, ...)` | `0x140002170` |
| Write PE sections | loop over the section table, write each `PointerToRawData` / `SizeOfRawData` | `0x1400021b0` |
| Get original context | `GetThreadContext(hThread, &ctx)` | `0x140002033` |
| Get the PEB | `PEB = ctx.Rdx` (`ctx + 0x88`) | `0x140002041` |
| Patch the PEB path | rewrite `PEB->ProcessParameters` image path back to notepad | `0x140001c50` |
| Patch the image base | `WriteProcessMemory(hProcess, PEB + 0x10, &newBase, 8)` | `0x14000207c` |
| Patch the entry point | `ctx.Rcx = newBase + AddressOfEntryPoint` (`ctx + 0x80`) | `0x14000209a` |
| Resume the thread | `SetThreadContext`, then `ResumeThread` | `0x14000209e` / `0x140001b08` |
| Restore protections | `VirtualProtectEx` per section | `0x14000230f` |

The suspended flag is the most important piece:

```text
0x14 = CREATE_SUSPENDED (0x00000004) | CREATE_NEW_CONSOLE (0x00000010)
```

And on x64, after `GetThreadContext`, `RDX` holds the PEB, so the code:

1. reads the PEB,
2. rewrites the process image path in `RTL_USER_PROCESS_PARAMETERS` back to `C:\Windows\System32\notepad.exe`,
3. replaces `PEB->ImageBaseAddress` with the new image base,
4. sets `RCX` to the new entry point,
5. calls `SetThreadContext`,
6. resumes the thread.

That is exactly the hollowing hand-off.

### A small note about this variant

This implementation does **not** call `NtUnmapViewOfSection`. Instead of unmapping notepad's original image, it allocates a fresh region with `VirtualAllocEx`, writes the replacement PE there, updates `PEB->ImageBaseAddress`, and redirects the initial thread. Behaviorally this is still process hollowing, just a no-unmap variant, and it still maps to **T1055.012**.

### Supporting tradecraft

The encrypted payload staging is also worth mentioning, although it is not the injection sub-technique itself:

- **T1027 - Obfuscated Files or Information** (RC4-encrypted `hacked.bin`)
- **T1140 - Deobfuscate/Decode Files or Information** (runtime RC4 decryption)

---

## Building the Solver

The complete solver is saved as `solve.py`. Its important parts are the key derivation, RC4, a small dependency-free PE section parser, and the final XOR:

```python
#!/usr/bin/env python3
import struct

KEY_TEMPLATE = (
    b"NbQ%:SJ;]{k!WuKr"
    b":h!8J%4@FXayMqW!"
    b"}bV]H#]Na]2qEi[R"
    b"}aJ4/*:E52%+,iT\x00"
)

IP_LIST = ["192.168.100.52", "10.10.10.12", "172.16.132.123", "152.77.83.151"]

def build_key():
    hexstr = "".join(f"{int(o):02X}" for ip in IP_LIST for o in ip.split(".")).encode()
    return bytes(t ^ hexstr[i % len(hexstr)] for i, t in enumerate(KEY_TEMPLATE))

def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xff]
    return bytes(out)

def pe_sections(blob):
    e_lfanew = struct.unpack_from("<I", blob, 0x3c)[0]
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", blob, coff + 2)[0]
    opt_size = struct.unpack_from("<H", blob, coff + 16)[0]
    table = coff + 20 + opt_size
    sections = {}
    for i in range(nsec):
        off = table + 40 * i
        name = blob[off:off + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", blob, off + 8)
        sections[name] = (vaddr, vsize, rawptr, rawsize)
    return sections

payload = rc4(build_key(), open("hacked.bin", "rb").read())
assert payload[:2] == b"MZ"
raw = payload[pe_sections(payload)[".data"][2] + 0x20:][:0x1d]
print(bytes(b ^ 0x41 for b in raw).decode())
```

Output:

```text
miit2026{r3v3rs3r_b3rj4y4_:3}
```

---

## Notes

- `hacked.bin` is a full PE payload, not shellcode. The dropper injects it as an image and fixes up the PEB and thread context.
- The RC4 key is not stored anywhere in plaintext; it is assembled from decoy-looking IP address strings and a 64-byte `.rdata` template.
- The three `miit2026{...}` strings in the payload's `.rdata` are decoys. The real flag is only produced at runtime by XORing 29 bytes from `.data` with `0x41`.
- The binary never calls `NtUnmapViewOfSection`. It performs a no-unmap hollowing variant using `VirtualAllocEx`, `WriteProcessMemory`, PEB patching and `SetThreadContext`, then `ResumeThread`.
- Everything above was recovered statically; no Windows host or dynamic execution was required.

---

## Final Answers

Challenge 1 - Hidden flag:

```text
miit2026{r3v3rs3r_b3rj4y4_:3}
```

Challenge 2 - MITRE ATT&CK sub-technique:

```text
T1055.012 - Process Injection: Process Hollowing
Parent: T1055 - Process Injection
Tactics: Defense Evasion (TA0005), Privilege Escalation (TA0004)
```
