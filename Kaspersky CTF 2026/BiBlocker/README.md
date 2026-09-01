# BiBlocker - Kaspersky{CTF} Write Up

Difficulty: Hard

Category: Reverse Engineering

---
Description:

You're asking why BitbLocker uses TPM? Well, you only need to understand the power contained in those three letters: 

T - Trusted, P - Potato, M - Module

Author: Kaspersky

---
- Files: `biblocker_5d741069dd2afdda`

## Initial Triage

```
└─$ file ./biblocker_5d741069dd2afdda
./biblocker_5d741069dd2afdda: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[xxHash]=baabe8880d2aa181, not stripped
```
- ELF 64-bit PIE executable
- not stripped

```
└─$ strings -a ./biblocker_5d741069dd2afdda
```

Useful strings:

```text
...
squashfs
invalid password!
blablablablablab
/mnt/biblocker
```

## Main Function

<img width="792" height="549" alt="Screenshot 2026-08-31 162229" src="https://github.com/user-attachments/assets/21a24811-d677-42d3-8b64-dae9e0b0b6b9" />

`target_key` is a static constant in `.data`. Jump to `target_key` to read the 16 bytes

```
d6 b9 ac 3e 97 3f 59 7a b2 91 bd 21 cb 0d b6 8a
```

```
target_key = d6b9ac3e973f597ab291bd21cb0db68a
```

## Password Derivation

Open `derive_decrypt_key` function in the decompiler

<img width="594" height="215" alt="Screenshot 2026-08-31 211226" src="https://github.com/user-attachments/assets/10b9bebe-c8ec-440e-af12-902f4a10b6bf" />

So `main` checks:

```
derived_key ^ secret_fault_bytes == target_key
```

therefore:

```
derived_key = target_key ^ secret_fault_bytes
```

However, we don't know where `secret_fault_bytes` come from.

## The SIGSEGV Trick

`0xa524f867b50` and `0xa524f867b58` are fake/unmapped addresses. Reading them raises Segmentation Fault (SIGSEGV). The binary installs a custom handler (`segsegv_handler`) through a *runtime-resolved* `sigaction` (it walks its own ELF dynamic section instead of linking against libc directly).

<img width="591" height="594" alt="image" src="https://github.com/user-attachments/assets/162a36c7-5860-4562-b50a-b539117f5284" />

- Reads the fault address from the saved `ucontext`.
- Computes a custom CRC (`sm_crc32_3`) over that address.
- Uses the CRC to choose one of two encrypted constants.
- Runs an XTEA-like decrypt keyed by the fault address.
- Writes the decrypted qword into the saved `RAX` slot in the context.
- Advances the saved `RIP`, so execution resumes after the faulting `mov`.

## Recovering the Fault Bytes

This is the one step where its hard to do a live debugger. To even reach the two fake reads at runtime the binary must:

- run as root (`getuid() == 0` — hence the `sudo` usage string)
- not be traced: `check_tracer` → `get_tracer_pid` reads `/proc/self/status`, and the SIGSEGV handler is only installed when no debugger is attached. In practice, under GDB the process simply crashes with SIGSEGV and the `segsegv_handler` breakpoint is never reached.

- so to avoid making my head spinning even more, we'll use Claude (saviour) for scripting

```bash
python3 - <<'PY'
from struct import pack, unpack

MASK64 = 0xffffffffffffffff
MASK32 = 0xffffffff

TARGET_KEY = bytes.fromhex("d6b9ac3e973f597ab291bd21cb0db68a")
FAULT_ADDRS = [0xa524f867b50, 0xa524f867b58]

def sm_crc32_3(data):
    eax = 0xc22792f8
    for b in data:
        eax = (eax ^ b) & MASK32
        for _ in range(8):
            eax = (((-(eax & 1)) & 0xf6abf146) ^ (eax >> 1)) & MASK32
    return (~eax) & MASK32

def synthesize_qword(fault_addr):
    crc = sm_crc32_3(pack("<Q", fault_addr))

    key0 = (0x00b7da05a379a0a4 * fault_addr) & MASK64
    key1 = (0x00b015462cbd5972 * fault_addr) & MASK64
    xtea_key = list(unpack("<4I", pack("<QQ", key0, key1)))

    if crc == 0x21f54549:
        encrypted = 0xb08863ae1cf8a11d
    elif crc == 0xa843a070:
        encrypted = 0x09692350899d4f57
    else:
        raise ValueError(f"unexpected crc: {crc:#x}")

    v0, v1 = unpack("<2I", pack("<Q", encrypted))

    delta = 0xb80c4716
    total = (delta << 5) & MASK32

    for _ in range(32):
        t = ((((v0 << 4) & MASK32) + xtea_key[2]) & MASK32) ^ ((v0 + total) & MASK32) ^ (((v0 >> 5) + xtea_key[3]) & MASK32)
        v1 = (v1 - t) & MASK32

        t = ((((v1 << 4) & MASK32) + xtea_key[0]) & MASK32) ^ ((v1 + total) & MASK32) ^ (((v1 >> 5) + xtea_key[1]) & MASK32)
        v0 = (v0 - t) & MASK32

        total = (total - delta) & MASK32

    out = pack("<2I", v0, v1)
    print(f"fault_addr={fault_addr:#x} crc={crc:#x} qword={out.hex()}")
    return out

secret_fault_bytes = b"".join(synthesize_qword(addr) for addr in FAULT_ADDRS)
aes_key = bytes(a ^ b for a, b in zip(TARGET_KEY, secret_fault_bytes))

print(f"secret_fault_bytes = {secret_fault_bytes.hex()}")
print(f"aes_key            = {aes_key.hex()}")
PY
```
 I found a way to do it dynamically later after CTF :D (patch out the root/anti-debug checks, 
 or hide the tracer, then break on `segsegv_handler` and read `RAX` after each fault), but the fastest way to perform anti-debug-proof route is to reimplement the handler offline in Python:

 Python expected output:

```
fault_addr=0xa524f867b50 crc=0x21f54549 qword=bcc18b954063597b
fault_addr=0xa524f867b58 crc=0xa843a070 qword=10196fdd8e16d405
secret_fault_bytes = bcc18b954063597b10196fdd8e16d405
aes_key            = 6a7827abd75c0001a288d2fc451b628f
```

## Recover and Decrypting Embedded File

carve the encrypted blob from the binary. Use the symbol values to compute offset and size:

```text
offset = fs_img_begin file offset
size   = fs_img_end - fs_img_begin
```

Decrypt with AES-128-CBC:

```bash
dd if=./biblocker_5d741069dd2afdda of=fs.enc bs=1 skip=<offset> count=<size> status=none
openssl enc -d -aes-128-cbc -K 6a7827abd75c0001a288d2fc451b628f -iv 626c61626c61626c61626c61626c6162 -in fs.enc -out fs.squashfs
```

Extract the SquashFS:

<img width="814" height="111" alt="image" src="https://github.com/user-attachments/assets/c7dc7ba0-f433-4670-be82-9c5fed2f4770" />

## Flag

```text
kaspersky{s1gn4l5_pr0v1d3d_tPm_k1nd4_sus}
```
