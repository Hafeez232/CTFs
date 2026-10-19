# AwasmSafe - Kaspersky{CTF} Write Up

Difficulty: Hard

Category: Reverse Engineering

---
Description:

```text
We're ordered a new secret-keeping machine! The whole safe-machine, believe it!
A massive terminal just to keep confidential info secure. They say it has
highest-grade protection made just for us! Amazing!
```

Author: -

---
Files:
```text
awasmsafe_b70b40963c94d668.AppImage
awasmsafe_748a67e5e2e3f002.exe
```

## Initial Triage

```
└─$ file awasmsafe_b70b40963c94d668.AppImage awasmsafe_748a67e5e2e3f002.exe
awasmsafe_b70b40963c94d668.AppImage: ELF 64-bit LSB executable, x86-64, stripped
awasmsafe_748a67e5e2e3f002.exe:      PE32 executable (GUI) Intel 80386, Nullsoft Installer self-extracting archive
```
Observed
```text
awasmsafe_b70b40963c94d668.AppImage
```
- ELF 64-bit LSB executable
- stripped

```text
awasmsafe_748a67e5e2e3f002.exe
```
- PE32 executable
- NSIS installer

Since the Windows binary is an NSIS installer, we can:

```bash
└─$ 7z l awasmsafe_748a67e5e2e3f002.exe
```
<img width="462" height="136" alt="image" src="https://github.com/user-attachments/assets/d029933e-df59-4e0a-94ad-06a2ee3addff" />

The Linux AppImage contains a SquashFS payload

```bash
└─$ binwalk awasmsafe_b70b40963c94d668.AppImage
```

<img width="688" height="187" alt="image" src="https://github.com/user-attachments/assets/26ab886c-0884-4ab1-852a-805ef0a6869e" />

So both packages are just containers and the AppImage is easier to extract.

## 2. Extract The Electron App

Extract the AppImage executable:

```bash
└─$ ./awasmsafe_b70b40963c94d668.AppImage --appimage-extract
```

Out of all the file, the most outstanding is the .asar since it is Electron's application archive format.

<img width="569" height="308" alt="image" src="https://github.com/user-attachments/assets/5fd280cf-b429-4eb8-a077-53be74f7148d" />

Check it:

```bash
└─$ file squashfs-root/resources/app.asar
└─$ strings -a -n 8 squashfs-root/resources/app.asar | head
```

Observed:

```text
Electron ASAR archive, header length: 757 bytes
```

The ASAR header is visible in strings and lists only three files:

```json
{
  "index.js": { "size": 2065, "offset": "0" },
  "package.json": { "size": 145, "offset": "2065" },
  "safe.html": { "size": 53552, "offset": "2210" }
}
```
ASAR file data begins after the header and here it starts at `776`, or `0x308`
https://github.com/electron/asar#format
```
JSON header length       = 757 bytes
padded header area       = 768 bytes
initial 8-byte fields    = 8 bytes
file data begins at      = 8 + 768 = 776
```

Carve the files manually:

```bash
mkdir -p asar_extract
dd if=squashfs-root/resources/app.asar of=asar_extract/index.js bs=1 skip=776 count=2065 status=none
dd if=squashfs-root/resources/app.asar of=asar_extract/package.json bs=1 skip=2841 count=145 status=none
dd if=squashfs-root/resources/app.asar of=asar_extract/safe.html bs=1 skip=2986 count=53552 status=none
```

<img width="444" height="128" alt="image" src="https://github.com/user-attachments/assets/43b166ee-28de-40d0-8667-1418f5cc65b0" />

The offsets are:

```text
index.js:     776 + 0
package.json: 776 + 2065 = 2841
safe.html:    776 + 2210 = 2986
```

## 3. Understand the Electron Launcher

Inside index.js. is obfuscated with XOR `0x17`. The decoder is:

```js
a => {
  let s = String();
  for (let i = 0; i < a.length; i++)
    s += String.fromCharCode(a[i] ^ 23);
  return s;
}
```
