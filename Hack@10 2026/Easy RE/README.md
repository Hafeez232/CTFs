# Easy RE - Hack@10 CTF Write Up

<img width="491" height="398" alt="image" src="https://github.com/user-attachments/assets/46bfdcf9-c4f2-47ef-9e39-50d1901be2db" />

## Challenge Info

- Category: Reverse Engineering
- File: `chall.apk`
- Description: `this is can be solve in 5min, warm up first`

## Flag

`hack10{t3r_ez_X0r}`

---

### 1. Decompile the outer APK

```bash
jadx -d chall_jadx chall.apk
```

The useful outer files are:

- `com.example.reforceapk.ProxyApplication`
- `com.example.reforceapk.MainActivity`
- `com.example.reforceapk.RefInvoke`

The important one is `ProxyApplication.java`.

`ProxyApplication.java` behavior:

1. Create private directories for payload extraction:

<img width="551" height="176" alt="image" src="https://github.com/user-attachments/assets/51dac2c2-e88f-4dfd-9b89-6819f6404150" />

2. If payload.apk does not already exist:

byte[] dexdata = readDexFileFromApk();
splitPayLoadFromDex(dexdata);

3. Replace the app class loader with a DexClassLoader that loads the hidden payload APK:

<img width="859" height="50" alt="image" src="https://github.com/user-attachments/assets/c4ff3a85-8a91-4685-993d-8abec9d66942" />

### Payload extraction details

The extraction happens in splitPayLoadFromDex(byte[] apkdata).

It shows the app is only a loader:

- it reads `classes.dex`
- extracts data appended at the end
- XORs it with `0xff`
- writes a hidden `payload.apk`
- loads that APK with `DexClassLoader`

So the real challenge is inside the hidden payload APK, not the outer APK.

---

### 2. Extract the hidden payload APK

The payload is appended to the outer `classes.dex`.

From `ProxyApplication.splitPayLoadFromDex()`:

- last 4 bytes of `classes.dex` = payload length
- payload bytes are extracted from the end
- each payload byte is XORed with `0xff`

Recover it with a short script:

```python
from pathlib import Path

data = Path("classes.dex").read_bytes()
size = int.from_bytes(data[-4:], "big", signed=True)
payload = bytes(b ^ 0xff for b in data[-4-size:-4])
Path("payload.apk").write_bytes(payload)
```

---

### 3. Decompile the payload APK

Run `jadx` again:

```bash
jadx -d payload_jadx payload.apk
```

Now the real files appear:

- `com.example.myapk.MainActivity`
- `com.example.myapk.ImageEncryptor`

---

### 4. Bypass the login

In `com.example.myapk.MainActivity.performLogin()`:

<img width="862" height="239" alt="image" src="https://github.com/user-attachments/assets/c63196df-2284-4049-876d-de54db59664d" />

Use:

- username: empty
- password: empty

This works because:

- the “same username/password” check is skipped when both are empty
- `md5("") == md5("")`

---

### 6. Run it in an Android emulator

Stucked here quite some time because the file was encrypted with a different 32-byte key.

Then thought of using an online Android emulator to run the APK to fetch the .bkp file directly 

Since the login check already showed that no username and password were needed, I just:
- left username empty
- left password empty
- pressed Login

<img width="721" height="714" alt="Screenshot 2026-03-28 004511" src="https://github.com/user-attachments/assets/58a5ff0c-a5c8-4803-b6af-5271093437db" />

After that, the app generated new `background.bkp` and showed the hint popup.

Pulled the generated file from the emulator and the file is the encrypted version of the wallpaper loaded from `assets/background.txt`.

---

### 7. Recover image from `background.txt`

Inside `MainActivity`, the app reads `background.txt`, strips the wrapper:

```text
url(data:image/jpeg;base64,
```

and also removes the final:
```text
)
```

After that, the remaining content is just base64 for the original wallpaper image.

Quick way to recover is using CyberChef

<img width="1693" height="792" alt="Screenshot 2026-04-03 190812" src="https://github.com/user-attachments/assets/6a67aba4-b57a-43ca-9d84-4088a41afac6" />

### 8. Recover the runtime XOR key

The app encrypts the wallpaper bytes and writes them as `background.bkp`.

So:

```text
key = runtime_background.bkp XOR original_wallpaper
```

Using the pulled file and the original wallpaper from the APK:

```python
orig = open("background.jpg", "rb").read()
run = open("background.bkp", "rb").read()
key = bytes(a ^ b for a, b in zip(orig, run))
print(key[:32].hex())
```

This gives the repeating 32-byte runtime key:

```text
5b8af99d4c742519ec0fbe724e697daff19246ec9c7a54d03d6fca7de133ea92
```

---

### 9. Recover the packaged key

The APK also ships `assets/background.bkp`.

Comparing:

- pulled runtime `background.bkp`
- packaged `assets/background.bkp`

gives a repeating 32-byte delta:

```text
bc49a355cad8fee7c8c0c50826e14101d6279093bc49a355cad8fee7c8c0c508
```

So:

```text
packaged_key = runtime_key XOR delta
````

```text
5b XOR bc = e7
8a XOR 49 = c3
f9 XOR a3 = 5a
9d XOR 55 = c8
...
````

Result:

```text
e7c35ac886acdbfe24cf7b7a68883cae27b5d67f2033f785f7b7349a29f32f9a
```

---

### 10. Decrypt the packaged `background.bkp`

Use the recovered packaged key:

```python
pkg = open("apk_background.bkp", "rb").read()
key = bytes.fromhex("e7c35ac886acdbfe24cf7b7a68883cae27b5d67f2033f785f7b7349a29f32f9a")
dec = bytes(b ^ key[i % 32] for i, b in enumerate(pkg))
open("flag.jpg", "wb").write(dec)
```

The result is a valid JPEG.

![flag](https://github.com/user-attachments/assets/6d96766a-8f58-4308-a4e8-04df1ea39d03)

---

## Final Flag

```text
hack10{t3r_ez_X0r}
```
