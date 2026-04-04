# Detonator - Hack@10 CTF Write Up

<img width="493" height="511" alt="image" src="https://github.com/user-attachments/assets/09f22891-3354-430d-8cfe-cbcb3bb1814a" />

## Challenge Info

- Category: Reverse Engineering
- File: `detonator.exe`
- Description: `In malware analysis, you can either statically analyze the assembly codes directly, or you can create a snapshot of your sandbox and detonate it inside.`
- Author: Jebat

## Flag

`HACK10{be029cf0e9f2eaa5f80489343630befb}`

---

### Initial Triage

 ```text
└─$ file detonator.exe                                                       
detonator.exe: PE32+ executable (console) x86-64, for MS Windows, 19 sections
```

- File type: `PE32+ executable (console) x86-64`
- The binary was not stripped

Running `strings` immediately revealed a few suspicious artifacts:

```text
└─$ strings detonator.exe | grep 'HACK10'
C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt
HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}
Here is the flag: HACK10{
```

That strongly suggested the visible flag was fake and the real logic was elsewhere.

---

### Main Static Analysis

<img width="545" height="326" alt="image" src="https://github.com/user-attachments/assets/6aed9167-abf5-4f3e-83ad-223b2ce832c5" />

`check_flag()` function can be seen just from main

---

### Understand the logic

<img width="886" height="327" alt="image" src="https://github.com/user-attachments/assets/11a25f0c-7d02-4233-b327-d82ba5efef9e" />

Inside `check_flag()`:

1. A `std::string` is created from the hardcoded path:

```text
C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt
```
The flag was obviously fake as it says.

2. The program calls `_stat64i32` on the hardcoded path.

3. If the file does not exist, it prints:

```text
File not found. Keep looking...
```

4. If the file exists, it prints:

```text
Here is the flag: HACK10{
```

and then appends the return value of its internal `md5()` function, followed by `}`

This mean it hashes the **path string itself**

---

## Recovering the Flag

Compute the MD5 of that exact string:

```bash
printf '%s' 'C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt' | md5sum
```

Result:

```text
be029cf0e9f2eaa5f80489343630befb
```

## Flag

```text
HACK10{be029cf0e9f2eaa5f80489343630befb}
```
