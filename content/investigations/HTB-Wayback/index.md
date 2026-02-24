---
title: "HTB-Wayback"
date: 2026-01-29
draft: false
summary: " "
tags:
  - Reverse Engineering
  - Linux
  - ida
  - ELF
  - srand
platform: reversing
---

{{< infobox 
    difficulty="Medium" 
    os="Linux" 
    date="2026-01-29" >}}

**Description:**  
A man named Michael Tanz bought 30 bitcoin in 2013 and stored it in his hardware wallet. He set the password for his hardware wallet through a password generator named "V1". He remembers that his password is 20 characters long, and consisted of only alphanumeric characters and symbols. Michael however is not exactly sure of the date he generated the password - he knows it was between the 10th and the 11th of December 2013. Can you crack the password and help him recover his bitcoin ?

## <span style="color:red">initial analysis</span>
Отримали два файли. 
```bash
$ file *             
decrypt.py: Python script, ASCII text executable
V1:         ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7d0ef4ad0fae598a68cba943d3a34c96ad6461d2, for GNU/Linux 4.4.0, not stripped
```

скрипт `decrypt.py` розшифровує дані з використанням ключа, ключ потрібно дізнатися.
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def decrypt_message(encrypted_message, key):
    try:
        key = key.ljust(32, b'\x00')
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
        return decrypted_message.decode()
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None

if __name__ == "__main__":
    encrypted_message = bytes.fromhex('ad24426047b0ffb03b679773664838462a6f00bdcaf0589dd1748e9ed5c568601edc87d974894f9dd9b98cc35535145c494eb0af84c8f78d440a033c91c7de62d506d8cabdc2a10138b95139bbe60e89')
    key = input("Please input your key : ")
    decrypted_message = decrypt_message(encrypted_message, key.encode())
    if decrypted_message:
        print(f"Decrypted message: {decrypted_message}")
    else:
        print("Decryption failed or no valid message found.")
```

by running executable nothing happend:
```bash
$ ./V1 
Enter len (max 50):
Include sym? (yes/no):yes
Include sym? (yes/no):
Include num? (yes/no):
Generated password: 

$ ./V1
Enter len (max 50):
Include sym? (yes/no):no
Include sym? (yes/no):
Include num? (yes/no):
Generated password: 
```

## reversing with ida
`main` func do nothing interested. from functions listing i saw unused `generate_password()` function. so, i started analysis it

alphabet for key is `"abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "@#$%^&*_+" + "0123456789"`:
```c
qmemcpy(v14, "abcdefghijklmnopqrstuvwxyz", 26);
// ...[snip]...
std::string::_M_append(&v14, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);
// ...[snip]...
std::string::_M_append(&v14, "!@#$%^&*_+", 10);
// ...[snip]...
std::string::_M_append(&v14, "0123456789", 10);
```

cryptography using time-based seeds for password generation, whihc is *insecure*. its becomes feasible to *brute-force* 
```c
v6 = localtime(&timer);
srand(
100000000 * (v6->tm_mon + 1)
+ 1410065408 * (v6->tm_year + 1900)
+ 10000 * v6->tm_hour
+ v6->tm_sec
+ 100 * v6->tm_min
+ 1000000 * v6->tm_mday);
```

the function then generates password character by character. for `a2` iterations (password length), it:
1. picks random char from alphabet using `rand() % charset_length`
2. appends it to the output string
```c
if ( a2 > 0 )
{
  for ( i = 0; i != a2; ++i )
  {
    v9 = *(v14 + rand() % v15);  // pick random char
    // ... string manipulation to append v9 to result ...
    *(*a1 + v10) = v9;           // add char to password
    a1[1] = v11;                          // update length
    *(*a1 + v10 + 1) = 0;        // null terminator
  }
}
```

## exploitation strategy
since password generation is deterministic (same timestamp = same password), i can:  
\- iterate through all timestamps in dec 10-11, 2013  
\- for each timestamp, calculate the seed value  
\- generate 20-char password using C's `rand()` with that seed  
\- attempt AES decryption with generated password  

recreated the seed calculation and password generation logic in python using `ctypes` to call C's `srand()`/`rand()`:
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import ctypes
from datetime import datetime, timedelta

def decrypt_message(encrypted_message, key):
    try:
        key = key.ljust(32, b'\x00')
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
        return decrypted_message.decode()
    except Exception as e:
        return None

def pwd_gen(length, seed_value):
    charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "!@#$%^&*_+" + "0123456789"
        
    libc = ctypes.CDLL(None)
    libc.srand(seed_value)
    
    pwd = ""
    for _ in range(length):
        rand_val = libc.rand()
        pwd += charset[rand_val % len(charset)]
    
    return pwd

def seed_gen(year, month, day, hour, minute, second):
    return (100000000 * (month + 1) + 
            1410065408 * (year + 1900) + 
            10000 * hour + 
            second + 
            100 * minute + 
            1000000 * day)


encrypted_message = bytes.fromhex('ad24426047b0ffb03b679773664838462a6f00bdcaf0589dd1748e9ed5c568601edc87d974894f9dd9b98cc35535145c494eb0af84c8f78d440a033c91c7de62d506d8cabdc2a10138b95139bbe60e89')

start = datetime(2013, 12, 10, 0, 0, 0)
end = datetime(2013, 12, 11, 23, 59, 59)

c = start
count = 0

while c <= end:
    seed = seed_gen(
        c.year - 1900,
        c.month - 1,
        c.day,
        c.hour,
        c.minute,
        c.second
    )
    
    pwd = pwd_gen(20, seed)
    
    d = decrypt_message(encrypted_message, pwd.encode())
    
    if d and d.isprintable():
        print(f"Password: {pwd}")
        print(f"Decrypted message: {d}")
        break
    
    count += 1
    if count % 10000 == 0:
        print(f"Checked {count} timestamps...")
    
    c += timedelta(seconds=1)
```

```bash
$ python3 dec.py
Checked 10000 timestamps...
Checked 20000 timestamps...
Checked 30000 timestamps...
Checked 40000 timestamps...
Checked 50000 timestamps...
Checked 60000 timestamps...
Checked 70000 timestamps...
Checked 80000 timestamps...
Checked 90000 timestamps...
Checked 100000 timestamps...
Checked 110000 timestamps...
Checked 120000 timestamps...
Checked 130000 timestamps...
Password: eWXtk*Oe%j5cof7Od08G
Decrypted message: d 30 Bitcoins! , HTB{T1me_0n_the_B1t5_1386784885}
```