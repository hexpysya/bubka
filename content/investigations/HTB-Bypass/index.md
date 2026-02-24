---
title: "HTB-Bypass"
date: 2026-01-28
draft: false
summary: " "
tags:
  - Reverse Engineering
  - Windows
  - .NET
  - dnspy
platform: reversing
---

{{< infobox platform="HackTheBox" difficulty="Easy" os="Windows" date="2026-01-28" >}}

**Description:**  
The Client is in full control. Bypass the authentication and read the key to get the Flag.

## <span style="color:red">initial analysis</span>
```bash
$  file Bypass.exe 
Bypass.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 Mono/.Net assembly, 3 sections
```

```powershell
C:\Users\f\Desktop>Bypass.exe
Enter a username: hi
Enter a password: hi
Wrong username and/or password
Enter a username: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Enter a password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Wrong username and/or password
Enter a username:
```

## reversing with dnspy
Код отримує доступ до вбудованого ресурсу з іменем `"0"`. ці дані передаються у *метод 3 класу 7*
![alt text](image.png)


![alt text](image-1.png)
it's AES-CBC decrytprion
where key is 32 bytes and iv is 16 byte
```c#
byte[] array = new byte[rijndaelManaged.Key.Length];
byte[] array2 = new byte[rijndaelManaged.IV.Length];
memoryStream.Read(array, 0, array.Length);
memoryStream.Read(array2, 0, array2.Length);
```


## solution
```python 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open("0.bin", "rb") as f:
    d = f.read()

k_s = 32 
iv_s = 16   

key = d[:k_s]
iv = d[k_s:k_s + iv_s]
enc_d= d[k_s + iv_s:]

c = AES.new(key, AES.MODE_CBC, iv)
dec_d = c.decrypt(enc_d)

with open("re.bin", 'wb') as f:
    f.write(dec_d)

print("re.bin\ndone")
```

```bash
$ python3 dec.py 
re.bin
done
                                                                                                
$ cat re.bin 
<Wrong username and/or password$Enter a username: $Enter a password: |ThisIsAReallyReallySecureKeyButYouCanReadItFromSourceSoItSucks:Please Enter the secret Key: 4Nice here is the Flag:HTB{}Wrong Key▒SuP3rC00lFL4g�This executable has been obfuscated by using RustemSoft Skater .NET Obfuscator Demo version. Please visit RustemSoft.com for more information.�This executable has been obfuscated by using RustemSoft Skater .NET Obfuscator Demo version. Please visit RustemSoft.com for more information.�This executable has been obfuscated by using RustemSoft Skater .NET Obfuscator Demo version. Please visit RustemSoft.com for more information.�This executable has been obfuscated by using RustemSoft Skater .NET Obfuscator Demo version. Please visit RustemSoft.com for more information. 
```
we see `HTB{}Wrong Key▒SuP3rC00lFL4g` so flag is `HTB{SuP3rC00lFL4g}`

