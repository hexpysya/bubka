---
title: "HTB-RAuth"
date: 2026-01-22
draft: false
tags:
  - Reverse Engineering
  - Linux
  - ELF
  - ida
  - rust
  - rust-gdb
  - salsa20
platform: reversing
---

{{< infobox platform="HackTheBox" difficulty="Easy" os="Linux" date="2026-01-22" >}}
Description:  
My implementation of authentication mechanisms in C turned out to be failures. But my implementation in Rust is unbreakable. Can you retrieve my password?



## Initial Analysis
Rauth це ELF binary під архітерутур x86-64.  
```bash
$ file rauth                                                    
rauth: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fc374b8206147fac9067599050989191b39eefcf, with debug_info, not stripped
```
При запуску нас просять вести пароль. 
```bash
$ ./rauth      
Welcome to secure login portal!
Enter the password to access the system: 
aaaaaaaaaaa
You entered a wrong password!
```
При введені невірного пароля виводиться повідомлення "You entered a wrong password!". Тому найпершою ідеєю в мене було відкрити цей файл в дизассемблері IDA та подивитися яка перевірка призводить до цієї гілки.

## Dissasembling
Розгалуження виконання робить ці рядки.  
Йде перевірка чи `bl = 0`, якщо так то відбуєвать стрибок `loc_6992` та виконується `print("You entered a wrong password!")`
![alt text](image.png)
![alt text](image-1.png)


## Debagging
Вирішив змінити хід виконання, змінивши в дебагері значення `rbx` 
```
(gdb) b *0x55555540683e
Breakpoint 2 at 0x55555540683e
(gdb) c
Continuing.
Welcome to secure login portal!
Breakpoint 2, 0x000055555540683e in rauth::main ()
(gdb) set $rbx = 1
(gdb) c
Continuing.
Successfully Authenticated
(gdb) "HTB{F4k3_f74g_4_t3s7ing}"
[Inferior 1 (process 24204) exited normally]
```
Бачимо що ми отримали fake flag.

## salsa20
Я помітив використання криптографічного алгоритму `Salsa20`.  
```
(gdb) info func salsa
All functions matching regular expression "salsa":

Non-debugging symbols:
0x00005555554056b0  salsa20::core::Core<R>::apply_keystream
0x0000555555405900  salsa20::core::Core<R>::new
0x00005555554059a0  salsa20::core::Core<R>::rounds
0x0000555555405d10  <salsa20::salsa::Salsa<R> as cipher::stream::StreamCipher>::try_apply_keystream
```
`salsa20::core::Core<R>::new` - constructor that typically takes a 256-bit (32-byte) key and a 64-bit (8-byte) nonce (IV)  
`salsa20::core::Core<R>::apply_keystream` - 

Вирішви подивитися які аргументи передаються в `Salsa20::new`
```
(gdb) b salsa20::core::Core<R>::new
Breakpoint 2 at 0x555555405900
(gdb) b salsa20::core::Core<R>::apply_keystream
Breakpoint 3 at 0x5555554056b0
(gdb) start
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Temporary breakpoint 4 at 0x555555406bd0
Starting program: /home/kali/Desktop/challanges/RAuth/rauth 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".

Temporary breakpoint 4, 0x0000555555406bd0 in main ()
(gdb) c
Continuing.
Welcome to secure login portal!
Enter the password to access the system: 
aaaaa

Breakpoint 2, 0x0000555555405900 in salsa20::core::Core<R>::new ()
(gdb) i r
rax            0x55555564fe20      93824993263136
rbx            0x555555408530      93824990872880
rcx            0x55555564fe20      93824993263136
rdx            0x7fffffffdaa0      140737488345760
rsi            0x7fffffffda70      140737488345712
rdi            0x7fffffffd9e0      140737488345568
rbp            0x1                 0x1
rsp            0x7fffffffd9d8      0x7fffffffd9d8
r8             0x7ffff7e15ac0      140737352129216
r9             0x30                48
r10            0x1                 1
r11            0x0                 0
r12            0x0                 0
r13            0x555555439e28      93824991075880
r14            0x555555649090      93824993235088
r15            0x55555564fe20      93824993263136
rip            0x555555405900      0x555555405900 <salsa20::core::Core<R>::new>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
fs_base        0x7ffff7f5d800      140737353472000
gs_base        0x0                 0
(gdb) x/s $rdi
0x7fffffffd9e0: " "
(gdb) x/s $rsi
0x7fffffffda70: "ef39f4f20e76e33bd25f4db338e81b10\001"
(gdb) x/s $rdx
0x7fffffffdaa0: "d4c270a3"
```
значення в rsi це 32byte ключ, в rdx це nonce
\- key: ef39f4f20e76e33bd25f4db338e81b10  
\- nonce: d4c270a3

Далі потрібно дізнатися де лежать зашифровані дані.
перед викликом функції `salsa20::core::Core<R>::new` я помітив як на стек кладеться 32 байтне значення з `xmmword_39CC0` та `xmmword_39CD0` 
![alt text](image-2.png)
```
.rodata:0000000000039CC0 xmmword_39CC0   xmmword 0F331CBA656F5D958D5A829A3B15F0505h
.rodata:0000000000039CD0 xmmword_39CD0   xmmword 0F91BAD626FB63EE372EC9DC9312A4324h
```
Спроба розшифрування
```python
$ python3                              
Python 3.13.11 (main, Dec  8 2025, 11:43:54) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.Cipher import Salsa20
>>> c = "0505 5fb1 a329 a8d5 58d9 f556 a6cb 31f3 2443 2a31 c99d ec72 e33e b66f 62ad 1bf9"
>>> Salsa20.new(key=b"ef39f4f20e76e33bd25f4db338e81b10", nonce=b"d4c270a3").decrypt(bytes.fromhex(c))
b'TheCrucialRustEngineering@2021;)'
```
І при спробі автентифікуватися на хості з цим паролем, ми отримуємо прапор
```bash
$ nc 94.237.63.176 32734
Welcome to secure login portal!
Enter the password to access the system: 
TheCrucialRustEngineering@2021;)
Successfully Authenticated
Flag: "HTB{I_Kn0w_h0w_t0_5al54}"
```
