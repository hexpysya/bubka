---
title: "HTB-Hubbub"
date: 2026-01-21
draft: false
tags:
  - reversing
  - ghidra
  - avr

platform: 
---
**Description**  
In the cacophony of noise lies the potential for a clear message. (The flag format is HTB{SOME TEXT HERE}.)
{{< infobox platform="HackTheBox" difficulty="Easy" os="Linux" date="2026-01-20" >}}



## Initial Analysis
I identified the binary type to understand what I was dealing with
```bash
$ file Hubbub 
Hubbub: ELF 32-bit LSB executable, Atmel AVR 8-bit, version 1 (SYSV), statically linked, with debug_info, not stripped
```
Its' an `Atmel AVR 8-bit` executable, commonly used in Arduino microcontrollers

Running `strings` on the binary revealed references to Arduino library functions like `tone()` and `delay()`. This immediately suggested the program generates audio output, possibly encoding a hidden message.

## Reverse
I'm opened it in Ghidra and found a main logic in function (`FUN_code_0002f4`)
i understood that ... and than ...
![alt text](image.png)
Inside main, I observed a repetitive pattern of function calls. By correlating the assembly instructions with the strings found earlier, I identified two key functions:
### The Pattern Emerges
`tone (FUN_code_0001b5)`: generates sound at specific frequencies

`delay (FUN_code_000098)`: creates pauses in execution

Looking closely at the arguments passed to delay(), I noticed two distinct constants being loaded into registers:
\- `0x012c (300 ms)`   
\- `0x0158 (600 ms)`  

Given the audio context, i hypothesized this was Morse Code.

\- The shorter duration 0x2c represents a **Dot (.)**  
\- The longer duration 0x58 (exactly double the short duration) represents a **Dash (-)**

## Decoding
I extracted the decompiled C code from Ghidra into a text file named dec.txt and wrote a Python script to parse it
```python
with open("dec.txt", 'r', encoding='utf-8') as f:
    lines = f.readlines()

morse_code = ""

for l in lines:
    if "0x2c" in l:
        morse_code += "."
    elif "0x58" in l:
        morse_code += "-"
    
    if "0xe8" in l:
        morse_code += " "
    elif "0xd0" in l:
        morse_code += " / " 

print(morse_code)

MORSE_dict = {
    '..-.': 'F', '-..-': 'X', '.--.': 'P', '-': 'T', '..---': '2',
    '....-': '4', '-----': '0', '--...': '7', '...-': 'V', '-.-.': 'C',
    '.': 'E', '.---': 'J', '---': 'O', '-.-': 'K', '----.': '9',
    '..': 'I', '.-..': 'L', '.....': '5', '...--': '3', '-.--': 'Y',
    '-....': '6', '.--': 'W', '....': 'H', '-.': 'N', '.-.': 'R',
    '-...': 'B', '---..': '8', '--..': 'Z', '-..': 'D', '--.-': 'Q',
    '--.': 'G', '--': 'M', '..-': 'U', '.-': 'A', '...': 'S', '.----': '1'
}

def morse_to_text(stri):
    res = ""
    stri = stri.split(" ")

    for s in stri:
        if s == "/":
            res += " "   
        else: 
            res += MORSE_dict[s]
    return res

print(morse_to_text(morse_code))
```
Running the script:
```bash
$ python3 dec.py
.... - -... / .- / -. --- .. ... -.-- / -... ..- --.. --.. . .-. / -.-. --- -- -- .- -. -.. ... / .- - - . -. - .. --- -.
HTB A NOISY BUZZER COMMANDS ATTENTION
```
the flag:
```
HTB{A NOISY BUZZER COMMANDS ATTENTION}
```