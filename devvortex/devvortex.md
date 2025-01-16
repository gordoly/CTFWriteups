## Writeup for “Devvortex” from HackTheBox


First a nmap scan was performed on the target machine to see which ports are available.


The command `nmap -sC -sV <Target_IP>` was used, which produced this output:

```
Nmap scan report for 10.10.11.242
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


After the nmap scan, it was revealed that an ssh server and a http server could be found on ports 22 and 80 respectively. Furthermore, the domain name devvortex.htb was revealed and was added to /etc/hosts. 


On port 80, a http server running on nginx was found. The web server was then visited. After finding nothing interesting on the webpage, fuzzing through subdomains was then attempted using wfuzz using the top 1 million subdomains list in SecLists. The wfuzz command used was: 


```wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://devvortex.htb" -H "Host: FUZZ.devvortex.htb" --hw 10```


Soon after, the subdomain “dev” was found:


```
Target: http://devvortex.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                             
=====================================================================

000000019:   200        501 L    1581 W     23221 Ch    "dev" 
```


 After dev.devvortex.htb was added to /etc/hosts and the site was visited, the next step that was taken was to fuzz for other directories or pages. Again wfuzz was used and the command used was:


```wfuzz -w /usr/share/dirb/wordlists/common.txt -h “http://dev.devvortex.htb/FUZZ” --hc 404```


The above command produced this output:


```
Target: http://dev.devvortex.htb/FUZZ
Total requests: 17770

=====================================================================
ID           Response   Lines    Word       Chars       Payload                             
=====================================================================

000000007:   301        7 L      12 W       178 Ch      "cache"                             
000000008:   301        7 L      12 W       178 Ch      "media"                             
000000006:   301        7 L      12 W       178 Ch      "templates"                         
000000004:   301        7 L      12 W       178 Ch      "includes"                          
000000018:   301        7 L      12 W       178 Ch      "components"                        
000000002:   301        7 L      12 W       178 Ch      "images"                            
000000011:   301        7 L      12 W       178 Ch      "tmp"                               
000000016:   301        7 L      12 W       178 Ch      "plugins"                           
000000005:   301        7 L      12 W       178 Ch      "modules"                           
000000023:   301        7 L      12 W       178 Ch      "libraries"                         
000000010:   301        7 L      12 W       178 Ch      "language"                          
000000017:   301        7 L      12 W       178 Ch      "administrator"                     
000000077:   301        7 L      12 W       178 Ch      "api"                               
000000127:   200        501 L    1581 W     23221 Ch    "home"                              
000000653:   301        7 L      12 W       178 Ch      "layouts"                           
000003809:   200        501 L    1581 W     23221 Ch    "http://dev.devvortex.htb/"         
000010185:   301        7 L      12 W       178 Ch      "cli"
```


Interesting directories that were identified included “administrator”, “templates” and “api”. Visiting the administrator page, a Joomla login page was found. The next step was to identify whether the Joomla CMS version used may be vulnerable. Earlier on the web page in the copyright section, the year 2020 could be found in the copyright suggesting that the Joomla version could be above 1.6.0 which was released in 2011. To find the Joomla CMS version on versions above 1.6.0 without being authenticated, visit http://dev.devvortex.htb/administrator/manifests/files/joomla.xml.


Upon visiting the XML page, the Joomla version 4.2.6 was identified. Next, public exploits for this Joomla version were researched on google, and an exploit by exploit-db was identified which affects versions 4.8.0 and earlier. The script appears to exploit an unauthenticated information disclosure exploit, whereupon sending get requests to two endpoints in /api would provide unauthenticated users with information on the users who could log into Joomla as well as configuration data on the Joomla site.


The exploit can be found at this site: https://www.exploit-db.com/exploits/51334


After downloading the exploit and running it using ruby, the usernames lewis and logan were revealed. Furthermore, it was also revealed that the server was running a MySql database on the backend and credentials for the database provided were lewis:P4ntherg0t1n5r3c0n##.


Given that passwords are commonly reused, these credentials were used to successfully login into the Joomla Control Panel as lewis who has administrator access. The next step involved searching for a place to upload a php reverse shell onto the machine. This was then found by visiting System > Templates. It could be seen that a Cassiopeia template was being used. The php files used by the template can be found. Next a php reverse shell script found in:


https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php


Was then copied and pasted onto the php files. It was found that error.php was a file that the user had permission to edit and the reverse shell was saved onto the file. A Netcat listener was then started on the port specified in the reverse shell. Keeping in mind that the templates directory was exposed, in order to trigger the reverse shell, the error.php page was visited at: http://dev.devvortex.htb/templates/cassiopedia/error.php.


This successfully triggered a reverse shell as the user www-data. Upon spawning an interactive bash shell using the command python3 -c "import pty; pty.spawn('/bin/bash')", the next step was to view the users that could be accessed in the machine in the /home directory. There only the logan user could be found. Remembering that logan was also revealed to have an account on the Joomla website, the mysql database was accessed as the user lewis, using the earlier identified credentials. After visiting the Joomla database and viewing the users in the sd4fg_users table, the hash of logan’s password could be found.


This hash was cracked using John the Ripper and the rockyou.txt file, an extensive file containing a list of common passwords. The command used was:
sudo john -w /usr/share/wordlists/rockyou.txt hash.txt (where hash.txt contains logan’s hash).


After some time logan’s password was revealed to be tequieromucho and was used to ssh into the box as logan.


The ssh connection was successful and the user.txt file could be read. The next step taken to escalate privileges involved running sudo -l to see which commands logan could run as the sudo user. It was found that the apport-cli program could be run as the superuser. Apport-cli is a program used to identify crashes in the system, generate crash reports, and also allow users to view such reports.


Subsequently, vulnerabilities for apport-cli were researched on google; a vulnerability was found at https://github.com/advisories/GHSA-qgrc-7333-5cgx. It appears that if less was used as a pager by apport-cli and was run as the super user, the user could escalate privileges. 


To escalate privileges, a crash is first triggered by running `sleep 60 &` in the background and killing this sleep process with a SIGSEGV signal to simulate a crash. Next a new report could be found to have been generated at /var/crash, which is the default directory for crash reports written by apport, documenting the SIGSEGV signal for the sleep command. Next apport-cli was run as the sudo user using the option to view the newly generated crash report. After selecting the “V” option to view to report, the less pager then appeared. After this, execute `!bash` to spawn a bash shell as the root user, hence successfully escalating privileges and allowing root.txt to be read.


Overall, I found the methods used to obtain foothold on the box to be relatively straightforward. This was because the box made use of a single public exploit and the vulnerable Joomla version was easily uncovered. However, I found escalating privileges to be quite challenging as the vulnerability of the apport-cli was not apparent at first. This taught me the importance of investigating the functionality of the potentially vulnerable binary and researching its public exploit.
