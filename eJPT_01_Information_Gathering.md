# Information Gathering

## Passive Recon

### Getting IP Addres by DNS Lookup

`host <url>`

### Getting Hidden Directories

Search for the `robots.txt`, `sitemap_index.xml` file it even can reveal the technology behind the website such as:

    - wordpress
    - Hidden directories
    - upload webs
    - plugins

### Getting Web Running Technologies

There are usefull mozilla add-ons such as `builtwith` or `wappalyzer`.
For CLI solutions its convenient to use `whatweb <url>` which tells the wordpress plugins that are being used.

### Getting Hidden Directories By Cloning the Website

Install `HTTrack` and then use it web UI to clon a website.

### Gathering Information Using Whois

For using CLI utility use `whois <domain>`, it will extract info from the domain if DNSSEC is enbaled such as:

    - Name of the person who registered the domain
    - Registrant Organization name
    - Registrant Province and country
    - Name servers
    - Network range
    - NetName

There are also some WHOIS public webs which will give the same results.

### Gathering Footprint With Netcraft

Netcraft is used to identify:

    - technologies
    - SSL certs info
    - SSL vulnerabilities
    - infraestructure of websites
    - hosting history
    - web tracker
    - Name server and other WHOIS info
    - IP delegation and IP blocks
    - Backend technologies

It can be accesed via website at `netcraft.com`.

### Gathering DNS Records

For getting and generate DNS records `dnsrecon -d <domain_name>` python script can be used.

It displays:

    - Name servers
    - A records -> IPV4 address
    - AAAA records -> IPV6 address
    - TXT records
    - MX records -> email server used for the org
    - IP address of thr actual site

For website UI `dnsdumpster.com` could be used as well. Which gives the feature for getting additional info about the asociated subdomains or records:

    - DNS servers and asociated IPs to it
    - MX records
    - subdomains
    - Graph of the infraestructure

### WAF Detection

For detecting any firewall or WAF the tool to be used could be `wafw00f <domain>`.
For trying and checking all WAF technologies use `wafw00f <domain> -a`.

### Subdomain Enumeration

The tool used for passive enumeration could be `sublist3r -e <search_engine_a>,<search_engine_b> -d <domain>`.
Use VPN becouse google has a ratelimit for making requests.
The available search engines are:

    - Baidu
    - Google
    - Yahoo
    - Bing
    - Ask
    - Netcraft
    - Visrutotal
    - ThreatCrowd
    - Search with SSL certificates
    - PassiveDNS

### Enumerating Subdomains With Google Hacking

Filters:

- `site:<domain>` -> this can lead to potentialy interesting subdomains asociated to the main domain.
- `site:<domain> inurl:<keyword>` -> this will show all the information related to the domain which has the keyword in the URL, interesting info here could be things such as admin panels by using admin as a kewyword
- `site:*.<domain>` -> this will search for subdomains related to the main domain
- `site:*.<domain> intitle:<keyword>` -> this will search for subdomains related to the main domain and show those which the title of the webpage is the same asa the given keyword
- `site:*.<domain> filetype:<filetype>` -> this will search for subdomains related to the main domain and show those which has files with the same as the filetype given
- intitle:index of -> this wil show webpages which have the indexing of the sources enabled (directory listing)
- `cache:<domain>` -> this will display the webs that is cached on google for the specified domain
- `inurl:auth_user_file.txt` -> this will display user info and configuration passwords
- `inurl:passwd.txt` -> this will display leaked passwd.txt files

[For more information Exploit-DB has a Google Hacking Database](https://www.exploit-db.com/google-hacking-database)

### Geting Emails

For this process there its a tools called `theHarvester`, some of the search engines require of an API key.

Query for domains `theHarvester -d <domain> -b <search_engine_a>,<search_engine_b>`
Query used for org names `theHarvester -d <org_name> -b <search_engine_a>,<search_engine_b>`

### Leaked Password Databases

`haveibeenpwned.com` when an email which credentials has been leaked this web displays the databridge in which was leaked.

## Active Scanning

Notes DNS records:

    - A: Resolves a hostname or domain to its associated IPv4
    - AAAA: Resolves a hostname or domain to its associated IPv6
    - NS: Reference to NameServer 
    - MX: Resolves a domain to a mail server
    - CNAME: Domain aliases
    - TXT: Test record
    - HINFO: Host information
    - SOA: Domain authority
    - SRV: Service records
    - PTR: Resolves IP to hostname

### DNS Zone Transfer Attack

Leads to copy the zone files from a DNS to the attacker DNS server.

- `dnsrecon -d <domain>`
- `dnsenum <domain>`
- `dig axfr @<nameserver> <domain>`
- `fierce -dns <domain>`

### Host Discovery With Nmap

Perform a host discovery using syn scan with `nmap` and `netdicsover`

- `sudo nmap -sn <network_address>`
- `netdiscover -i <interface> -r <network_address>`

### Port scanning with Nmap

Default TCP scans this arguments are given as OPTIONS and can be combined each them:

- nmap <ip>
- Scan without probing that the host is alive: `nmap -Pn <ip>`
- Specific ports: `nmap -p <port> <ip> or nmap -p <portA>,<portB> <ip>`
- Port ranges: `nmap -p<first_port_in_range>-<last_port_in_range>`
- Top 100 ports: `nmap -F <ip>`
- Increase verbosity: `nmap <ip> -vv`
- service detection: `nmap -sV <ip>`
- OS detection: `nmap -O <ip>`
- Script scan: `nmap -sC <ip>`

Type of scans based on the packet sent per second:

- IDS evasion limits the packets/seconds `nmap -T1 <ip>`
- More IDS evasion limits the packets/seconds `nmap -T2 <ip>`
- Normal packet/seconds send `nmap -T3 <ip>`
- Agressive scan speeds up the packets send `nmap -T4 [OPTIONS] <ip>`
- Insane scan speeds up the packets send used for faster networks `nmap -T4 <ip>`

UDP scan:

- `nmap -sU <ip>`

Output results:

- Default format `txt` file `nmap [OPTIONS] <ip> -oN <file_name>.txt`
- XML format `nmap [OPTIONS] <ip> -oN <file_name>.xml`

# Mapping Network

## Passive

### Sniffing

- `Wireshark`
- `TCPDump`

## Active

### Retrieving List of Live IPs

- `arp-scan -I <network_interface> -g <network_ip>\<network_type>`
- `nmap -sn <network_ip>\<network_type>`
- `fping -I <network_interface> -g <network_ip>\<network_type> -a 2>/dev/null`

# Services Enumeration

## Mail Servers SMTP 25/465/587

### Gather Information Using Metasploit

- `auxiliary/scanner/smtp/smtp_version` will retrieve server version
- `auxiliary/scanner/smtp/smtp_enum` will enumerate SMTP users

### Gather Information Using telnet/nertcat

- `RCPT <user>` or `VRFY <user>` if the response from server is `OK` or `252` then the user will be a valid one
- `EXPN <user>` is used to list all emails available

### Gather Information Using SMTP-User-Enum

`smtp-user-enum -M <mode> -U <user_dict> -t <ip>`

## Samba Server SMB 445

### Connect to Windows Shared Drive

`net use Z: \\<ip>\<drive>$ <password> /user:<user>`

### Gather Information Using Nmap

Full scan

- `nmap -Pn -sSVC -p 445 <ip>` run all checks
- `nmap -Pn -p 445 --script smb-security-mode <ip>` Enumerate security SMB options
- `nmap -Pn -p 445 --script smb-enum-sessions <ip>` Enumerate active sessions
- `nmap -Pn -p 445 --script smb-os-discovery <ip>` Enumerates target OS, domain name, hostname
- `nmap -Pn -p 445 --script smb-enum-sessions --script-args smbusername=<username>, smbpassword=<password> <ip>` log new sessions
- `nmap -Pn -p 445 --script smb-enum-shares <ip>` Enumerates shared folders
- `nmap -Pn -p 445 --script smb-enum-shares --script-args smbusername=<username>, smbpassword=<password> <ip>` Shows a detailed view of the shared folders
- `nmap -Pn -p 445 --script smb-enum-shares, smb-ls --script-args smbusername=<username>, smbpassword=<password> <ip>` Shows a detailed view of the shared folders and displays the directories and files inside the shares
- `nmap -Pn -p 445 --script smb-enum-users --script-args smbusername=<username>, smbpassword=<password> <ip>` Gives a detailed view of the actual users
- `nmap -Pn -p 445 --script smb-enum-groups --script-args smbusername=<username>, smbpassword=<password> <ip>` Gives a detailed view of the actual groups
- `nmap -Pn -p 445 --script smb-enum-stats --script-args smbusername=<username>, smbpassword=<password> <ip>` Show a detailed view of the server stats
- `nmap -Pn -p 445 --script smb-enum-domains --script-args smbusername=<username>, smbpassword=<password> <ip>` Show a detailed view of the existing domains
- `nmap -Pn -p 445 --script smb-enum-services --script-args smbusername=<username>, smbpassword=<password> <ip>` Show a detailed view of the running services

### SMB mapping with SMBMap

- `nmap -Pn -p 445 --script smb-protocols <ip>` Enumerates the versions of SMB used by the server

To enumerate with `smbmap` it's neccesary to go throught a null session or with a valid user, then run as: `smbmap -u <user> -p <password> -d <directory> -H <ip>`.

- `smbmap -u <user> -p <password> -H <ip> -x <command>` This make the user able to execute commands
- `smbmap -u <user> -p <password> -H <ip> -L` This make the user able to see connected Drives
- `smbmap -u <user> -p <password> -H <ip> -r '<drive>'` Connecting to a drive
- `smbmap -u <user> -p <password> -H <ip> --upload 'path_to_file' 'path_in_SMB_server'` This make the user able to upload files
- `smbmap -u <user> -p <password> -H <ip> --download 'file_path'` This make the user able to download files

### Mapping with other tools

#### Gather Information Using Metasploit

- Using metasploit framework for service detection with `scanner/smb/smb_version` module also works to enum samba information
- Using metasploit framework for service detection with `scanner/smb/smb2` module will display if the samba server uses smb2 dialect
- Using metasploit framework for service detection with `scanner/smb/smb_enumusers` will list all users
- Using metasploit framework for service detection with `scanner/smb/smb_enumshares` will list all shares
- Using metasploit framework for service detection with `scanner/smb/smb_login` will try to login into SMB and report those successfull logins, by doing a dictionary attack
- Using metasploit framework for service detection with `scanner/smb/pipe_auditor` will list all available pipes that SMB is using at that moment to connect to with services

#### Gather Information Using Nbmlookup

`nmblookup -A <ip>` this tool retrieves workgroups/MAC of the SMB server

#### Gather Information Using SMBClient

- `smbclient -L <ip> -N` List the workgroups and the shares in smb server
- `smbclient //<ip>//<folder> -N` will get the user into the folder

#### Gather Information Using RPCClient

- `rpcclient -U <username> -N <ip>` -N indicates no password needed
- `rpcclient> srvinfo` will display system info
- `rpcclient> enumdomusers` will display users info
- `rpcclient> enumdomgroups` will display groups info
- `rpcclient> lookupnames <user>` will display the specified user SID

#### Gather Information Using Enum4linux

- `enum4linux -o <ip>` will display a bunch of information about OS
- `enum4linux -U <ip>` will try to list all users
- `enum4linux -G <ip>` will try to list all groups
- `enum4linux -S <ip>` will display all shares of smb server
- `enum4linux -i <ip>` will display connected printers info
- `enum4linux -r -u <user> -p <password>` will retrieve all users SID by doing RID cycling attack

#### Hydra Dictionary Based Attack

Bruteforcing SMB using hydra with dict based attack

`hydra -l <user> -P <path_to_dict> <ip> smb`

## FTP Enumeration 21

### Gather Information Using Nmap

- `nmap -Pn -p 21 --script ftp-brute --script-args userdb=<user_dict> <ip>` Will perform a dictionary based attack and return those valid users
- `nmap -Pn -p 21 --script ftp-anon <ip>` Will try to connect to FTP via anonymous login

### Hydra Dictionary Based Attack

Bruteforcing FTP using hydra with dict based attack

`hydra -l <user> -P <path_to_dict> <ip> ftp`

### Gather Information Using Metasploit

- `auxiliary/scanner/ftp/ftp_version` module that assist to get the FTP server version
- `auxiliary/scanner/ftp/ftp_login` module to perform bruteforcing
- `auxiliary/scanner/ftp/anonymous` module to perform anonymous login into FTP server

## SSH Enumeration 22

### Gather Information Using Metasploit

- `auxilary/scanner/ssh/ssh_login` exploit used to brute force by dictionary attack ssh login
- `auxilary/scanner/ssh/ssh_version` will perform banner grabbing to perform a service detection
- `auxilary/scanner/ssh/ssh_enumusers` will perform a bruteforce to enumerate users

### Gather Information Using Nmap

- `nmap -Pn -p 22 --script ssh2-enum-algos <ip>` will enumerate the algorithms that the target machine will use to encrypt the session
- `nmap -Pn -p 22 --script ssh-hostkey --script-args ssh_hostkey=full <ip>` will retrieve the host rsa-ssh key
- `nmap -Pn -p 22 --script ssh-auth-methods --script-args="ssh.user=<user>" <ip>` will check for weak passwords
- `nmap -Pn -p 22 --script ssh-brute --script-args userdb=<path_to_dict> <ip>` Will perform a dictionary based attack and return those valid users

#### Hydra Dictionary Based Attack

Bruteforcing SSH using hydra with dict based attack

`hydra -l <user> -P <path_to_dict> <ip> ssh`

## HTTP Enumeration 80/443

### Gather Information Using Metasploit

- `auxiliary/scanner/http/http_version` will give the banner and version of the actual server that is running HTTP
- `auxiliary/scanner/http/robots_txt` wiil display information from robots.txt
- `auxiliary/scanner/http/http_header` will display detected headers
- `auxiliary/scanner/http/brute_dirs` will try to bruteforce for directories
- `auxiliary/scanner/http/dir_scanner` will try to bruteforce for directories
- `auxiliary/scanner/http/files_dir` will try to bruteforce to display specific files extensions and directories
- `auxilary/scanner/http/apache_userdir_enum` will perform bruterforce anagainst a user file, this will retrieve a list of valid users
- `auxiliary/scanner/http/http_put`  will try to upload a file into the webserver
- `auxiliary/scanner/http/http_login` will perform bruteforce against a target URI

### Gather Information Ubout Web Technology

- `whatweb <ip>` will give a list of the technologies that are running on the server
- `http <ip>` will show the response header, tokens, cookies and body content of the HTTP request

### Fuzzing and Bruteforcing Hidden Directories

All these applications are fuzzers

- `dirb <URI> <path_to_dict>`
- `feroxbuster --url <URI> --wordlist <path_to_dict> --depth <depth_level>`
- `gobuster dir -u <url> -c 'session=<cookie>' -t <threads> -w <path_to_dict>`
- `dirsearch.py -u <url> -w <path_to_dict>`

### Gather Information Uhrought Nmap

- `nmap -Pn -p 80 --script http-enum <ip>` will fuzz for specific and common hidden directories
- `nmap -Pn -p 80 --script http-headers <ip>` will retrieve headers being used in the responses, this will be usefull for getting information about the server
- `nmap -Pn -p 80 --script http-methods --script-args http-methods.url-path=/<directory_were_list_methods>/ <ip>` will retrieve methods that are allowed to the users
- `nmap -Pn -p 80 --script http-webdav-scan <ip>` will scan for weadv installations
- `nmap -Pn -p 80 --script banner <ip>` perform banner grabbing

### Gather Information With other tools

- `curl <url> | more` Will get the reponse from the server and it could be used to extract technologies from `head` tags

## MySQL Enumeration 3306

### Gather Information Using Metasploit

- `auxiliary/scanner/mysql/mysql_version` will lookup for mysql version
- `auxiliary/scanner/mysql/mysql_writable_dirs` will list all wrtiable directories on the target via MySQL shell
- `auxiliary/admin/mysql/mysql_enum` will perform an advanced enumeration scan
- `auxiliary/admin/mysql/mysql_sql` will execute a query in the server
- `auxiliary/scanner/mysql/mysql_schemadump` will perform a dump of the databases and tables
- `auxiliary/scanner/mysql/mysql_hashdump` will try to dump user hashes from the target system
- `auxiliary/scanner/mysql/mysql_login` will bruteforce with a dictionary to get a valid username

### Hydra Dictionary Based Attack

`hydra -l <user> -P <path_to_dict> <ip> mysql`

### MySQL commands

- `select load("<file>");` will try to display the contents of the specified file

### Gather Information With Nmap

- `nmap -Pn -p 3306 --script mysql-empty-password <ip>` will check if is posible to connect to mysql without using a password
- `nmap -Pn -p 3306 --script mysql-info <ip>` will display general information as a banner and the enabled capabilties of MySQL
- `nmap -Pn -p 3306 --script mysql-users --script-args="mysqluser='<user>',mysqlpass='<password>'" <ip>` will try to dump all users of mysql
- `nmap -Pn -p 3306 --script mysql-databases --script-args="mysqluser='<user>',mysqlpass='<password>'" <ip>` will try to dump all databases from mysql
- `nmap -Pn -p 3306 --script mysql-variables --script-args="mysqluser='<user>',mysqlpass='<password>'" <ip>` will dump all variables information stored in them such as the working directory
- `nmap -Pn -p 3306 --script mysql-audit --script-args="mysql-audit.username='<user>',mysql-audit.password='<password>',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" <ip>` will dump info about users logins, anonymous accounts and user privs
- `nmap -Pn -p 3306 --script mysql-dump-hashes --script-args="username='<user>',password='<password>'" <ip>` will dump all user hashes
- `nmap -Pn -p 3306 --script mysql-query --script-args="query='<sql_query>'mysqluser='<user>',mysqlpass='<password>'" <ip>` will execute the provided query

## MSSQL Enumeration 1433

### Metasploit

- `auxiliary/scanner/mssql/mssql_login` will bruteforce with a dictionary based attack
- `auxiliary/admin/mssql/mssql_enum` will retrieve bunch of information about the server
- `auxiliary/admin/mssql/mssql_enum_sql_logins` will enumerate the users that logged into the server
- `auxiliary/admin/mssql/mssql_exec` will try to execute commands in the remote server
- `auxiliary/admin/mssql/mssql_enum_domain` will enumerate domain accounts of the server

### Gather Information With Nmap

- `nmap -Pn -p 1433 --script ms-sql-info <ip>` will display general information as a banner and the enabled capabilties of MySQL
- `nmap -Pn -p 1433 --script ms-sql-ntlm-info <ip>` will dump information about the domain name and hostname
- `nmap -Pn -p 1433 --script ms-sql-brute --script-args userdb=<path_to_user_dict> passdb=<path_to_password_dict> <ip>` will try to bruteforce and get a valid username
- `nmap -Pn -p 1433 --script ms-sql-empty-password <ip>` will check if is posible to connect to mysql without using a password
- `nmap -Pn -p 1433 --script ms-sql-query --script-args mssql.username=<username>,mssql.password=<password>,ms-sql-query.query=<query> <ip>` will execute the provided query
- `nmap -Pn -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=<username>,mssql.password=<password> <ip>` will dump user hashes
- `nmap -Pn -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=<username>,mssql.password=<password>,ms-sql-xp-cmdshell.cmd="<query>" <ip>` will execute the provided query

## Searching for Nmap scripts

`ls -al /usr/share/nmap/scripts/ | grep <protocol>-*`

## Importing nmap results into metasploit

- `workspace -a <new_workspace_name>` will create a new metasploit workspace, then save data from nmap into `XML` format `nmap -Pn -sS -O -sV <ip> -oX <output_name>`, to import the file to metasploit `db_import <file>`
- Ruun directly from metasploit with `db_nmap -Pn -sS -O -sV <ip>`
