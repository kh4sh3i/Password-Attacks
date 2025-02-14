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
  <img src="/img/1.webp" alt="" height="500px;">
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
## Network Services
```
FTP	SMB	NFS
IMAP/POP3	SSH	MySQL/MSSQL
RDP	WinRM	VNC
Telnet	SMTP	LDAP
```
