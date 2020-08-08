# This is shamelessly taken from @mubix (https://github.com/mubix/repos) and I'm just adding my 2 cents for my own records

# Quick Jump List:

<details>
  <summary>Sites</summary>
  
  - [Helpful Sites](#helpful-sites)
    - [Training](#training)
  - [Misc. Git Repos](#misc-git-repos)
</details>

<details>
  <summary>Recon</summary>

  - [External](#external)
  - [Internal](#internal)
  - [OSINT](#osint)
  - [Port Scanning](#port-scanning)
</details>

<details>
  <summary>Windows</summary>
  
  - [BloodHound / SharpHound](#bloodhound--sharphound)
  - [ActiveDirectory](#activedirectory)
  - [GPO](#gpo)
  - [ACLs](#acls)
  - [Mimikatz](#mimikatz)
  - [Windows Shares](#windows-shares)
  - [Kerberos](#kerberos)
  - [MSSQL](#mssql)
  - [Sharp / CSharp Tools](#sharp--csharp-tools)
  - [DotNet Obfuscation](#dotnet-obfuscation)
  - [DotNet Deserialization](#dotnet-deserialization)
  - [PowerShell](#powershell)
  - [Lateral Movement](#lateral-movement)
  - [Privilege Escalation](#privilege-escalation)
  - [WSUS Exploitation](#wsus-exploitation)
  - [Process Injection](#process-injection)
</details>

<details>
  <summary>OSX</summary>
  
   - [Jamf](#jamf)
</details>
  
<details>
  <summary>Linux</summary>
  
   - [Kernel Exploits](#kernel-exploits)
</details>

<details>
  <summary>C2 Frameworks</summary>
  
  - [CobaltStrike Resources](#cobaltstrike-resources)
</details>

<details>
  <summary>WWW</summary>
  
  - [Web Shells](#web-shells)
</details>

<details>
  <summary>Passwords</summary>
  
  - [Hash Cracking](#hash-cracking)
  - [Cracking Rules](#cracking-rules)
  - [Word Lists](#word-lists)
  - [Password Spraying](#password-spraying)
  - [Password Brute Forcing](#password-brute-forcing)
</details>

<details>
  <summary>Programming</summary>
  
  - [C](#c)
  - [GoLang](#golang)
</details>

<details>
  <summary>VMWare / vSphere</summary>
  
  - [AWS](#aws)
  - [Office365 / Azure](#office365--azure)
  - [DevOps Tools](#devops-tools)
  - [Browser](#browser)
</details>

<details>
  <summary>Other Resources</summary>

- [DNS](#dns)
- [Phishing](#phishing)
- [Wireless](#wireless)
- [Secrets Extraction](#secrets-extraction)
- [Kubernetes](#kubernetes)
- [Hardware](#hardware)
- [ThreatHunting](#threathunting)
- [LAB Creation](#lab-creation)
- [Live Memory Editing / Game Cheats](#live-memory-editing--game-cheats)
- [Pentesting Documents](#pentesting-documents)
- [Honey Pots](#honey-pots)
- [Reversing](#reversing)
- [Articles](#articles--papers)
</details>

##

### Misc. Git Repos
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://github.com/Binject/backdoorfactory
- https://github.com/carpedm20/awesome-hacking
- https://github.com/Hack-with-Github/Awesome-Hacking
- https://github.com/D35m0nd142/LFISuite
- https://github.com/leostat/rtfm - I LOVE THIS ONE!
- https://github.com/lanmaster53/recon-ng
- https://github.com/carnal0wnage
- https://github.com/trimstray/the-book-of-secret-knowledge
- https://github.com/xapax/security
- https://github.com/xrkk/awesome-cyber-security
- https://github.com/danielmiessler/SecLists
- https://github.com/devanshbatham/Awesome-Bugbounty-Writeups


### Helpful Sites
- https://ippsec.rocks/ - Content creator @ippsec searchable video archive
- http://pentestmonkey.net/ - List of helpful reverse shell cheat sheets and others
- https://blog.g0tmi1k.com/ - More Helpful tips
- https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/
- https://hakin9.org/covenant-the-net-based-c2-on-kali-linux/
- https://www.bleepingcomputer.com/news/security/resurrected-powershell-empire-framework-converted-to-python-3/
- https://jhalon.github.io/utilizing-syscalls-in-csharp-1/
- https://web.stanford.edu/class/cs107/resources/gdb
- https://www.hackingarticles.in/comprehensive-guide-to-local-file-inclusion/
- https://geekflare.com/open-source-web-security-scanner/
- https://medium.com/@l4mp1/difference-between-xss-and-csrf-attacks-ff29e5abcd33
- https://pentest-tools.com/home
- https://www.pentestgeek.com/
- https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/
- https://github.com/mishmashclone/OlivierLaflamme-Cheatsheet-God - Another site like this one
- https://www.ired.team/
- https://gtfobins.github.io/
- https://lolbas-project.github.io/
- https://hackerassociation.com/home
- https://cti-league.com/
- https://www.chapo.chat/

#### Training
  - https://www.hackthebox.eu/login
  - https://portswigger.net/web-security/
  - https://tryhackme.com/
  - https://www.hackthissite.org/

## Recon

### External
- https://github.com/OWASP/Amass

### OSINT
- LinkedIn Intel - https://github.com/vysecurity/LinkedInt
- WeakestLink (LinkedIn) - https://github.com/shellfarmer/WeakestLink
- Gather Contacts (Google) - https://github.com/clr2of8/GatherContacts

### Internal
- https://github.com/rvrsh3ll/eavesarp (Watches ARP for inter-IP communication)
- https://github.com/mzfr/gtfo (Located GTFO/LOLBAS binaries on disk)
- PXE CLient - https://github.com/Meatballs1/PXEClient

### Port Scanning
- RustScan - https://github.com/RustScan/RustScan

## Windows

### BloodHound / SharpHound
- https://github.com/BloodHoundAD/BloodHound
- https://github.com/BloodHoundAD/SharpHound3
- https://github.com/fox-it/BloodHound.py
- Bloodhound Import (direct import into Neo4j) - https://github.com/fox-it/bloodhound-import
- Cypheroth (Awesome bloodhound query repo) - https://github.com/seajaysec/cypheroth
- "Custom Queries" (another bloodhound query repo) - https://github.com/awsmhacks/awsmBloodhoundCustomQueries

### ActiveDirectory
- Cheat Sheet - https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
- PywerView (Python version of PowerView) - https://github.com/the-useless-one/pywerview

### GPO
- Grouper2 - https://github.com/l0ss/Grouper2

### ACLs
- ALCPwn (connects to Neo4j and executes changes) https://github.com/fox-it/aclpwn.py

### Mimikatz
- https://github.com/gentilkiwi/mimikatz
- https://github.com/gentilkiwi/kekeo
- Invoke-UpdateMimikatzScript.ps1 - https://gist.github.com/ihack4falafel/8b41d810d79cb16a4b1bca5ff6600b17

### Windows Shares
- SMBMap - https://github.com/ShawnDEvans/smbmap
- Snaffler - https://github.com/SnaffCon/Snaffler

### Kerberos
- https://github.com/ropnop/kerbrute
- Kerbeos Attack Cheatsheet - https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

### MSSQL
- https://github.com/NetSPI/PowerUpSQL
- https://github.com/Keramas/mssqli-duet/

### Sharp / CSharp Tools
- https://github.com/GhostPack/SharpDump
- SharPersist (persistence automation) - https://github.com/fireeye/SharPersist
- https://github.com/rasta-mouse/MiscTools
- Watson (looks for missing patches) - https://github.com/rasta-mouse/Watson 
- CertEXP (Extracts exportable certificates) - https://github.com/mubix/certexp
- Internal Monologue (steal creds w/o admin)  - https://github.com/eladshamir/Internal-Monologue
- ProcessInjection - https://github.com/ZeroPointSecurity/ProcessInjection

#### DotNet Obfuscation
- ConfuserEx - https://github.com/mkaring/ConfuserEx

#### DotNet Deserialization
- https://github.com/Illuminopi/RCEvil.NET
- YSoSerial.net - https://github.com/pwntester/ysoserial.net

### PowerShell
- PowerSploit DEV branch - https://github.com/PowerShellMafia/PowerSploit/tree/dev
- PowerUpSQL - https://github.com/NetSPI/PowerUpSQL
- PowerMAD - https://github.com/Kevin-Robertson/Powermad
- Inveigh - https://github.com/Kevin-Robertson/Inveigh
- Spooler bug PS1 Exploit / Original PoC - https://github.com/leechristensen/SpoolSample
- DAMP - Remote registry exploitation - https://github.com/HarmJ0y/DAMP

### Lateral Movement
- LethalHTA (DCOM to load HTA remotely) - https://github.com/codewhitesec/LethalHTA
- Excel4DCOM (DCOM to load Excel 4 macro) - https://github.com/outflanknl/Excel4-DCOM
- LSASSY (Remotely dump LSASS memory) - https://github.com/Hackndo/lsassy
- IOXIDResolver (identifies host with multiple interfaces w/o auth) - https://github.com/mubix/IOXIDResolver

### Privilege Escalation
- Change-LockScreen - https://github.com/nccgroup/Change-Lockscreen
- RunAsTI (TrustedInstaller) - https://github.com/jschicht/RunAsTI
- CEFDebug - https://github.com/taviso/cefdebug
- Tokenvator - https://github.com/0xbadjuju/Tokenvator

### WSUS Exploitation
- WSUSpect (doesn't work on Win10) - https://github.com/ctxis/wsuspect-proxy
- WSUSpendu - https://github.com/AlsidOfficial/WSUSpendu
- SeBackupPrivilege - https://github.com/giuliano108/SeBackupPrivilege

### Process Injection
- Pinjectra - https://github.com/SafeBreach-Labs/pinjectra

### Microsoft Exchange
- Ruler - https://github.com/sensepost/ruler

## OSX

- MacSwift C2 - https://github.com/cedowens/MacShellSwift/tree/master/MacShellSwift

### Jamf
- https://github.com/FSecureLABS/Jamf-Attack-Toolkit


## Linux
- NFSpy (exploiting/mounting NFS) - https://github.com/bonsaiviking/NfSpy
### Kernel Exploits
  - https://github.com/lucyoa/kernel-exploits (3+ year old repo)

## C2 Frameworks

- Metasploit - https://github.com/rapid7/metasploit-framework
- Empire 2- https://github.com/BC-SECURITY/Empire
- Covenant - https://github.com/cobbr/Covenant
- PoshC2 - https://github.com/nettitude/PoshC2
- Sliver - https://github.com/BishopFox/sliver
- Merlin - https://github.com/Ne0nd0g/merlin
- Koadic C3 - https://github.com/zerosum0x0/koadic
- SilentTrinity - https://github.com/byt3bl33d3r/SILENTTRINITY

### CobaltStrike Resources
- https://github.com/killswitch-GUI/CobaltStrike-ToolKit

## DNS
- DNS Ftp (Download file over DNS) - https://github.com/breenmachine/dnsftp

## WWW

- API key usage / hacks - https://github.com/streaak/keyhacks 
- Jenkins PWN - https://github.com/gquere/pwn_jenkins
- CORStest (CORS scanner) - https://github.com/RUB-NDS/CORStest

### Web Shells
- ABPTTS - https://github.com/nccgroup/ABPTTS

## Passwords

### Hash Cracking
- Hashcat - https://github.com/hashcat
- John the Ripper - https://github.com/magnumripper/JohnTheRipper

### Cracking Rules
- OneRuleToRuleThemAll - https://github.com/NotSoSecure/password_cracking_rules

### Word Lists
- WordSmith - https://github.com/skahwah/wordsmith
- PwDB-Public - https://github.com/FlameOfIgnis/Pwdb-Public

### Password Spraying
- PurpleSpray - https://github.com/mvelazc0/PurpleSpray
- KerBrute - https://github.com/TarlogicSecurity/kerbrute

### Password Brute Forcing
- Patator - https://github.com/lanjelot/patator

# Programming
### C
    - https://www.programiz.com/c-programming/examples/print-sentence
### Golang
    - https://www.freecodecamp.org/news/how-to-make-your-own-web-server-with-go/
    - Run shellcode (Windows or Unix via hex command line arg) - https://github.com/brimstone/go-shellcode
    - Hershell - https://github.com/lesnuages/hershell

## VMWare / vSphere
- GoVC - https://github.com/vmware/govmomi/tree/master/govc

### AWS

- DuffleBag (Search public EBS for secrets) - https://github.com/BishopFox/dufflebag
- Pacu (search all AWS for everything) - https://github.com/RhinoSecurityLabs/pacu
- Trailblazer - https://github.com/willbengtson/trailblazer-aws

### Office365 / Azure
- UhOh356 - https://github.com/Raikia/UhOh365
- MSOLSpray - https://github.com/dafthack/MSOLSpray

### DevOps Tools
- Master of Servers (Puppet, Cheff, Ansible exploitation) - https://github.com/master-of-servers/mose

### Browser
- Chrome Password Dumper - https://github.com/roflsandwich/Chrome-Password-Dumper
- Browser Exploitation list - https://github.com/Escapingbug/awesome-browser-exploit

## Phishing
- https://github.com/UndeadSec/SocialFish
- Fudge (auto-download embedded files) - https://github.com/dale-ruane/fudge

## Wireless
- Wifi Phisher - https://github.com/wifiphisher/wifiphisher
- EAP Hammer - https://github.com/s0lst1c3/eaphammer

## Secrets Extraction
- Gralwer (git) - https://github.com/jregele/grawler (ShmooCon 2018)
- GitGot - https://github.com/BishopFox/GitGot
- Blacklist3r - https://github.com/NotSoSecure/Blacklist3r (ASP Machine Keys - DotNet Deserialization)

## Kubernetes
- Finding and exploiting Kubernetes - https://github.com/averonesis/kubolt

## Hardware
- Defeating BIOS passwords - https://github.com/skysafe/reblog/tree/master/0000-defeating-a-laptops-bios-password

## ThreatHunting
- ThreatHunter's playbooks - https://github.com/hunters-forge/ThreatHunter-Playbook/
- BlueSPAWN - https://github.com/ION28/BLUESPAWN
- OSCtrl (OSQuery open source management tool) - https://github.com/jmpsec/osctrl

## LAB Creation

- DetectionLab - https://github.com/clong/DetectionLab
- Mini-Internet using LXC - https://github.com/flesueur/mi-lxc

## Live Memory Editing / Game Cheats
- Squalr - https://github.com/Squalr/Squalr

## Pentesting Documents
- Physical Docs - https://github.com/trustedsec/physical-docs

## Honey Pots
- https://github.com/s0md3v/Predator

# Reversing
- https://github.com/wtsxDev/reverse-engineering
- https://github.com/TheCodeArtist/elf-parser

# Articles / Papers
- https://eclypsium.com/2020/07/29/theres-a-hole-in-the-boot/
- https://www.rapid7.com/research/report/nicer-2020/
- https://www.fsl.cs.sunysb.edu/docs/nfscrack-tr/
