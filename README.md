# List of Repositories

This is just a list of repositories I tend to find useful or interesting... Not sure how well sorting will work out...

## Comprehensive Resources
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://www.ired.team/
- https://github.com/danielmiessler/SecLists
- https://gtfobins.github.io/
- https://lolbas-project.github.io/
- https://github.com/trimstray/the-book-of-secret-knowledge
- https://github.com/xapax/security
- https://github.com/xrkk/awesome-cyber-security
- https://github.com/Spacial/csirt
- https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki
- https://rmusser.net/docs/index.html
- https://dmcxblue.gitbook.io/red-team-notes-2-0/

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

### Egress Busting
- Go-Out - https://github.com/sensepost/go-out

## Windows

### BloodHound / SharpHound
- https://github.com/BloodHoundAD/BloodHound
- https://github.com/BloodHoundAD/SharpHound3
- https://github.com/fox-it/BloodHound.py
- Bloodhound Import (direct import into Neo4j) - https://github.com/fox-it/bloodhound-import
- Cypheroth (Awesome bloodhound query repo) - https://github.com/seajaysec/cypheroth
- "Custom Queries" (another bloodhound query repo) - https://github.com/awsmhacks/awsmBloodhoundCustomQueries
- "Custom Queries" (another bloodhound query repo - more updated) - https://github.com/hausec/Bloodhound-Custom-Queries

### ActiveDirectory
- Cheat Sheet - https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
- PywerView (Python version of PowerView) - https://github.com/the-useless-one/pywerview
- ADModule (Import ActiveDirectory module without installing RSAT) - https://github.com/samratashok/ADModule
- MSLDAP - https://github.com/skelsec/msldap

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

#### DotNet DeObfuscation
- De4dot - https://github.com/0xd4d/de4dot
- De4dot with ConfuserEx deobfuscation - https://github.com/ViRb3/de4dot-cex

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

### Active Directory Certificate Services - ADCS
- Whisker - https://github.com/eladshamir/Whisker
  - PyWhisker (Python version of Whisker) https://github.com/ShutdownRepo/pywhisker
  - These attacks require Windows 2016 functional level to have the `msDs-KeyCredentialLink` object attribute.
- PKINIT Tools - https://github.com/dirkjanm/PKINITtools

## OSX

- MacSwift C2 - https://github.com/cedowens/MacShellSwift/tree/master/MacShellSwift

### Jamf
- https://github.com/FSecureLABS/Jamf-Attack-Toolkit


## Linux

- Kernel Exploits (3+ year old repo) https://github.com/lucyoa/kernel-exploits
- NFSpy (exploiting/mounting NFS) - https://github.com/bonsaiviking/NfSpy

## C2 Frameworks

- Metasploit - https://github.com/rapid7/metasploit-framework
- Empire 2- https://github.com/BC-SECURITY/Empire
- Covenant - https://github.com/cobbr/Covenant
- PoshC2 - https://github.com/nettitude/PoshC2
- Sliver - https://github.com/BishopFox/sliver
  - Sliver Scripting - https://github.com/moloch--/sliver-script
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

### Web Enumeration
- GAU (Gather All Links) - https://github.com/lc/gau

### Web Screenshots
- GoWitness - https://github.com/sensepost/gowitness

### Web Shells
- ABPTTS - https://github.com/nccgroup/ABPTTS

## Passwords

### Hash Cracking
- Hashcat - https://github.com/hashcat
- John the Ripper - https://github.com/magnumripper/JohnTheRipper

### Cracking Rules
- OneRuleToRuleThemAll - https://github.com/NotSoSecure/password_cracking_rules

### Cracking Masks
- Microsoft mask is really effective - https://github.com/xfox64x/Hashcat-Stuffs

### Word Lists
- WordSmith - https://github.com/skahwah/wordsmith
- PwDB-Public - https://github.com/FlameOfIgnis/Pwdb-Public

### Password Spraying
- PurpleSpray - https://github.com/mvelazc0/PurpleSpray
- KerBrute - https://github.com/TarlogicSecurity/kerbrute

### Password Brute Forcing
- Patator - https://github.com/lanjelot/patator


## Go Projects (Generic)
- Run shellcode (Windows or Unix via hex command line arg) - https://github.com/brimstone/go-shellcode
- Hershell - https://github.com/lesnuages/hershell

## VMWare / vSphere
- GoVC - https://github.com/vmware/govmomi/tree/master/govc

### AWS

- DuffleBag (Search public EBS for secrets) - https://github.com/BishopFox/dufflebag

### Office365 / Azure
- UhOh356 - https://github.com/Raikia/UhOh365
- MSOLSpray - https://github.com/dafthack/MSOLSpray
- ROADtools - https://github.com/dirkjanm/ROADtools

### DevOps Tools
- Master of Servers (Puppet, Cheff, Ansible exploitation) - https://github.com/master-of-servers/mose

### Browser
- Chrome Password Dumper - https://github.com/roflsandwich/Chrome-Password-Dumper
- Browser Exploitation list - https://github.com/Escapingbug/awesome-browser-exploit
- Chrome Cookie stealer via Remote Debugging port - https://github.com/slyd0g/WhiteChocolateMacademiaNut
- BrowserPass (Steals Firefox and IE creds, but needs a lot of DLLs) - https://github.com/jabiel/BrowserPass

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

## Routers and Switches
- Routopsy (attack dynamic routing protocols) - https://github.com/sensepost/routopsy

## ThreatHunting
- ThreatHunter's playbooks - https://github.com/hunters-forge/ThreatHunter-Playbook/
- BlueSPAWN - https://github.com/ION28/BLUESPAWN
- PeaceMaker - https://github.com/D4stiny/PeaceMaker
- OSCtrl (OSQuery open source management tool) - https://github.com/jmpsec/osctrl

## LAB Creation

- DetectionLab - https://github.com/clong/DetectionLab
- DynamicLabs - https://github.com/ctxis/DynamicLabs
- Mini-Internet using LXC - https://github.com/flesueur/mi-lxc
- Microsoft's Defend the Flag - https://github.com/microsoft/DefendTheFlag/

### Atomic Red Teaming
- Leonidas by @fsecurelabs https://github.com/fsecurelabs/leonidas

## Live Memory Editing / Game Cheats
- Squalr - https://github.com/Squalr/Squalr

## Pentesting Documents
- Physical Docs - https://github.com/trustedsec/physical-docs

## Honey Pots
- https://github.com/s0md3v/Predator

## Classes
- Modern Binary Exploiration - https://github.com/RPISEC/MBE
