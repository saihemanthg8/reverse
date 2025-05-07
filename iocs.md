# Kaolin RAT: Indicators of Compromise (IOCs)

This document provides a comprehensive list of Indicators of Compromise (IOCs) associated with the Kaolin RAT malware and its attack chain.

## File Hashes

### ISO Dropper
```
b8a4c1792ce2ec15611932437a4a1a7e43b7c3783870afebf6eae043bcfade30
```

### RollFling Loader
```
a3fe80540363ee2f1216ec3d01209d7c517f6e749004c91901494fb94852332b
```

### NLS Files
```
01ca7070bbe4bfa6254886f8599d6ce9537bafcbab6663f1f41bfc43f2ee370e
7248d66dea78a73b9b80b528d7e9f53bae7a77bad974ededeeb16c33b14b9c56
```

### RollSling Loader
```
e68ff1087c45a1711c3037dad427733ccb1211634d070b03cb3a3c7e836d210f
f47f78b5eef672e8e1bd0f26fb4aa699dec113d6225e2fcbd57129d6dada7def
```

### RollMid Loader
```
9a4bc647c09775ed633c134643d18a0be8f37c21afa3c0f8adf41e038695643e
```

### Kaolin RAT
```
a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690
```

## File Names and Paths

### Initial Infection
- `AmazonVNC.exe` - Legitimate Windows application (`choice.exe`) used for DLL sideloading
- `version.dll` - Malicious DLL that is sideloaded by the legitimate application
- `aws.cfg` - Obfuscated payload (VMProtect) that downloads shellcode from the C2 server

### Persistence Locations
- `%driveLetter%:\ProgramData\Package Cache\[0-9A-Z]{8}-DF09-AA86-YI78-[0-9A-Z]{12}\`
- `%driveLetter%:\ProgramData\Package Cache\[0-9A-Z]{8}-09C7-886E-II7F-[0-9A-Z]{12}\`

### File Extensions
- `.nls` - Used for encrypted RollSling components
- `.cab` - Used for binary blobs stored in the Package Cache folder

## Network Indicators

### C2 Domains and URLs
- Primary C2: `henraux.com`
- Specific URL: `https://www.henraux.com/sitemaps/about/about.asp`

### Network Traffic Patterns
- HTTP POST requests with encrypted content
- URLs containing randomly selected dictionary words
- Base64-encoded and AES-encrypted payloads
- Steganography in images retrieved from C2 servers

### HTTP Request Format
- URL Pattern: `%addressOfC&Cserver%?%RandomWordFromDictonary%=%RandomString%`
- POST Content: `%RandomWordFromDictonary%=%TEMP_DATA%&%RandomWordFromDictonary%=%IV%%KEY%&%RandomWordFromDictonary%=%EncryptedContent%&%RandomWordFromDictonary%=%EncryptedHostNameAndIPAddr%`

## Registry Indicators
- Registry key accessed: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Iconservice`

## System Artifacts

### Processes
- `iexpress.exe` - Used to host malicious payloads
- Service creation for persistence

### Memory Artifacts
- Fileless execution of RollSling, RollMid, and Kaolin RAT components
- AES-encrypted data in memory
- Dictionary of words used for URL generation

## MITRE ATT&CK Techniques

| Technique ID | Name | Description |
|--------------|------|-------------|
| T1566.002 | Phishing: Spearphishing Link | Initial access through fabricated job offers |
| T1204.002 | User Execution: Malicious File | Victim executes the malicious ISO file |
| T1027 | Obfuscated Files or Information | VMProtect obfuscation, encryption |
| T1055 | Process Injection | Injection into iexpress.exe |
| T1140 | Deobfuscation/Decoding Files or Information | XOR and AES decryption |
| T1036 | Masquerading | Disguising as Amazon VNC tool |
| T1218.011 | System Binary Proxy Execution: Rundll32 | DLL sideloading |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Service persistence |
| T1070.006 | Indicator Removal: Timestomp | Changing file timestamps |
| T1001.002 | Data Obfuscation: Steganography | Hiding data in images |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES encryption for C2 |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 communication |

## Detection Guidance

### File System Monitoring
- Monitor for the creation of suspicious folders in the Package Cache directory
- Look for unexpected `.nls` and `.cab` files
- Monitor for DLL sideloading patterns (legitimate executables loading DLLs from non-standard locations)

### Network Monitoring
- Monitor for HTTP requests to uncommon domains with dictionary-word parameters
- Look for base64-encoded content in HTTP POST requests
- Monitor for image downloads followed by encrypted HTTP POST requests

### Memory Analysis
- Look for processes with injected code
- Monitor for AES encryption/decryption operations in unexpected processes
- Look for dictionary generation in process memory

### Registry Monitoring
- Monitor for access to uncommon registry keys, especially under Windows\Iconservice

## Mitigation Recommendations

1. Implement application whitelisting to prevent execution of unauthorized binaries
2. Block ISO file attachments in email
3. Disable AutoRun for removable media
4. Implement network segmentation and monitor for unusual outbound connections
5. Deploy endpoint detection and response (EDR) solutions
6. Educate users about social engineering tactics, especially those involving job offers
7. Implement YARA rules to detect Kaolin RAT components
8. Monitor for the creation of services by unauthorized applications
