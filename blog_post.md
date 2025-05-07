# Unmasking Kaolin RAT: A Deep Dive into Lazarus Group's Latest Malware

## Introduction

In the ever-evolving landscape of cyber threats, Advanced Persistent Threat (APT) groups continue to develop sophisticated malware to achieve their objectives. One such recent discovery is the Kaolin RAT, a Remote Access Trojan attributed to the North Korean Lazarus Group. This blog post provides a comprehensive analysis of Kaolin RAT, its attack chain, technical capabilities, and detection methods.

## The Lazarus Connection

The Lazarus Group, also known as HIDDEN COBRA or APT38, is a North Korean state-sponsored threat actor known for its sophisticated cyber operations. The group has been active since at least 2009 and has been linked to numerous high-profile attacks, including the 2014 Sony Pictures hack, the 2016 Bangladesh Bank heist, and the 2017 WannaCry ransomware outbreak.

The Kaolin RAT represents the latest addition to the Lazarus Group's arsenal, showcasing their continued evolution and technical sophistication.

## Initial Access: The Job Offer Lure

The Kaolin RAT attack begins with a social engineering approach that has become increasingly common for the Lazarus Group: fabricated job offers. The attackers establish rapport with targeted individuals, often those with technical backgrounds, through platforms like LinkedIn, WhatsApp, or email.

Once trust is established, the attackers send a malicious ISO file disguised as a VNC tool, supposedly part of the job interview process. This approach is particularly effective because:

1. ISO files can be automatically mounted in Windows 10 and later versions
2. This mounting process may bypass Mark-of-the-Web (MotW) protections
3. The victim is already primed to expect and execute the file

## The Attack Chain: A Multi-Stage Approach

The Kaolin RAT is deployed through a sophisticated multi-stage attack chain that demonstrates the technical expertise of its developers:

```
ISO File → AmazonVNC.exe (choice.exe) → version.dll → iexpress.exe → aws.cfg → 
Shellcode → RollFling → RollSling → RollMid → Kaolin RAT → FudModule Rootkit
```

Let's break down each stage:

### Stage 1: ISO Dropper and DLL Sideloading

The ISO file contains three components:
- `AmazonVNC.exe` - A legitimate Windows application (`choice.exe`) used for DLL sideloading
- `version.dll` - A malicious DLL that is sideloaded by the legitimate application
- `aws.cfg` - An obfuscated payload (VMProtect) that downloads shellcode from the C2 server

When the victim executes `AmazonVNC.exe`, it loads the malicious `version.dll` through DLL sideloading. This technique helps evade detection since the malicious code executes in the context of a legitimate application.

The `version.dll` uses direct syscalls to avoid user-mode API hooks, a technique designed to bypass security products. It then spawns an `iexpress.exe` process to host the next stage payload from `aws.cfg`.

### Stage 2: RollFling Loader

The RollFling loader serves as the initial persistence mechanism, registered as a service. Its key feature is the use of the System Management BIOS (SMBIOS) table as a decryption key for the next stage.

By calling the `GetSystemFirmwareTable` function, RollFling retrieves the SMBIOS data and uses it as a 32-byte key to decrypt the RollSling loader using XOR operation. This approach indicates a highly targeted attack, as the decryption would fail without the correct SMBIOS data specific to the victim's machine.

### Stage 3: RollSling Loader

RollSling executes entirely in memory to evade detection. Its primary function is to locate a binary blob containing encrypted components and configuration data.

To better hide its malicious files, RollSling creates two folders in the Package Cache directory, a common repository for software installation files. It moves the binary blob to these folders with a `.cab` extension to blend with legitimate files.

### Stage 4: RollMid Loader

RollMid is responsible for loading key components and establishing C2 communication. It extracts and decrypts components from the binary blob using AES encryption and decompression.

The loader establishes communication with a multi-layered C2 infrastructure:
1. It communicates with the first C2 layer to retrieve the address of the second layer
2. It contacts the second layer to download an image containing hidden data (steganography)
3. It communicates with the third layer using the data extracted from the image

To make its traffic appear legitimate, RollMid constructs URLs using randomly selected words from a generated dictionary.

### Stage 5: Kaolin RAT

The Kaolin RAT is the main payload with extensive remote access capabilities. It parses configuration data from the received data blob and establishes encrypted communication with its C2 server.

The RAT supports a wide range of commands:
- File system operations (listing, modifying, deleting files)
- Process management (listing, creating, terminating)
- Command execution via command line
- Configuration management
- File upload to C2
- Network connections
- File compression
- Loading and executing DLLs from the C2 server

One particularly interesting capability is the ability to change a file's last write timestamp, a technique used to avoid detection based on file modification times.

## Advanced Evasion Techniques

The Kaolin RAT employs multiple sophisticated evasion techniques:

### 1. Fileless Execution
Most components are loaded and executed directly in memory, minimizing artifacts on disk and making detection more difficult.

### 2. DLL Sideloading
The use of legitimate Windows applications to load malicious DLLs helps bypass security controls that trust legitimate applications.

### 3. Encryption and Obfuscation
The malware uses AES encryption for C2 communication and stored components, VMProtect for obfuscation, and XOR encryption with SMBIOS data as a key.

### 4. Steganography
Data is hidden within images retrieved from the C2 server, making it difficult to detect malicious traffic.

### 5. Legitimate-Looking Network Traffic
URLs are constructed with dictionary words to appear legitimate, and standard HTTP methods are used for communication.

### 6. Anti-Analysis Techniques
The malware checks for specific security products and uses direct syscalls to bypass user-mode API hooks.

## Detection and Mitigation

### YARA Rules

We've developed YARA rules to detect various components of the Kaolin RAT attack chain:

```yara
rule Kaolin_RAT {
    meta:
        description = "Detects Kaolin RAT malware used by Lazarus Group"
        author = "Security Researcher"
        date = "2024-05-01"
        hash = "a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690"
    
    strings:
        // Strings related to C2 communication
        $s1 = "SendDataFromUrl" ascii wide
        $s2 = "GetImageFromUrl" ascii wide
        $s3 = "GetHtmlFromUrl" ascii wide
        $s4 = "curl_global_cleanup" ascii wide
        $s5 = "curl_global_init" ascii wide
        
        // Exported functions
        $export1 = "_DoMyFunc" ascii wide
        $export2 = "_DoMyFunc2" ascii wide
        $export3 = "_DoMyThread" ascii wide
        $export4 = "_DoMyCommandWork" ascii wide
        
        // Dictionary-based URL generation
        $dict = { 83 C0 04 89 45 ?? 8B 45 ?? 8B 00 89 45 ?? 8B 45 ?? 83 C0 04 89 45 ?? }
        
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($s*) or 2 of ($export*)) and $dict
}
```

### Mitigation Recommendations

1. **Application Whitelisting**: Implement application whitelisting to prevent execution of unauthorized binaries.
2. **Email Security**: Block ISO file attachments in email and implement advanced email filtering.
3. **Disable AutoRun**: Disable AutoRun for removable media to prevent automatic execution.
4. **Network Segmentation**: Implement network segmentation and monitor for unusual outbound connections.
5. **EDR Solutions**: Deploy endpoint detection and response (EDR) solutions for advanced threat detection.
6. **User Education**: Educate users about social engineering tactics, especially those involving job offers.
7. **YARA Rules**: Implement YARA rules to detect Kaolin RAT components.
8. **Service Monitoring**: Monitor for the creation of services by unauthorized applications.

## Indicators of Compromise (IOCs)

### File Hashes

- **ISO Dropper**: `b8a4c1792ce2ec15611932437a4a1a7e43b7c3783870afebf6eae043bcfade30`
- **RollFling**: `a3fe80540363ee2f1216ec3d01209d7c517f6e749004c91901494fb94852332b`
- **RollSling**: `e68ff1087c45a1711c3037dad427733ccb1211634d070b03cb3a3c7e836d210f`
- **RollMid**: `9a4bc647c09775ed633c134643d18a0be8f37c21afa3c0f8adf41e038695643e`
- **Kaolin RAT**: `a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690`

### Network Indicators

- C2 Domain: `henraux.com`
- C2 URL Path: `/sitemaps/about/about.asp`

## Conclusion

The Kaolin RAT represents a sophisticated malware strain used by the Lazarus Group in targeted attacks. Its multi-stage deployment, advanced evasion techniques, and extensive capabilities demonstrate the high level of technical expertise of its developers.

The use of SMBIOS data as a decryption key indicates a highly targeted approach, suggesting that victims are carefully selected before the attack is launched. This level of sophistication highlights the continued evolution of APT groups and the need for advanced security measures to detect and mitigate such threats.

By understanding the techniques and tactics used by the Kaolin RAT, security professionals can better protect their organizations against similar threats in the future.

---

*All analysis was conducted in a controlled environment. The IOCs and YARA rules provided in this blog post are intended for defensive purposes only.*
