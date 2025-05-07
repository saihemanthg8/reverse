# Kaolin RAT: Technical Analysis and Detection

## Overview

This repository contains a detailed technical analysis of the Kaolin RAT malware, a sophisticated Remote Access Trojan associated with the North Korean Lazarus APT group. The malware was discovered in 2023-2024 and has been used in targeted attacks against individuals through fabricated job offers.

## Attack Chain

The Kaolin RAT is deployed through a complex multi-stage attack chain:

1. **Initial Access**: Victims are targeted through fabricated job offers, leading to the delivery of a malicious ISO file disguised as a VNC tool.
2. **Stage 1 - RollFling**: A loader DLL that uses SMBIOS data as a decryption key for the next stage.
3. **Stage 2 - RollSling**: Executed in memory, locates and processes a binary blob containing encrypted components.
4. **Stage 3 - RollMid**: Responsible for loading key components and establishing C2 communication.
5. **Stage 4 - Kaolin RAT**: The main payload with extensive remote access capabilities.

## Technical Details

### Kaolin RAT Capabilities

The Kaolin RAT includes the following capabilities:

- Updating sleep intervals
- File system operations (listing, modifying, deleting files)
- Changing file timestamps
- Process management (listing, creating, terminating)
- Command execution
- Configuration management
- File upload to C2
- Network connections
- File compression
- Loading and executing DLLs from the C2 server

### C2 Communication

The malware employs sophisticated C2 communication techniques:

- Multi-layered C2 infrastructure
- Steganography for hiding data in images
- AES encryption for C2 traffic
- Dictionary-based URL generation to appear legitimate
- Base64 encoding for data blobs

### Evasion Techniques

- Fileless execution (loading components directly in memory)
- Legitimate application sideloading
- Encrypted binary blobs
- Steganography
- Timestamp manipulation
- Complex multi-stage execution chain

## YARA Rules

```yara
rule Kaolin_RAT {
    meta:
        description = "Detects Kaolin RAT malware used by Lazarus Group"
        author = "Security Researcher"
        date = "2024-05-01"
        hash = "a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
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

rule RollFling_Loader {
    meta:
        description = "Detects RollFling loader used in Kaolin RAT attack chain"
        author = "Security Researcher"
        date = "2024-05-01"
        hash = "a3fe80540363ee2f1216ec3d01209d7c517f6e749004c91901494fb94852332b"
    
    strings:
        $smbios = "GetSystemFirmwareTable" ascii wide
        $xor_decrypt = { 33 ?? 88 ?? 41 4? 75 ?? }
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
```

## Indicators of Compromise (IOCs)

### File Hashes

- **ISO File**: `b8a4c1792ce2ec15611932437a4a1a7e43b7c3783870afebf6eae043bcfade30`
- **RollFling**: `a3fe80540363ee2f1216ec3d01209d7c517f6e749004c91901494fb94852332b`
- **NLS Files**:
  - `01ca7070bbe4bfa6254886f8599d6ce9537bafcbab6663f1f41bfc43f2ee370e`
  - `7248d66dea78a73b9b80b528d7e9f53bae7a77bad974ededeeb16c33b14b9c56`
- **RollSling**:
  - `e68ff1087c45a1711c3037dad427733ccb1211634d070b03cb3a3c7e836d210f`
  - `f47f78b5eef672e8e1bd0f26fb4aa699dec113d6225e2fcbd57129d6dada7def`
- **RollMid**: `9a4bc647c09775ed633c134643d18a0be8f37c21afa3c0f8adf41e038695643e`
- **Kaolin RAT**: `a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690`

### Network Indicators

- C2 Domain: `henraux.com`
- C2 URL Path: `/sitemaps/about/about.asp`

## References

1. [Avast: From BYOVD to a 0-day: Unveiling Advanced Exploits in Cyber Recruiting Scams](https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/)
2. [Microsoft: Multiple North Korean threat actors exploiting the TeamCity CVE-2023-42793 vulnerability](https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/)

## Analysis Methodology

This analysis was conducted using:
- Static analysis of malware components
- Dynamic analysis in an isolated environment
- Network traffic analysis
- Memory forensics

## Conclusion

The Kaolin RAT represents a sophisticated malware strain used by the Lazarus APT group in targeted attacks. Its multi-stage deployment, advanced evasion techniques, and extensive capabilities demonstrate the high level of technical expertise of its developers. Organizations should implement the provided YARA rules and monitor for the identified indicators of compromise to detect potential infections.
