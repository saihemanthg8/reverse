# Kaolin RAT: Technical Analysis

## Introduction

This document provides a detailed technical analysis of the Kaolin RAT malware, a sophisticated Remote Access Trojan attributed to the North Korean Lazarus APT group. The malware was discovered in 2023-2024 and has been used in targeted attacks against individuals through fabricated job offers.

## Attack Chain Overview

The Kaolin RAT is deployed through a complex multi-stage attack chain:

```
ISO File → AmazonVNC.exe (choice.exe) → version.dll → iexpress.exe → aws.cfg → 
Shellcode → RollFling → RollSling → RollMid → Kaolin RAT → FudModule Rootkit
```

## Initial Infection Vector

The attack begins with social engineering, where the attacker establishes rapport with the victim through fabricated job offers. The victim is then tricked into mounting an ISO file containing:

- `AmazonVNC.exe` - A legitimate Windows application (`choice.exe`) used for DLL sideloading
- `version.dll` - A malicious DLL that is sideloaded by the legitimate application
- `aws.cfg` - An obfuscated payload (VMProtect) that downloads shellcode from the C2 server

## Stage 1: RollFling Loader

The RollFling loader is a malicious DLL that serves as the initial persistence mechanism, registered as a service.

### Key Characteristics:

1. **SMBIOS Table Acquisition**: 
   - Uses `GetSystemFirmwareTable` to retrieve the System Management BIOS table
   - The SMBIOS data serves as a 32-byte key for decrypting the next stage

2. **Targeted Approach**:
   - The use of SMBIOS data as a decryption key indicates a highly targeted attack
   - Without the correct SMBIOS data, decryption fails and the malware cannot proceed

3. **File Operations**:
   - Decrypts the RollSling loader using XOR operation with the SMBIOS data
   - Loads the decrypted RollSling into memory for execution

## Stage 2: RollSling Loader

RollSling is executed entirely in memory to evade detection by security software.

### Key Characteristics:

1. **Binary Blob Location**:
   - Searches for a specific binary blob in the same folder or in the Package Cache folder
   - Uses multiple conditions to identify the correct binary blob (MZ header check, export function check)

2. **Persistence Enhancement**:
   - Creates two folders in the Package Cache directory with specific naming patterns
   - Moves the binary blob to these folders with a `.cab` extension to blend with legitimate files

3. **Execution Flow**:
   - Calls the exported `StartAction` function with specific arguments
   - Passes information about file paths to the next stage (RollMid)

## Stage 3: RollMid Loader

RollMid is responsible for loading key components and establishing C2 communication.

### Key Characteristics:

1. **Binary Blob Structure**:
   - The binary blob contains multiple components:
     - RollMid loader (beginning of the blob)
     - Two encrypted DLLs
     - Configuration data (end of the blob)

2. **Decryption Process**:
   - Uses AES algorithm for decryption
   - Applies decompression after decryption
   - Loads the decrypted components into memory

3. **C2 Communication**:
   - Establishes communication with a multi-layered C2 infrastructure
   - Uses steganography to hide data in images from the second C2 layer
   - Constructs URLs with randomly selected words from a generated dictionary

## Stage 4: Kaolin RAT

The Kaolin RAT is the main payload with extensive remote access capabilities.

### Key Characteristics:

1. **Configuration Parsing**:
   - Parses configuration data from the received data blob
   - Configuration includes sleep intervals, flags for information collection, and C2 addresses

2. **C2 Communication**:
   - Uses AES encryption for C2 traffic
   - Employs base64 encoding for data blobs
   - Constructs URLs with randomly selected words from a dictionary

3. **Command Execution**:
   - Supports a wide range of commands:
     - File system operations (listing, modifying, deleting files)
     - Process management (listing, creating, terminating)
     - Command execution via command line
     - Configuration management
     - File upload to C2
     - Network connections
     - File compression
     - Loading and executing DLLs from the C2 server

4. **Advanced Capabilities**:
   - Can change a file's last write timestamp to avoid detection
   - Capable of loading arbitrary DLLs from the C2 server
   - Can execute specific exported functions from loaded DLLs

## Evasion Techniques

The Kaolin RAT employs multiple evasion techniques:

1. **Fileless Execution**:
   - Most components are loaded and executed directly in memory
   - Minimizes artifacts on disk

2. **DLL Sideloading**:
   - Uses legitimate Windows applications to load malicious DLLs
   - Helps bypass security controls that trust legitimate applications

3. **Encryption and Obfuscation**:
   - Uses AES encryption for C2 communication and stored components
   - Employs VMProtect for obfuscation
   - Uses XOR encryption with SMBIOS data as a key

4. **Steganography**:
   - Hides data within images retrieved from the C2 server

5. **Legitimate-Looking Network Traffic**:
   - Constructs URLs with dictionary words to appear legitimate
   - Uses standard HTTP methods for communication

6. **Anti-Analysis Techniques**:
   - Checks for specific security products (e.g., Kaspersky)
   - Uses direct syscalls to bypass user-mode API hooks

## YARA Rules

```yara
rule Kaolin_RAT_Memory {
    meta:
        description = "Detects Kaolin RAT malware in memory"
        author = "Security Researcher"
        date = "2024-05-01"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // Command capabilities
        $cmd1 = "Updating sleep interval" ascii wide nocase
        $cmd2 = "Listing files in folder" ascii wide nocase
        $cmd3 = "Changing file timestamp" ascii wide nocase
        $cmd4 = "Executing command line" ascii wide nocase
        
        // Function imports
        $func1 = "SendDataFromURL" ascii wide
        $func2 = "ZipFolder" ascii wide
        $func3 = "UnzipStr" ascii wide
        
        // Memory patterns
        $mem1 = { 83 ?? 04 89 ?? ?? 8B ?? ?? 8B 00 89 ?? ?? }
        $mem2 = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? }
        
    condition:
        (2 of ($cmd*) and 2 of ($func*)) or (any of ($mem*) and any of ($func*))
}
```

## Indicators of Compromise (IOCs)

### File Hashes

- **Kaolin RAT**: `a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690`

### File System Artifacts

- Folders created in Package Cache:
  - `%driveLetter%:\ProgramData\Package Cache\[0-9A-Z]{8}-DF09-AA86-YI78-[0-9A-Z]{12}\`
  - `%driveLetter%:\ProgramData\Package Cache\[0-9A-Z]{8}-09C7-886E-II7F-[0-9A-Z]{12}\`

### Network Indicators

- HTTP POST requests with encrypted content
- URLs containing randomly selected dictionary words
- Base64-encoded and AES-encrypted payloads

## Conclusion

The Kaolin RAT represents a sophisticated malware strain used by the Lazarus APT group in targeted attacks. Its multi-stage deployment, advanced evasion techniques, and extensive capabilities demonstrate the high level of technical expertise of its developers. The use of SMBIOS data as a decryption key indicates a highly targeted approach, suggesting that victims are carefully selected before the attack is launched.

Organizations should implement the provided YARA rules and monitor for the identified indicators of compromise to detect potential infections. Additionally, awareness of social engineering tactics, particularly those involving job offers, is crucial for preventing initial compromise.
