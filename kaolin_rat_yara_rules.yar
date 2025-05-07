/*
   Kaolin RAT Assembly Code Detection YARA Rules
   Author: Security Researcher
   Date: May 2024
   
   These rules target specific assembly code patterns found in the Kaolin RAT malware
   and its associated components (RollFling, RollSling, RollMid).
*/

import "pe"

rule Kaolin_RAT_SMBIOS_Retrieval {
    meta:
        description = "Detects SMBIOS data retrieval code used in Kaolin RAT's RollFling loader"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "a3fe80540363ee2f1216ec3d01209d7c517f6e749004c91901494fb94852332b"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // Push "RSMB" signature and call GetSystemFirmwareTable
        $smbios1 = { 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 8B ?? 85 ?? 74 ?? 56 FF 15 }
        
        // Second call to GetSystemFirmwareTable with buffer
        $smbios2 = { 56 57 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? }
        
        // "RSMB" signature string
        $rsmb = "RSMB" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "GetSystemFirmwareTable") and
        all of them
}

rule Kaolin_RAT_XOR_Decryption {
    meta:
        description = "Detects XOR decryption routine used in Kaolin RAT's RollFling loader"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "a3fe80540363ee2f1216ec3d01209d7c517f6e749004c91901494fb94852332b"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // XOR decryption loop
        $xor_loop = { 8B ?? 33 ?? ?? 8A ?? ?? 30 ?? ?? 42 3B ?? 72 ?? }
        
        // Alternative pattern for the XOR operation
        $xor_op = { 8A ?? ?? ?? 30 ?? ?? ?? 4? 75 ?? }
        
    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule Kaolin_RAT_Binary_Blob_Parser {
    meta:
        description = "Detects binary blob parsing code used in Kaolin RAT's RollSling loader"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "e68ff1087c45a1711c3037dad427733ccb1211634d070b03cb3a3c7e836d210f"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // Reading first 4 bytes to determine size
        $read_size = { 6A 00 8D ?? ?? ?? ?? ?? 50 6A 04 ?? ?? 50 FF 15 }
        
        // Checking for MZ header
        $mz_check = { 8B ?? ?? ?? 66 81 ?? 4D 5A 75 ?? }
        
        // Looking for StartAction export
        $start_action = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? }
        
        // StartAction string
        $start_action_str = "StartAction" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        2 of ($read_size, $mz_check, $start_action) and
        $start_action_str
}

rule Kaolin_RAT_Dictionary_Generation {
    meta:
        description = "Detects dictionary generation code used in Kaolin RAT's RollMid loader"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "9a4bc647c09775ed633c134643d18a0be8f37c21afa3c0f8adf41e038695643e"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // Dictionary filling pattern
        $dict_fill = { 83 C0 04 89 45 ?? 8B 45 ?? 8B 00 89 45 ?? 8B 45 ?? 83 C0 04 89 45 ?? }
        
        // Common dictionary words
        $word1 = "user" ascii
        $word2 = "type" ascii
        $word3 = "id" ascii
        $word4 = "session" ascii
        $word5 = "token" ascii
        $word6 = "auth" ascii
        $word7 = "data" ascii
        $word8 = "content" ascii
        $word9 = "action" ascii
        $word10 = "status" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        $dict_fill and
        5 of ($word*)
}

rule Kaolin_RAT_AES_Decryption {
    meta:
        description = "Detects AES decryption code used in Kaolin RAT"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // AES context initialization
        $aes_init = { 8D ?? ?? ?? ?? 50 FF 75 ?? 56 E8 ?? ?? ?? ?? 83 C4 0C }
        
        // AES-CBC decryption
        $aes_cbc = { 8D ?? ?? ?? ?? 50 56 57 E8 ?? ?? ?? ?? 83 C4 0C }
        
        // AES function names
        $func1 = "AES_init_ctx" ascii
        $func2 = "AES_init_ctx_iv" ascii
        $func3 = "AES_CBC_decrypt_buffer" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        (all of ($aes*) or 2 of ($func*))
}

rule Kaolin_RAT_Command_Handler {
    meta:
        description = "Detects command handling code used in Kaolin RAT"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // Command ID comparison pattern
        $cmd_check = { 8B 06 83 F8 01 74 ?? 83 F8 02 74 ?? 83 F8 03 74 ?? 83 F8 04 74 ?? 83 F8 05 74 ?? }
        
        // Sleep interval update
        $cmd_sleep = { 83 ?? 08 72 ?? 8B 46 04 A3 ?? ?? ?? ?? B8 01 00 00 00 }
        
        // Command function names or strings
        $cmd_str1 = "ListFiles" ascii
        $cmd_str2 = "UpdateFile" ascii
        $cmd_str3 = "ChangeTimestamp" ascii
        $cmd_str4 = "ListProcesses" ascii
        $cmd_str5 = "ExecuteCommand" ascii
        $cmd_str6 = "UploadFile" ascii
        $cmd_str7 = "ConnectHost" ascii
        $cmd_str8 = "CompressFiles" ascii
        $cmd_str9 = "LoadDll" ascii
        $cmd_str10 = "_DoMyFunc" ascii
        $cmd_str11 = "_DoMyThread" ascii
        $cmd_str12 = "_DoMyCommandWork" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        ($cmd_check or $cmd_sleep) and
        3 of ($cmd_str*)
}

rule Kaolin_RAT_C2_Communication {
    meta:
        description = "Detects C2 communication code used in Kaolin RAT"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // URL construction with dictionary words
        $url_gen = { 8B ?? ?? 03 ?? ?? 0F B6 00 ?? ?? ?? ?? 8D ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 }
        
        // C2 function names
        $c2_func1 = "SendDataFromUrl" ascii
        $c2_func2 = "GetImageFromUrl" ascii
        $c2_func3 = "GetHtmlFromUrl" ascii
        $c2_func4 = "curl_global_cleanup" ascii
        $c2_func5 = "curl_global_init" ascii
        $c2_func6 = "ZipFolder" ascii
        $c2_func7 = "UnzipStr" ascii
        
        // POST request content type
        $content_type = "application/x-www-form-urlencoded" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        $url_gen and
        3 of ($c2_func*) and
        $content_type
}

rule Kaolin_RAT_Steganography {
    meta:
        description = "Detects steganography code used in Kaolin RAT's RollMid loader"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "9a4bc647c09775ed633c134643d18a0be8f37c21afa3c0f8adf41e038695643e"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // Image processing patterns
        $img_proc1 = { 89 ?? ?? 8B ?? ?? 83 ?? 01 83 ?? 01 }
        $img_proc2 = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B ?? ?? 89 ?? ?? }
        
        // GetImageFromUrl function call
        $get_image = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? }
        
        // Image-related strings
        $img_str1 = "GetImageFromUrl" ascii
        $img_str2 = "image/jpeg" ascii
        $img_str3 = "image/png" ascii
        $img_str4 = ".jpg" ascii
        $img_str5 = ".png" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        1 of ($img_proc*) and
        $get_image and
        2 of ($img_str*)
}

rule Kaolin_RAT_Package_Cache_Folders {
    meta:
        description = "Detects Package Cache folder creation used in Kaolin RAT's RollSling loader"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "e68ff1087c45a1711c3037dad427733ccb1211634d070b03cb3a3c7e836d210f"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    strings:
        // Package Cache folder strings
        $folder1 = "Package Cache" ascii wide
        $folder2 = "-DF09-AA86-YI78-" ascii wide
        $folder3 = "-09C7-886E-II7F-" ascii wide
        $folder4 = ".cab" ascii wide
        
        // CreateDirectory function calls
        $create_dir = { 6A 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? }
        
    condition:
        uint16(0) == 0x5A4D and
        2 of ($folder*) and
        $create_dir
}

rule Kaolin_RAT_Complete {
    meta:
        description = "Comprehensive rule to detect Kaolin RAT based on multiple code patterns"
        author = "Security Researcher"
        date = "2024-05-07"
        hash = "a75399f9492a8d2683d4406fa3e1320e84010b3affdff0b8f2444ac33ce3e690"
        reference = "https://decoded.avast.io/luiginocamastra/from-byovd-to-a-0-day-unveiling-advanced-exploits-in-cyber-recruiting-scams/"
    
    condition:
        uint16(0) == 0x5A4D and
        (
            Kaolin_RAT_SMBIOS_Retrieval or
            Kaolin_RAT_XOR_Decryption or
            Kaolin_RAT_Binary_Blob_Parser or
            Kaolin_RAT_Dictionary_Generation or
            Kaolin_RAT_AES_Decryption or
            Kaolin_RAT_Command_Handler or
            Kaolin_RAT_C2_Communication or
            Kaolin_RAT_Steganography or
            Kaolin_RAT_Package_Cache_Folders
        )
}
