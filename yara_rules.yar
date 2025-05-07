/*
   Kaolin RAT and Associated Components YARA Rules
   Author: Security Researcher
   Date: 2024-05-01
   
   These rules are designed to detect various components of the Kaolin RAT
   attack chain attributed to the North Korean Lazarus APT group.
*/

import "pe"

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
        $smbios1 = "GetSystemFirmwareTable" ascii wide
        $smbios2 = "RSMB" ascii wide
        $xor_decrypt = { 33 ?? 88 ?? 41 4? 75 ?? }
        
    condition:
        uint16(0) == 0x5A4D and all of them and
        pe.imports("kernel32.dll", "GetSystemFirmwareTable")
}

rule RollSling_Loader {
    meta:
        description = "Detects RollSling loader used in Kaolin RAT attack chain"
        author = "Security Researcher"
        date = "2024-05-01"
        hash = "e68ff1087c45a1711c3037dad427733ccb1211634d070b03cb3a3c7e836d210f"
    
    strings:
        $export = "StartAction" ascii wide
        $folder1 = "Package Cache" ascii wide
        $folder2 = "-DF09-AA86-YI78-" ascii wide
        $folder3 = "-09C7-886E-II7F-" ascii wide
        $mz_check = { 81 ?? ?? ?? 4D 5A }
        
    condition:
        uint16(0) == 0x5A4D and
        $export and $mz_check and
        2 of ($folder*)
}

rule RollMid_Loader {
    meta:
        description = "Detects RollMid loader used in Kaolin RAT attack chain"
        author = "Security Researcher"
        date = "2024-05-01"
        hash = "9a4bc647c09775ed633c134643d18a0be8f37c21afa3c0f8adf41e038695643e"
    
    strings:
        $curl1 = "curl_global_init" ascii wide
        $curl2 = "curl_global_cleanup" ascii wide
        $url1 = "GetHtmlFromUrl" ascii wide
        $url2 = "GetImageFromUrl" ascii wide
        $url3 = "SendDataFromUrl" ascii wide
        $decrypt = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? }
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($curl*) or 2 of ($url*)) and
        $decrypt
}

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

rule Lazarus_ISO_Dropper {
    meta:
        description = "Detects ISO files used in Lazarus Kaolin RAT attacks"
        author = "Security Researcher"
        date = "2024-05-01"
        hash = "b8a4c1792ce2ec15611932437a4a1a7e43b7c3783870afebf6eae043bcfade30"
    
    strings:
        $iso1 = "AmazonVNC.exe" ascii wide
        $iso2 = "version.dll" ascii wide
        $iso3 = "aws.cfg" ascii wide
        
    condition:
        all of them and
        uint32(0) == 0x0000001 and uint32(4) == 0x0000008
}

rule Lazarus_DLL_Sideloading {
    meta:
        description = "Detects DLL sideloading technique used in Kaolin RAT attacks"
        author = "Security Researcher"
        date = "2024-05-01"
    
    strings:
        $syscall1 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        $syscall2 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        $av_check = "Kaspersky" ascii wide nocase
        $process = "iexpress.exe" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        pe.exports("DllMain") and
        (all of ($syscall*) or ($av_check and $process))
}

rule Lazarus_Steganography {
    meta:
        description = "Detects steganography techniques used in Kaolin RAT attacks"
        author = "Security Researcher"
        date = "2024-05-01"
    
    strings:
        $img1 = "GetImageFromUrl" ascii wide
        $img2 = { 89 ?? ?? 8B ?? ?? 83 ?? 01 83 ?? 01 }
        $img3 = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B ?? ?? 89 ?? ?? }
        
    condition:
        $img1 and any of ($img2, $img3)
}

rule Lazarus_Dictionary_URL_Generation {
    meta:
        description = "Detects dictionary-based URL generation used in Kaolin RAT attacks"
        author = "Security Researcher"
        date = "2024-05-01"
    
    strings:
        $dict_fill = { 83 C0 04 89 45 ?? 8B 45 ?? 8B 00 89 45 ?? 8B 45 ?? 83 C0 04 89 45 ?? }
        $url_gen1 = { 8B ?? ?? 03 ?? ?? 0F B6 00 }
        $url_gen2 = { 8D ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 }
        
    condition:
        $dict_fill and any of ($url_gen*)
}
