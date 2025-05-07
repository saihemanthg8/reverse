#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <windows.h>

/**
 * Kaolin RAT XOR Decryption Tool
 * 
 * This tool demonstrates the XOR decryption routine used in the Kaolin RAT malware
 * to decrypt the next stage payload using SMBIOS data as the key.
 * 
 * Author: Security Researcher
 * Date: May 2024
 */

// Function to retrieve SMBIOS data (similar to what the malware does)
std::vector<uint8_t> GetSMBIOSData() {
    std::vector<uint8_t> smbiosData;
    
    // Get the size of the SMBIOS table
    DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size == 0) {
        std::cerr << "Failed to get SMBIOS table size. Error: " << GetLastError() << std::endl;
        return smbiosData;
    }
    
    // Allocate buffer for the SMBIOS table
    smbiosData.resize(size);
    
    // Get the SMBIOS table
    DWORD result = GetSystemFirmwareTable('RSMB', 0, smbiosData.data(), size);
    if (result == 0) {
        std::cerr << "Failed to get SMBIOS table. Error: " << GetLastError() << std::endl;
        smbiosData.clear();
        return smbiosData;
    }
    
    // Ensure we got the expected size
    if (result != size) {
        std::cerr << "Warning: Requested " << size << " bytes but got " << result << " bytes" << std::endl;
        smbiosData.resize(result);
    }
    
    return smbiosData;
}

// Function to extract a 32-byte key from SMBIOS data (similar to what the malware does)
std::vector<uint8_t> ExtractKeyFromSMBIOS(const std::vector<uint8_t>& smbiosData) {
    std::vector<uint8_t> key;
    
    // The malware extracts a 32-byte key from specific offsets in the SMBIOS data
    // This is a simplified version that just takes the first 32 bytes
    // In reality, the malware might use a more complex algorithm
    
    if (smbiosData.size() >= 32) {
        key.assign(smbiosData.begin(), smbiosData.begin() + 32);
    } else {
        // If SMBIOS data is smaller than 32 bytes, pad with zeros
        key.assign(smbiosData.begin(), smbiosData.end());
        key.resize(32, 0);
    }
    
    return key;
}

// XOR decryption function (identical to what the malware uses)
void XorDecrypt(uint8_t* data, size_t dataSize, const uint8_t* key, size_t keySize) {
    for (size_t i = 0; i < dataSize; i++) {
        data[i] ^= key[i % keySize];
    }
}

// Function to read a file into a vector
std::vector<uint8_t> ReadFile(const std::string& filePath) {
    std::vector<uint8_t> data;
    std::ifstream file(filePath, std::ios::binary);
    
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return data;
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Read file content
    data.resize(fileSize);
    file.read(reinterpret_cast<char*>(data.data()), fileSize);
    
    return data;
}

// Function to write a vector to a file
bool WriteFile(const std::string& filePath, const std::vector<uint8_t>& data) {
    std::ofstream file(filePath, std::ios::binary);
    
    if (!file) {
        std::cerr << "Failed to create file: " << filePath << std::endl;
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

// Function to print a hex dump of data
void PrintHexDump(const std::vector<uint8_t>& data, size_t maxBytes = 256) {
    size_t bytesToPrint = std::min(data.size(), maxBytes);
    
    for (size_t i = 0; i < bytesToPrint; i += 16) {
        // Print offset
        std::cout << std::setfill('0') << std::setw(8) << std::hex << i << "  ";
        
        // Print hex values
        for (size_t j = 0; j < 16; j++) {
            if (i + j < bytesToPrint) {
                std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(data[i + j]) << " ";
            } else {
                std::cout << "   ";
            }
            
            if (j == 7) {
                std::cout << " ";
            }
        }
        
        // Print ASCII representation
        std::cout << " |";
        for (size_t j = 0; j < 16; j++) {
            if (i + j < bytesToPrint) {
                char c = data[i + j];
                if (c >= 32 && c <= 126) {
                    std::cout << c;
                } else {
                    std::cout << ".";
                }
            } else {
                std::cout << " ";
            }
        }
        std::cout << "|" << std::endl;
    }
    
    if (data.size() > maxBytes) {
        std::cout << "... (showing " << maxBytes << " of " << data.size() << " bytes)" << std::endl;
    }
    
    std::cout << std::dec;  // Reset to decimal output
}

// Function to check if a buffer contains a valid PE file
bool IsPEFile(const std::vector<uint8_t>& data) {
    if (data.size() < 64) {
        return false;
    }
    
    // Check for MZ header
    if (data[0] != 'M' || data[1] != 'Z') {
        return false;
    }
    
    // Get PE header offset
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    
    // Check if PE offset is valid
    if (peOffset >= data.size() - 4) {
        return false;
    }
    
    // Check for PE signature
    if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || 
        data[peOffset + 2] != 0 || data[peOffset + 3] != 0) {
        return false;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "Kaolin RAT XOR Decryption Tool" << std::endl;
    std::cout << "===============================" << std::endl << std::endl;
    
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <encrypted_file> <output_file> [key_file]" << std::endl;
        std::cout << "  If key_file is not provided, SMBIOS data will be used as the key" << std::endl;
        return 1;
    }
    
    std::string encryptedFilePath = argv[1];
    std::string outputFilePath = argv[2];
    std::string keyFilePath = (argc > 3) ? argv[3] : "";
    
    // Read encrypted file
    std::cout << "Reading encrypted file: " << encryptedFilePath << std::endl;
    std::vector<uint8_t> encryptedData = ReadFile(encryptedFilePath);
    if (encryptedData.empty()) {
        std::cerr << "Error: Failed to read encrypted file or file is empty" << std::endl;
        return 1;
    }
    
    std::cout << "Read " << encryptedData.size() << " bytes from encrypted file" << std::endl;
    
    // Get decryption key
    std::vector<uint8_t> key;
    if (!keyFilePath.empty()) {
        // Use provided key file
        std::cout << "Reading key from file: " << keyFilePath << std::endl;
        key = ReadFile(keyFilePath);
        if (key.empty()) {
            std::cerr << "Error: Failed to read key file or file is empty" << std::endl;
            return 1;
        }
    } else {
        // Use SMBIOS data as key
        std::cout << "Retrieving SMBIOS data for key..." << std::endl;
        std::vector<uint8_t> smbiosData = GetSMBIOSData();
        if (smbiosData.empty()) {
            std::cerr << "Error: Failed to retrieve SMBIOS data" << std::endl;
            return 1;
        }
        
        std::cout << "Retrieved " << smbiosData.size() << " bytes of SMBIOS data" << std::endl;
        key = ExtractKeyFromSMBIOS(smbiosData);
    }
    
    std::cout << "Using " << key.size() << " byte key:" << std::endl;
    PrintHexDump(key);
    
    // Create a copy of the encrypted data for decryption
    std::vector<uint8_t> decryptedData = encryptedData;
    
    // Decrypt the data
    std::cout << "\nDecrypting data..." << std::endl;
    XorDecrypt(decryptedData.data(), decryptedData.size(), key.data(), key.size());
    
    // Check if the decrypted data looks valid
    bool isPE = IsPEFile(decryptedData);
    std::cout << "Decryption " << (isPE ? "successful" : "may have failed") << std::endl;
    
    if (isPE) {
        std::cout << "Decrypted data appears to be a valid PE file" << std::endl;
    } else {
        std::cout << "Warning: Decrypted data does not appear to be a valid PE file" << std::endl;
        std::cout << "This could indicate an incorrect key or non-PE payload" << std::endl;
    }
    
    // Print a hex dump of the decrypted data
    std::cout << "\nFirst bytes of decrypted data:" << std::endl;
    PrintHexDump(decryptedData);
    
    // Write decrypted data to output file
    std::cout << "\nWriting decrypted data to: " << outputFilePath << std::endl;
    if (WriteFile(outputFilePath, decryptedData)) {
        std::cout << "Successfully wrote " << decryptedData.size() << " bytes to output file" << std::endl;
    } else {
        std::cerr << "Error: Failed to write to output file" << std::endl;
        return 1;
    }
    
    return 0;
}
