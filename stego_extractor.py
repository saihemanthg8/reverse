#!/usr/bin/env python3
"""
Kaolin RAT Steganography Extractor

This script demonstrates how to extract hidden data from images used in 
Kaolin RAT C2 communications. The malware uses steganography to hide 
C2 server addresses and other configuration data in image files.

Usage:
    python stego_extractor.py <image_file>

Author: Security Researcher
Date: May 2024
"""

import sys
import os
import argparse
from PIL import Image
import numpy as np
import binascii
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def extract_lsb(image_path):
    """
    Extract the least significant bits from an image.
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        bytes: Extracted hidden data
    """
    try:
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Extract LSB from each pixel
        hidden_bits = []
        for row in img_array:
            for pixel in row:
                # Handle both RGB and RGBA images
                for i in range(min(3, len(pixel))):  # Only use RGB channels, ignore alpha
                    hidden_bits.append(pixel[i] & 1)  # Extract LSB
        
        # Convert bits to bytes
        hidden_bytes = []
        for i in range(0, len(hidden_bits), 8):
            if i + 8 <= len(hidden_bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | hidden_bits[i + j]
                hidden_bytes.append(byte)
        
        return bytes(hidden_bytes)
    
    except Exception as e:
        print(f"Error extracting LSB data: {e}")
        return None

def find_patterns(data):
    """
    Look for common patterns in the extracted data.
    
    Args:
        data (bytes): Extracted data
        
    Returns:
        dict: Dictionary of identified patterns
    """
    patterns = {
        'urls': [],
        'base64': [],
        'hex_strings': [],
        'ascii_strings': []
    }
    
    # Convert to string for pattern matching
    data_str = data.decode('latin-1')
    
    # Look for URL patterns
    url_patterns = ['http://', 'https://', 'www.']
    for pattern in url_patterns:
        start_idx = 0
        while True:
            start_idx = data_str.find(pattern, start_idx)
            if start_idx == -1:
                break
            
            # Find the end of the URL (space, null byte, or non-printable char)
            end_idx = start_idx
            while end_idx < len(data_str) and data_str[end_idx].isprintable() and data_str[end_idx] not in [' ', '\t', '\r', '\n']:
                end_idx += 1
            
            url = data_str[start_idx:end_idx]
            if url and url not in patterns['urls']:
                patterns['urls'].append(url)
            
            start_idx = end_idx
    
    # Look for base64 patterns (long strings of base64 characters)
    base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    start_idx = 0
    while start_idx < len(data_str):
        # Find a potential base64 string
        while start_idx < len(data_str) and data_str[start_idx] not in base64_chars:
            start_idx += 1
        
        if start_idx >= len(data_str):
            break
        
        # Find the end of the base64 string
        end_idx = start_idx
        while end_idx < len(data_str) and data_str[end_idx] in base64_chars:
            end_idx += 1
        
        # Check if it's a valid base64 string (at least 16 chars)
        if end_idx - start_idx >= 16:
            b64_str = data_str[start_idx:end_idx]
            # Try to decode it to verify it's valid base64
            try:
                decoded = base64.b64decode(b64_str)
                patterns['base64'].append(b64_str)
            except:
                pass
        
        start_idx = end_idx + 1
    
    # Look for ASCII strings (at least 4 printable chars)
    start_idx = 0
    while start_idx < len(data_str):
        # Find the start of a printable string
        while start_idx < len(data_str) and not data_str[start_idx].isprintable():
            start_idx += 1
        
        if start_idx >= len(data_str):
            break
        
        # Find the end of the printable string
        end_idx = start_idx
        while end_idx < len(data_str) and data_str[end_idx].isprintable():
            end_idx += 1
        
        # Check if it's a meaningful string (at least 4 chars)
        if end_idx - start_idx >= 4:
            ascii_str = data_str[start_idx:end_idx]
            patterns['ascii_strings'].append(ascii_str)
        
        start_idx = end_idx + 1
    
    # Look for hex strings (at least 8 hex chars)
    hex_chars = set('0123456789abcdefABCDEF')
    start_idx = 0
    while start_idx < len(data_str):
        # Find the start of a hex string
        while start_idx < len(data_str) and data_str[start_idx] not in hex_chars:
            start_idx += 1
        
        if start_idx >= len(data_str):
            break
        
        # Find the end of the hex string
        end_idx = start_idx
        while end_idx < len(data_str) and data_str[end_idx] in hex_chars:
            end_idx += 1
        
        # Check if it's a meaningful hex string (at least 8 chars)
        if end_idx - start_idx >= 8 and (end_idx - start_idx) % 2 == 0:
            hex_str = data_str[start_idx:end_idx]
            patterns['hex_strings'].append(hex_str)
        
        start_idx = end_idx + 1
    
    return patterns

def try_aes_decrypt(data, key_candidates=None):
    """
    Attempt to decrypt data using AES with candidate keys.
    
    Args:
        data (bytes): Data to decrypt
        key_candidates (list): List of candidate keys to try
        
    Returns:
        list: List of successful decryptions
    """
    results = []
    
    # If no key candidates provided, use some common ones
    if not key_candidates:
        # First 32 bytes might be the key
        key_candidates = [data[:32], data[:16]]
        
        # Add some common Lazarus keys (placeholder)
        key_candidates.append(bytes.fromhex('0123456789abcdef0123456789abcdef'))
    
    # Try each base64 string as potential encrypted data
    patterns = find_patterns(data)
    for b64_str in patterns['base64']:
        try:
            encrypted_data = base64.b64decode(b64_str)
            
            # Try each key candidate
            for key in key_candidates:
                if len(key) not in [16, 24, 32]:
                    continue
                
                # Try different IV sizes
                iv_sizes = [16]
                for iv_size in iv_sizes:
                    # Try using the first iv_size bytes as IV
                    for i in range(len(encrypted_data) - iv_size):
                        iv = encrypted_data[i:i+iv_size]
                        
                        try:
                            cipher = AES.new(key, AES.MODE_CBC, iv)
                            decrypted = unpad(cipher.decrypt(encrypted_data[i+iv_size:]), AES.block_size)
                            
                            # Check if decryption looks valid (contains printable ASCII)
                            printable_ratio = sum(1 for c in decrypted if 32 <= c <= 126) / len(decrypted)
                            if printable_ratio > 0.7:
                                results.append({
                                    'key': binascii.hexlify(key).decode(),
                                    'iv': binascii.hexlify(iv).decode(),
                                    'decrypted': decrypted.decode('utf-8', errors='ignore')
                                })
                        except:
                            pass
        except:
            pass
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Extract hidden data from images used in Kaolin RAT C2 communications')
    parser.add_argument('image_file', help='Path to the image file')
    parser.add_argument('-o', '--output', help='Output file for extracted data')
    parser.add_argument('-a', '--analyze', action='store_true', help='Analyze extracted data for patterns')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Attempt to decrypt extracted data')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image_file):
        print(f"Error: Image file '{args.image_file}' not found")
        return 1
    
    print(f"[+] Extracting hidden data from {args.image_file}...")
    hidden_data = extract_lsb(args.image_file)
    
    if not hidden_data:
        print("[-] No hidden data extracted or extraction failed")
        return 1
    
    print(f"[+] Extracted {len(hidden_data)} bytes of hidden data")
    
    # Save extracted data if output file specified
    if args.output:
        with open(args.output, 'wb') as f:
            f.write(hidden_data)
        print(f"[+] Saved extracted data to {args.output}")
    
    # Analyze extracted data if requested
    if args.analyze:
        print("\n[+] Analyzing extracted data for patterns...")
        patterns = find_patterns(hidden_data)
        
        if patterns['urls']:
            print("\n[+] Found potential URLs:")
            for url in patterns['urls']:
                print(f"    {url}")
        
        if patterns['base64']:
            print("\n[+] Found potential base64 strings:")
            for b64 in patterns['base64'][:5]:  # Show only first 5
                print(f"    {b64[:50]}..." if len(b64) > 50 else f"    {b64}")
            if len(patterns['base64']) > 5:
                print(f"    ... and {len(patterns['base64']) - 5} more")
        
        if patterns['hex_strings']:
            print("\n[+] Found potential hex strings:")
            for hex_str in patterns['hex_strings'][:5]:  # Show only first 5
                print(f"    {hex_str[:50]}..." if len(hex_str) > 50 else f"    {hex_str}")
            if len(patterns['hex_strings']) > 5:
                print(f"    ... and {len(patterns['hex_strings']) - 5} more")
        
        if patterns['ascii_strings']:
            print("\n[+] Found potential ASCII strings:")
            for ascii_str in patterns['ascii_strings'][:10]:  # Show only first 10
                if len(ascii_str) > 50:
                    print(f"    {ascii_str[:50]}...")
                else:
                    print(f"    {ascii_str}")
            if len(patterns['ascii_strings']) > 10:
                print(f"    ... and {len(patterns['ascii_strings']) - 10} more")
    
    # Attempt decryption if requested
    if args.decrypt:
        print("\n[+] Attempting to decrypt data with AES...")
        decryption_results = try_aes_decrypt(hidden_data)
        
        if decryption_results:
            print(f"[+] Found {len(decryption_results)} potential decryptions:")
            for i, result in enumerate(decryption_results):
                print(f"\n--- Decryption #{i+1} ---")
                print(f"Key: {result['key']}")
                print(f"IV: {result['iv']}")
                print(f"Decrypted data (first 100 chars): {result['decrypted'][:100]}")
        else:
            print("[-] No successful decryptions found")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
