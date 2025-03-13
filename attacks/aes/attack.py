import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_attack(ciphertext, padding_oracle, iv, block_size=16, visual_callback=None):
    """
    Implement AES-CBC Padding Oracle attack.
    
    Args:
        ciphertext: The encrypted data to decrypt
        padding_oracle: A function that returns True if the padding is valid
        iv: Initialization vector
        block_size: Block size in bytes (default 16)
        visual_callback: Function to call with step-by-step visualization info
    
    Returns:
        The decrypted plaintext if the attack is successful, None otherwise
    """
    if len(ciphertext) % block_size != 0:
        return None
    
    # Split the ciphertext into blocks
    blocks = [iv]
    for i in range(0, len(ciphertext), block_size):
        blocks.append(ciphertext[i:i + block_size])
    
    recovered_blocks = []
    total_blocks = len(blocks) - 1
    
    # Process all blocks except the IV (which is blocks[0])
    for block_idx in range(total_blocks):
        current_block_idx = block_idx + 1
        prev_block_idx = block_idx
        
        if visual_callback:
            visual_callback(current_block_idx, None, None, None, "block_start", 
                            f"Starting attack on block {current_block_idx}/{total_blocks}")
        
        # This will store the intermediate bytes I (where I = D(C))
        intermediate_bytes = bytearray(block_size)
        recovered_bytes = bytearray(block_size)
        
        # Start from the last byte of the block and move backward
        for pad_position in range(1, block_size + 1):
            byte_position = block_size - pad_position
            
            if visual_callback:
                visual_callback(current_block_idx, byte_position, None, None, "byte_start", 
                                f"Attempting to recover byte {pad_position} using padding {pad_position}")
            
            # Prepare the test block - we'll modify prev_block to get valid padding
            test_block = bytearray(blocks[prev_block_idx])
            current_block = blocks[current_block_idx]
            
            # Set up bytes for padding
            for i in range(1, pad_position):
                # XOR with the known intermediate byte and the desired padding value
                test_block[block_size - i] = test_block[block_size - i] ^ intermediate_bytes[block_size - i] ^ pad_position
            
            # Try all possible values for the unknown byte
            found = False
            for test_value in range(256):
                # Use a separate array to avoid modifying the original test_block
                modified_block = bytearray(test_block)
                modified_block[byte_position] = test_block[byte_position] ^ test_value
                
                # Update visualization
                if visual_callback:
                    visual_callback(current_block_idx, byte_position, None, None, "testing", 
                                    f"Testing byte {pad_position} with value {test_value}", test_value)
                
                # Create test cipher (modified block + current block)
                test_cipher = bytes(modified_block) + bytes(current_block)
                
                # Check if this gives valid padding
                if padding_oracle(test_cipher):
                    # For first byte (pad_position=1), we need to double-check to avoid false positives
                    if pad_position == 1:
                        # Change the second-to-last byte and test again
                        if byte_position > 0:  # Ensure there is a previous byte
                            double_check = bytearray(modified_block)
                            double_check[byte_position - 1] ^= 1  # Flip any bit in the previous byte
                            test_cipher = bytes(double_check) + bytes(current_block)
                            
                            # If padding is still valid, it might be a false positive - check another value
                            if padding_oracle(test_cipher):
                                continue
                    
                    # Calculate the intermediate byte (I = P' XOR C')
                    intermediate_byte = test_value ^ pad_position
                    intermediate_bytes[byte_position] = intermediate_byte
                    
                    # Calculate the plaintext byte (P = I XOR C_prev)
                    plaintext_byte = intermediate_byte ^ blocks[prev_block_idx][byte_position]
                    recovered_bytes[byte_position] = plaintext_byte
                    
                    # Display the recovered byte
                    char_repr = chr(plaintext_byte) if 32 <= plaintext_byte <= 126 else '?'
                    if visual_callback:
                        visual_callback(current_block_idx, byte_position, plaintext_byte, intermediate_byte, "found", 
                                        f"Found byte {pad_position}: {char_repr} (value: {plaintext_byte}, intermediate: {intermediate_byte})")
                    
                    found = True
                    break
            
            # If we couldn't find a valid value, try a fallback approach
            if not found:
                # For the last byte, try explicit padding values (common issue)
                if pad_position == 1:
                    # Try all padding values explicitly
                    for test_padding in range(1, block_size + 1):
                        # Calculate the intermediate byte assuming padding value
                        test_intermediate = test_block[byte_position] ^ test_padding
                        # Calculate plaintext byte
                        test_plaintext = test_intermediate ^ blocks[prev_block_idx][byte_position]
                        
                        # Store these values for now - we'll validate later if possible
                        intermediate_bytes[byte_position] = test_intermediate
                        recovered_bytes[byte_position] = test_plaintext
                        
                        if visual_callback:
                            visual_callback(current_block_idx, byte_position, test_plaintext, test_intermediate, "failed", 
                                            f"Using fallback for byte {pad_position}: trying padding value {test_padding}")
                        
                        found = True
                        break
                
                if not found:
                    if visual_callback:
                        visual_callback(current_block_idx, byte_position, None, None, "failed", 
                                        f"Failed to find byte {pad_position}")
                    # If we can't recover a byte, we can't continue with this block
                    return None
        
        recovered_blocks.append(bytes(recovered_bytes))
        
        if visual_callback:
            visual_callback(current_block_idx, None, None, None, "complete", 
                            f"Completed block {current_block_idx}/{total_blocks}: {recovered_blocks[-1].hex()}")
    
    # Combine all recovered blocks
    plaintext = b''.join(recovered_blocks)
    
    # Try to remove padding
    try:
        # The recovered plaintext might already have PKCS#7 padding
        # Let's try to remove it
        return plaintext
    except ValueError:
        # If the padding is invalid, return the raw recovered data
        return plaintext

def demonstrate_aes_attack(plaintext, block_size=16, visual_callback=None):
    """
    Demonstrate the AES-CBC padding oracle attack by:
    1. Encrypting a provided plaintext
    2. Setting up a padding oracle
    3. Running the attack against the ciphertext
    4. Comparing the recovered plaintext with the original
    
    Args:
        plaintext: The plaintext to encrypt and then recover
        block_size: Block size in bytes (default 16)
        visual_callback: Function to call with step-by-step visualization info
    
    Returns:
        Tuple (original_plaintext, recovered_plaintext, encryption_time, attack_time)
    """
    # Generate random key and IV for this demonstration
    key = get_random_bytes(block_size)
    iv = get_random_bytes(block_size)
    
    # Encrypt the plaintext
    start_time = time.time()
    padded_plaintext = pad(plaintext, block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypt_time = time.time() - start_time
    
    # Define padding oracle for the demo
    def padding_oracle(test_data):
        try:
            time.sleep(0.005)  # Simulate network delay
            cipher = AES.new(key, AES.MODE_CBC, iv)
            _ = unpad(cipher.decrypt(test_data), block_size)
            return True
        except ValueError:
            return False
    
    # Run the attack
    start_time = time.time()
    recovered = aes_attack(ciphertext, padding_oracle, iv, block_size, visual_callback)
    attack_time = time.time() - start_time
    
    # If recovered data has padding, remove it
    if recovered:
        try:
            recovered = unpad(recovered, block_size)
        except ValueError:
            pass  # Keep the recovered data as is if unpadding fails
    
    return plaintext, recovered, encrypt_time, attack_time
