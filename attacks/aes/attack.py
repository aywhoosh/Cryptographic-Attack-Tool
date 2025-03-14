import os
import time
import threading
from queue import Queue
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_attack(ciphertext, padding_oracle, iv, block_size=16, visual_callback=None):
    """
    Implement AES-CBC Padding Oracle attack.
    
    Args:
        ciphertext (bytes): The encrypted data to decrypt.
        padding_oracle (function): Function that returns True if the padding is valid.
        iv (bytes): Initialization vector.
        block_size (int): Block size in bytes (default 16).
        visual_callback (function): Callback for step-by-step visualization.
    
    Returns:
        The decrypted plaintext if successful, or None.
    """
    # Ensure the ciphertext is properly padded
    if len(ciphertext) % 16 != 0:  # AES always requires 16-byte blocks
        padded_size = ((len(ciphertext) // 16) + 1) * 16
        ciphertext = pad(ciphertext, 16)
    
    # Split ciphertext into blocks
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    
    # Add IV as block[0] to make indexing easier
    blocks.insert(0, iv)
    total_blocks = len(blocks) - 1  # Actual ciphertext blocks (excluding IV)
    
    # Store recovered plaintext blocks
    plaintext_blocks = []
    
    # Create a queue for thread-safe communication
    result_queue = Queue()
    stop_event = threading.Event()

    def process_block(current_block_idx):
        try:
            target_block = blocks[current_block_idx]      # Block we're trying to decrypt
            previous_block = bytearray(blocks[current_block_idx-1])  # Block used for manipulation
            
            if visual_callback:
                visual_callback(current_block_idx, None, None, None, "block_start",
                              f"Starting attack on block {current_block_idx}/{total_blocks}")
            
            # Store intermediate state and recovered plaintext for this block
            intermediate_bytes = bytearray(block_size)
            plaintext_bytes = bytearray(block_size)
            
            # Work backwards through the bytes
            for padding_byte in range(1, block_size + 1):
                if stop_event.is_set():
                    return None
                    
                byte_pos = block_size - padding_byte  # Current byte position (0-indexed from start of block)
                
                if visual_callback:
                    visual_callback(current_block_idx, byte_pos, None, None, "byte_start",
                                  f"Recovering byte {padding_byte} with padding {padding_byte}")
                
                # Create test block based on previous block
                test_block = bytearray(previous_block)
                
                # Set padding for already-discovered bytes
                for i in range(byte_pos + 1, block_size):
                    test_block[i] = test_block[i] ^ intermediate_bytes[i] ^ padding_byte
                
                # Test all possible values for the current byte
                found = False
                candidate_values = []
                
                # First pass: collect all candidate values
                for test_byte in range(256):
                    if stop_event.is_set():
                        return None
                        
                    # Set the byte we're attacking
                    test_block[byte_pos] = test_block[byte_pos] ^ test_byte
                    
                    if visual_callback:
                        visual_callback(current_block_idx, byte_pos, None, None, "testing",
                                      f"Testing byte value {test_byte} at pad {padding_byte}", test_byte)
                    
                    # Check if padding is valid
                    test_input = bytes(test_block) + target_block
                    if padding_oracle(test_input):
                        candidate_values.append(test_byte)
                    
                    # Reset the byte for next test
                    test_block[byte_pos] = previous_block[byte_pos]
                
                # Process candidates and verify results
                if candidate_values:
                    if padding_byte == 1:
                        # Additional verification for padding=1
                        verified_values = []
                        for candidate in candidate_values:
                            if stop_event.is_set():
                                return None
                                
                            test_block[byte_pos] = test_block[byte_pos] ^ candidate
                            valid = True
                            
                            # Try invalidating the padding by modifying previous byte
                            if byte_pos > 0:
                                verifier = bytearray(test_block)
                                verifier[byte_pos-1] ^= 0xFF
                                if padding_oracle(bytes(verifier) + target_block):
                                    valid = False
                            
                            if valid:
                                verified_values.append(candidate)
                            test_block[byte_pos] = previous_block[byte_pos]
                        
                        if verified_values:
                            test_byte = verified_values[0]
                            found = True
                        elif candidate_values:
                            test_byte = candidate_values[0]
                            found = True
                    else:
                        test_byte = candidate_values[0]
                        found = True
                
                if found:
                    intermediate_byte = test_byte ^ padding_byte
                    intermediate_bytes[byte_pos] = intermediate_byte
                    plaintext_byte = intermediate_byte ^ previous_block[byte_pos]
                    plaintext_bytes[byte_pos] = plaintext_byte
                    
                    if visual_callback:
                        char_repr = chr(plaintext_byte) if 32 <= plaintext_byte <= 126 else '?'
                        visual_callback(current_block_idx, byte_pos, plaintext_byte, intermediate_byte, "found",
                                      f"Found byte {padding_byte}: {char_repr} (value: {plaintext_byte})")
            
            # Block completed
            result_queue.put((current_block_idx, bytes(plaintext_bytes)))
            if visual_callback:
                visual_callback(current_block_idx, None, None, None, "complete",
                              f"Completed block {current_block_idx}/{total_blocks}")
                              
        except Exception as e:
            result_queue.put((current_block_idx, None, str(e)))

    # Process blocks in separate threads
    threads = []
    for current_block_idx in range(1, len(blocks)):
        if stop_event.is_set():
            break
        
        thread = threading.Thread(target=process_block, args=(current_block_idx,))
        thread.daemon = True  # Make thread daemon so it exits when main thread exits
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    results = []
    try:
        # Collect results from queue
        for _ in range(len(threads)):
            result = result_queue.get()
            results.append(result)
            result_queue.task_done()
            
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=0.1)  # Short timeout to allow for cancellation
            
    except Exception as e:
        stop_event.set()  # Signal threads to stop
        raise e
    
    # Sort results by block index and combine
    results.sort(key=lambda x: x[0])
    plaintext_blocks = [result[1] for result in results if result[1] is not None]
    
    if len(plaintext_blocks) != total_blocks:
        return None
        
    # Combine all blocks
    plaintext = b''.join(plaintext_blocks)
    return plaintext

def demonstrate_aes_attack(plaintext_bytes, block_size=16, visual_callback=None):
    """
    Demonstrate the AES-CBC padding oracle attack with proper padding and threading support.
    
    Args:
        plaintext_bytes (bytes): Plaintext to encrypt.
        block_size (int): Block size in bytes.
        visual_callback (function): Callback for visualization.
    
    Returns:
        Tuple (original_plaintext, recovered_plaintext, encryption_time, attack_time).
    """
    # Ensure the plaintext is properly padded for AES
    padded_plaintext = pad(plaintext_bytes, 16)  # Always pad to 16 bytes for AES
    
    # Generate key and IV
    key = get_random_bytes(16)  # AES requires 16-byte key
    iv = get_random_bytes(16)   # AES requires 16-byte IV
    
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypt_time = time.time() - start_time
    
    def padding_oracle(test_data):
        """Thread-safe padding oracle"""
        try:
            time.sleep(0.005)  # Simulate network delay
            cipher = AES.new(key, AES.MODE_CBC, iv)
            _ = unpad(cipher.decrypt(test_data), block_size)  # Use provided block_size instead of hardcoded 16
            return True
        except ValueError:
            return False
    
    start_time = time.time()
    recovered = aes_attack(ciphertext, padding_oracle, iv, block_size, visual_callback)
    attack_time = time.time() - start_time
    
    if recovered:
        try:
            recovered = unpad(recovered, block_size)  # Use provided block_size instead of hardcoded 16
        except ValueError:
            pass  # Return the raw recovered data if unpadding fails
    
    return plaintext_bytes, recovered, encrypt_time, attack_time
