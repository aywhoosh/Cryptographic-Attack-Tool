#!/usr/bin/env python3
import sys
from .settings import *
from .oracle import oracle

def poc(encrypted):
    block_number = len(encrypted)//BYTE_NB
    decrypted = bytes()
    
    # Go through each block
    for i in range(block_number, 0, -1):
        current_encrypted_block = encrypted[(i-1)*BYTE_NB:(i)*BYTE_NB]
        # At the first encrypted block, use the initialization vector
        if(i == 1):
            previous_encrypted_block = bytearray(IV)
        else:
            previous_encrypted_block = encrypted[(i-2)*BYTE_NB:(i-1)*BYTE_NB]
        bruteforce_block = previous_encrypted_block
        current_decrypted_block = bytearray(IV)
        padding = 0
        
        # Go through each byte of the block
        for j in range(BYTE_NB, 0, -1):
            padding += 1
            # Bruteforce byte value
            for value in range(0,256):
                bruteforce_block = bytearray(bruteforce_block)
                bruteforce_block[j-1] = (bruteforce_block[j-1] + 1) % 256
                joined_encrypted_block = bytes(bruteforce_block) + current_encrypted_block
                # Ask the oracle
                if(oracle(joined_encrypted_block)):
                    current_decrypted_block[-padding] = bruteforce_block[-padding] ^ previous_encrypted_block[-padding] ^ padding
                    # Prepare newly found byte values
                    for k in range(1, padding+1):
                        bruteforce_block[-k] = padding+1 ^ current_decrypted_block[-k] ^ previous_encrypted_block[-k]
                    break
        decrypted = bytes(current_decrypted_block) + bytes(decrypted)
    return decrypted[:-decrypted[-1]]  # Padding removal