#!/usr/bin/env python3

'''
Parts of this code are contributed by Aditya Jain.
Some elements of the code here are directly from 
their contribution. Other parts take some of the original
logic, and others are mine own, modified for our task.
It has been posted on the Geeks For Geeks website.

It can be found at the following link: 
https://www.geeksforgeeks.org/data-encryption-standard-des-set-1/

The original code, posted by the contributor, has been
modified in various ways by myself, Matthew Turzai, in
order to perform a DES decryption. I use the original
work with citation, acknowledgement, caution.

'''
# Modified DES implementation for the given problem

# Helper functions for binary operations

def permute(k, arr, n):
    """Permute function to rearrange the bits"""
    permutation = ""
    for i in range(0, n):
        permutation = permutation + k[arr[i] - 1]
    return permutation

def shift_left(k, nth_shifts):
    """Shifting the bits towards left by nth shifts"""
    s = ""
    for i in range(nth_shifts):
        for j in range(1, len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k

def xor(a, b):
    """XOR of two binary strings"""
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

def bin2dec(binary_str):
    """Binary string to decimal conversion"""
    return int(binary_str, 2)

def dec2bin(num, padding=4):
    """Decimal to binary conversion with padding"""
    binary = bin(num)[2:]
    return binary.zfill(padding)

# DES Algorithm Tables

# Initial Permutation Table
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation Table
per = [16, 7, 20, 21, 29, 12, 28, 17,
       1, 15, 23, 26, 5, 18, 31, 10,
       2, 8, 24, 14, 32, 27, 3, 9,
       19, 13, 30, 6, 22, 11, 4, 25]

# S-box Table
sbox = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Final Permutation Table
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

# Parity bit drop table for key generation
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Number of bit shifts
shift_table = [1, 1, 2, 2, 2, 2, 2, 2,
               1, 2, 2, 2, 2, 2, 2, 1]

# Key Compression Table
key_comp = [14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32]

def process_sbox(expanded_xor):
    """Process S-box substitution"""
    sbox_str = ""
    for j in range(0, 8):
        chunk = expanded_xor[j * 6:j * 6 + 6]
        row = bin2dec(chunk[0] + chunk[5])
        col = bin2dec(chunk[1:5])
        val = sbox[j][row][col]
        sbox_str += dec2bin(val)
    return sbox_str

def f_function(right, round_key):
    """Feistel function used in each round"""
    # Expansion: 32 bits to 48 bits
    right_expanded = permute(right, exp_d, 48)
    
    # XOR with round key
    xor_result = xor(right_expanded, round_key)
    
    # S-box substitution: 48 bits to 32 bits
    sbox_result = process_sbox(xor_result)
    
    # Permutation: rearranging the bits
    f_result = permute(sbox_result, per, 32)
    
    return f_result, right_expanded, xor_result, sbox_result

def des_decrypt(ciphertext, key):
    """Decrypt using DES algorithm and show all intermediary steps"""
    # Generate round keys
    round_keys = generate_round_keys(key)
    
    # Apply initial permutation
    ciphertext_ip = permute(ciphertext, initial_perm, 64)
    print(f"After initial permutation: {ciphertext_ip}")
    
    # Split into left and right halves
    left = ciphertext_ip[:32]
    right = ciphertext_ip[32:]
    
    print("\nDecryption Process:")
    print(f"Initial L0: {left}")
    print(f"Initial R0: {right}")
    
    # Store all intermediate values
    l_values = [left]
    r_values = [right]
    f_outputs = []
    expansion_outputs = []
    xor_outputs = []
    sbox_outputs = []
    
    # Process 16 rounds in reverse (for decryption)
    for i in range(16):
        # Get round key (in reverse order for decryption)
        round_key = round_keys[15 - i]
        
        # Save previous right as new left
        new_left = right
        
        # Apply f function to right half and round key
        f_result, expanded, xor_result, sbox_result = f_function(right, round_key)
        
        # XOR f result with left half to get new right
        new_right = xor(left, f_result)
        
        # Update for next round
        left = new_left
        right = new_right
        
        # Store intermediate values
        l_values.append(left)
        r_values.append(right)
        f_outputs.append(f_result)
        expansion_outputs.append(expanded)
        xor_outputs.append(xor_result)
        sbox_outputs.append(sbox_result)
        
        print(f"\nRound {i+1}:")
        print(f"Round Key K{i+1}: {round_key}")
        print(f"Expansion E(R{i}): {expanded}")
        print(f"XOR Result: {xor_result}")
        print(f"S-Box Output: {sbox_result}")
        print(f"f Function Output: {f_result}")
        print(f"L{i+1}: {left}")
        print(f"R{i+1}: {right}")
    
    # Combine final L16 and R16 (after swap)
    combined = right + left  # Note: R16 and L16 are swapped
    
    # Apply final permutation
    plaintext = permute(combined, final_perm, 64)
    
    # Convert binary to ASCII
    plaintext_ascii = binary_to_ascii(plaintext)
    
    print()
    print("Final Result:")
    print(f"Binary of Plaintext: {plaintext}")
    print(f"ASCII of Plaintext: {plaintext_ascii}")
    
    return plaintext, l_values, r_values, f_outputs, round_keys

def generate_round_keys(key):
    """Generate all 16 round keys from the initial key"""
    # Apply key permutation (PC-1)
    key = permute(key, keyp, 56)
    
    # Split into left and right halves
    left = key[:28]
    right = key[28:]
    
    round_keys = []
    print("\nRound Key Generation:")
    
    for i in range(16):
        # Perform left circular shift
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        
        # Combine left and right halves
        combined = left + right
        
        # Key compression (PC-2): 56 bits to 48 bits
        round_key = permute(combined, key_comp, 48)
        round_keys.append(round_key)
        
        print(f"Round Key K{i+1}: {round_key}")
    
    return round_keys

def binary_to_ascii(binary):
    """Convert binary string to ASCII text"""
    result = ""
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:  # Ensure complete byte
            result += chr(int(byte, 2))
    return result

# Test the decryption with the given values
ciphertext = "1100101011101101101000100110010101011111101101110011100001110011"
key = "0100110001001111010101100100010101000011010100110100111001000100"

# Run the decryption
plaintext, l_values, r_values, f_outputs, round_keys = des_decrypt(ciphertext, key)

# Summary of values through all rounds
print("the output of f function in each iteration, LnRn (1<=n<=16) in each iteration:")
print("Round | Left Half (Ln) | Right Half (Rn) | f(Rn-1, Kn)")
print()
print(f"0\t| {l_values[0]} | {r_values[0]} | N/A")
for i in range(16):
    print(f"{i+1}\t| {l_values[i+1]} | {r_values[i+1]} | {f_outputs[i]}")

print()

print('The 16 round keys:')
for i in range(16):
    print(round_keys[i])
