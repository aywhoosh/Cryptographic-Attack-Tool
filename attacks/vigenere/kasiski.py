import re
import math
from collections import Counter, defaultdict
import string

ENGLISH_FREQS = {
    'E': 0.1249, 'T': 0.0928, 'A': 0.0804, 'O': 0.0764, 'I': 0.0757,
    'N': 0.0723, 'S': 0.0651, 'R': 0.0628, 'H': 0.0505, 'L': 0.0407,
    'D': 0.0382, 'C': 0.0334, 'U': 0.0273, 'M': 0.0251, 'F': 0.0240,
    'P': 0.0214, 'G': 0.0187, 'W': 0.0168, 'Y': 0.0166, 'B': 0.0148,
    'V': 0.0105, 'K': 0.0054, 'X': 0.0023, 'J': 0.0016, 'Q': 0.0012,
    'Z': 0.0009
}

def find_repeated_sequences(text, min_length=3):
    """Find repeated sequences in text and their positions."""
    sequences = {}
    text_len = len(text)
    # Calculate appropriate maximum sequence length based on text length
    max_length = min(20, text_len // 3)
    
    # Start with longer sequences to find the most meaningful patterns
    for length in range(max_length, min_length - 1, -1):
        for i in range(text_len - length):
            seq = text[i:i+length]
            if seq in sequences:
                sequences[seq].append(i)
            else:
                # Look for all occurrences, not just the next one
                j = i + 1
                while True:
                    j = text.find(seq, j)
                    if j == -1:
                        break
                    if seq not in sequences:
                        sequences[seq] = [i, j]
                    else:
                        sequences[seq].append(j)
                    j += 1
    
    # Return sequences that appear at least twice
    return {seq: positions for seq, positions in sequences.items() if len(positions) >= 2}

def get_spacings(positions):
    """Calculate spacings between positions."""
    return [positions[i+1] - positions[i] for i in range(len(positions)-1)]

def get_factors(n):
    """Get all factors of a number."""
    # Handle edge cases to prevent math domain error
    if n <= 0:
        return []
    
    factors = []
    for i in range(1, int(math.sqrt(n)) + 1):
        if n % i == 0:
            factors.append(i)
            if i != n//i:
                factors.append(n//i)
    return sorted(factors)

def analyze_key_length(repeated_seqs):
    """Analyze possible key lengths from sequence spacings."""
    if not repeated_seqs:
        return None
        
    all_spacings = []
    
    # Extract all spacings between repeated sequences
    for seq, positions in repeated_seqs.items():
        spacings = get_spacings(positions)
        # Weight by sequence length (longer sequences are more significant)
        weight = len(seq)
        all_spacings.extend([s for s in spacings for _ in range(weight)])
    
    # Handle the case where we don't have enough spacings
    if len(all_spacings) < 1:
        # Try simple divisibility approach on text length
        return {i: 1 for i in range(2, 11)}
    
    # Count factor frequency
    factor_counts = defaultdict(float)
    total_spacings = len(all_spacings)
    
    # Process each spacing to find potential key lengths
    for spacing in all_spacings:
        factors = get_factors(spacing)
        # Avoid giving too much weight to numbers with many factors
        weight = 1.0 / (len(factors) or 1)  
        # Consider more reasonable key length range
        for factor in factors:
            if 2 <= factor <= 20:  # Allow key lengths from 2 to 20
                factor_counts[factor] += weight
    
    # If we found very few factors, be more lenient
    if len(factor_counts) < 3:
        # Include common key lengths with minimal weights
        for i in range(2, 11):
            if i not in factor_counts:
                factor_counts[i] = 0.1
    
    return factor_counts

def get_letter_frequency(text):
    """Get frequency analysis of letters in text."""
    freq = Counter(text)
    total = sum(freq.values())
    return {char: count/total for char, count in freq.items()}

def chi_squared_score(observed, expected=ENGLISH_FREQS):
    """Calculate chi-squared statistic for frequency comparison."""
    score = 0
    for letter in string.ascii_uppercase:
        o = observed.get(letter, 0)
        e = expected.get(letter, 0)
        if e > 0:
            score += ((o - e) ** 2) / e
    return score

def decrypt_vigenere(text, key):
    """Decrypt Vigenère cipher with given key."""
    plaintext = []
    key_len = len(key)
    for i, char in enumerate(text):
        if char in string.ascii_uppercase:
            p = (ord(char) - ord('A'))
            k = (ord(key[i % key_len]) - ord('A'))
            decrypted = chr(((p - k) % 26) + ord('A'))
            plaintext.append(decrypted)
        else:
            plaintext.append(char)
    return ''.join(plaintext)

def get_possible_keys(ciphertext, key_length):
    """Get possible encryption key for a given key length."""
    key = ''
    confidence_scores = []
    
    for i in range(key_length):
        key_char, confidence = find_key_segment_with_confidence(ciphertext, key_length, i)
        key += key_char
        confidence_scores.append(confidence)
    
    # If average confidence is too low, try with overlapping segments
    if sum(confidence_scores) / len(confidence_scores) < 0.6:
        overlapping_key = ''
        for i in range(key_length):
            # Use overlapping segments for better context
            extended_column = get_extended_column(ciphertext, key_length, i)
            key_char, _ = find_key_segment_with_confidence(extended_column, key_length, 0)
            overlapping_key += key_char
        
        # Return the better scoring key
        if score_decryption(decrypt_vigenere(ciphertext, overlapping_key)) < score_decryption(decrypt_vigenere(ciphertext, key)):
            key = overlapping_key
            
    return key

def find_key_segment_with_confidence(ciphertext, period, offset=0):
    """Enhanced version of find_key_segment that returns confidence score."""
    column = ciphertext[offset::period]
    if len(column) < 2:
        return 'A', 0.0
        
    scores = []
    for shift in range(26):
        shifted = ''.join(chr(((ord(c)-ord('A')-shift) % 26) + ord('A')) for c in column)
        freq = get_letter_frequency(shifted)
        score = chi_squared_score(freq)
        
        # Consider common letter occurrences for better accuracy
        common_english = {'E': 3, 'T': 2, 'A': 2, 'O': 2, 'I': 2, 'N': 2, 'S': 2, 'H': 2, 'R': 2}
        letter_score = sum(3 for c in shifted if c in 'ETAOIN') + sum(1 for c in shifted if c in 'SRDLUHCMPFYWGBVKXJQZ')
        letter_score /= len(shifted) * 3  # Normalize to 0-1 range
        
        # Combine frequency score and letter score (weighted)
        combined_score = score * (1.0 - letter_score * 0.3)  # Adjust weight of letter score
        scores.append((shift, combined_score))
    
    # Sort by score (lower is better)
    scores.sort(key=lambda x: x[1])
    best_shift, best_score = scores[0]
    
    # Specific check for 'H' vs 'L' in English text (common mistake)
    if chr(best_shift + ord('A')) == 'L':
        # Check if 'H' is close in score
        for shift, score in scores:
            if chr(shift + ord('A')) == 'H':
                # If H is close in score, prefer it as it's more common in English
                if score < best_score * 1.1:
                    best_shift = shift
                    break
    
    # Calculate confidence based on difference from next best score
    confidence = 0.0
    if len(scores) > 1:
        score_diff = scores[1][1] - best_score
        confidence = min(1.0, score_diff / best_score)
        
    # Add bigram analysis confidence
    bigram_confidence = analyze_bigrams(column, best_shift)
    
    # Combine confidences
    final_confidence = (confidence + bigram_confidence) / 2
    
    return chr(best_shift + ord('A')), final_confidence

def analyze_bigrams(text, shift):
    """Analyze text bigrams for additional confidence scoring."""
    common_bigrams = {
        'TH': 0.27, 'HE': 0.23, 'IN': 0.21, 'ER': 0.19, 
        'AN': 0.19, 'RE': 0.18, 'ND': 0.17, 'AT': 0.16,
        'ON': 0.15, 'NT': 0.14, 'HA': 0.13, 'ES': 0.13,
        'ST': 0.12, 'EN': 0.12, 'ED': 0.12, 'TO': 0.12
    }
    
    shifted = ''.join(chr(((ord(c)-ord('A')-shift) % 26) + ord('A')) for c in text)
    bigrams = [''.join(pair) for pair in zip(shifted[:-1], shifted[1:])]
    
    score = sum(common_bigrams.get(bigram, 0) for bigram in bigrams)
    max_possible = len(bigrams) * max(common_bigrams.values())
    
    return score / max_possible if max_possible > 0 else 0.0

def get_extended_column(text, period, offset):
    """Get an extended column that includes neighboring characters for context."""
    result = []
    for i in range(offset, len(text), period):
        segment = text[max(0, i-1):min(len(text), i+2)]
        result.append(segment)
    return ''.join(result)

def score_decryption(text):
    """Score a decrypted text based on English letter frequencies."""
    freq = get_letter_frequency(text)
    return chi_squared_score(freq)

def kasiski_examination(ciphertext, min_seq_length=3, max_key_length=10):
    """
    Perform Kasiski examination to break a Vigenère cipher.
    
    Returns:
        Tuple: (most likely key length, key analysis, list of possible keys with scores, list of decryptions)
    """
    # Ensure minimum viable text length with relaxed constraints
    if len(ciphertext) < min_seq_length * 2:
        return None
        
    # Find repeated sequences
    repeated = find_repeated_sequences(ciphertext, min_seq_length)
    
    # If no repeated sequences found with min_length, try with shorter length
    if not repeated and min_seq_length > 2:
        repeated = find_repeated_sequences(ciphertext, 2)
    
    # If still no repeated sequences, try brute forcing common key lengths
    if not repeated:
        # Create a synthetic analysis result using common key lengths
        key_analysis = {i: (max_key_length + 1 - i) for i in range(2, max_key_length + 1)}
        likely_key_length = 5  # Most common key length
        
        # Try common key lengths
        possible_keys = []
        for key_len in range(2, max_key_length + 1):
            key = get_possible_keys(ciphertext, key_len)
            plaintext = decrypt_vigenere(ciphertext, key)
            score = score_decryption(plaintext)
            possible_keys.append((key, score))
            
        if not possible_keys:
            return None
            
        possible_keys.sort(key=lambda x: x[1])
        decryptions = [(key, decrypt_vigenere(ciphertext, key)) for key, _ in possible_keys[:5]]
        
        return likely_key_length, key_analysis, possible_keys, decryptions
        
    # Analyze key lengths from repeated sequences
    key_analysis = analyze_key_length(repeated)
    if not key_analysis:
        return None
        
    # Sort key lengths by likelihood
    likely_lengths = sorted(key_analysis.items(), key=lambda x: x[1], reverse=True)
    likely_key_length = likely_lengths[0][0]
    
    # Try multiple key lengths including common key lengths
    possible_keys = []
    tested_lengths = set()
    
    # Always try common key lengths: 3, 4, 5, 6 (most frequent in historical ciphers)
    common_lengths = [5, 6, 4, 3, 7]
    
    # Try first the most likely lengths
    for length, score in likely_lengths[:5]:
        if length in tested_lengths:
            continue
        tested_lengths.add(length)
        
        key = get_possible_keys(ciphertext, length)
        plaintext = decrypt_vigenere(ciphertext, key)
        score = score_decryption(plaintext)
        possible_keys.append((key, score))
        
    # Then try common lengths that haven't been tested yet
    for length in common_lengths:
        if length in tested_lengths:
            continue
        tested_lengths.add(length)
        
        key = get_possible_keys(ciphertext, length)
        plaintext = decrypt_vigenere(ciphertext, key)
        score = score_decryption(plaintext)
        possible_keys.append((key, score))
    
    if not possible_keys:
        return None
        
    # Sort by score (lower is better)
    possible_keys.sort(key=lambda x: x[1])
    
    # Generate sample decryptions for the best keys
    decryptions = []
    for key, _ in possible_keys[:5]:
        plaintext = decrypt_vigenere(ciphertext, key)
        decryptions.append((key, plaintext))
    
    return likely_key_length, key_analysis, possible_keys, decryptions

def kasiski_attack(ciphertext):
    """
    Perform Kasiski examination to break a Vigenère cipher.
    
    Returns the most likely key.
    """
    ciphertext = ''.join(c.upper() for c in ciphertext if c.isalpha())
    if len(ciphertext) < 20:
        return None
    result = kasiski_examination(ciphertext)
    if result:
        likely_key_length, _, possible_keys, _ = result
        if possible_keys:
            return possible_keys[0][0]
    return None

def vigenere_encrypt(plaintext, key):
    """Encrypt plaintext using Vigenère cipher."""
    ciphertext = []
    key_len = len(key)
    for i, char in enumerate(plaintext):
        if char in string.ascii_uppercase:
            p = ord(char) - ord('A')
            k = ord(key[i % key_len]) - ord('A')
            c = (p + k) % 26
            ciphertext.append(chr(c + ord('A')))
        else:
            ciphertext.append(char)
    return ''.join(ciphertext)
