"""
Wiener's attack implementation for RSA.
"""
from math import gcd, isqrt
from sympy import mod_inverse

def continued_fraction(e, n, callback=None):
    """Generate convergents from the continued fraction expansion of e/n"""
    if callback:
        callback("start", f"Starting continued fraction expansion of {e}/{n}")
    
    quotients = []
    e_orig, n_orig = e, n
    while n:
        q = e // n
        quotients.append(q)
        e, n = n, e % n
        if callback:
            callback("fraction", f"Found quotient: {q}")
    
    if callback:
        callback("info", f"Generating convergents from quotients: {quotients}")
    
    convergents = []
    num1, num2 = 1, 0
    den1, den2 = 0, 1
    
    for i, q in enumerate(quotients):
        num = q * num1 + num2
        den = q * den1 + den2
        convergents.append((num, den))
        if callback:
            callback("convergent", f"Convergent {i+1}: {num}/{den}")
        num2, num1 = num1, num
        den2, den1 = den1, den
    
    return convergents

def wiener_attack(e, n, callback=None):
    """
    Perform Wiener's attack on an RSA public key with small private exponent.
    
    The attack works when d < N^(1/4)/3, where d is the private exponent.
    This typically happens when d is chosen to be too small for efficiency.
    
    Args:
        e: Public exponent
        n: Modulus
        callback: Function to receive step-by-step information
    
    Returns:
        Tuple (d, p, q) if attack succeeds, None otherwise
    """
    if callback:
        callback("start", f"Starting Wiener's attack on RSA key (n={n}, e={e})")
        callback("info", "This attack works when the private exponent d is small (d < N^(1/4)/3)")
    
    conv = continued_fraction(e, n, callback)
    theoretical_limit = isqrt(isqrt(n)) // 3
    
    if callback:
        callback("info", f"Theoretical limit for vulnerable d: {theoretical_limit}")
        callback("info", f"Testing {len(conv)} convergents as potential private exponents...")
    
    for i, (k, d) in enumerate(conv):
        if callback:
            callback("attempt", f"Testing convergent {i+1}: k={k}, d={d}")
        
        if k == 0:
            if callback:
                callback("skip", "Skipping k=0")
            continue
        
        if d > theoretical_limit:
            if callback:
                callback("skip", f"Skipping d={d} as it exceeds theoretical limit")
            continue
        
        if (e * d - 1) % k != 0:
            if callback:
                callback("fail", f"k={k}, d={d} is not a valid solution")
            continue
        
        phi = (e * d - 1) // k
        if callback:
            callback("progress", f"Found potential φ(n): {phi}")
        
        # Using the quadratic equation: x^2 - sx + n = 0
        # where s = n - φ + 1
        s = n - phi + 1
        discrim = s * s - 4 * n
        
        if discrim < 0:
            if callback:
                callback("fail", f"Discriminant {discrim} is negative")
            continue
        
        t = isqrt(discrim)
        if t * t != discrim:
            if callback:
                callback("fail", "Discriminant is not a perfect square")
            continue
        
        # Potential prime factors
        p = (s + t) // 2
        q = (s - t) // 2
        
        if callback:
            callback("check", f"Checking potential factors: p={p}, q={q}")
        
        if p * q == n:
            if callback:
                callback("success", f"""Attack succeeded!
                Found private exponent d = {d}
                Prime factors: 
                p = {p}
                q = {q}
                Verifying: p * q = {p * q} = n = {n}""")
            return d, p, q
        else:
            if callback:
                callback("fail", "Product of potential factors doesn't match n")
    
    if callback:
        callback("failed", """Attack failed! Possible reasons:
        1. The private exponent d is not small enough
        2. The key is not vulnerable to Wiener's attack
        3. Additional key strengthening measures are in place""")
    return None

def generate_vulnerable_key(bits=256, callback=None):
    """
    Generate an RSA key pair vulnerable to Wiener's attack by ensuring a small private exponent.
    
    Args:
        bits: Key size in bits
        callback: Function to receive generation progress
        
    Returns:
        Tuple (n, e, d, p, q) representing public and private key components
    """
    from Crypto.Util.number import getPrime
    
    if callback:
        callback("start", f"Generating {bits}-bit RSA key vulnerable to Wiener's attack")
    
    while True:
        try:
            p = getPrime(bits // 2)
            q = getPrime(bits // 2)
            if p == q:
                continue
            
            n = p * q
            phi = (p - 1) * (q - 1)
            
            # Generate a small d that satisfies d < n^(1/4)/3
            d = getPrime(bits // 5)  # Make d significantly smaller than before
            
            if callback:
                callback("progress", f"Testing with d = {d}")
            
            # Calculate e as modular multiplicative inverse of d
            try:
                e = mod_inverse(d, phi)
                
                # Verify the key will be vulnerable
                limit = int(pow(n, 0.25) / 3)
                if d > limit:
                    if callback:
                        callback("retry", f"d = {d} is too large (limit {limit}), retrying...")
                    continue
                
                if callback:
                    callback("success", f"""Successfully generated vulnerable key pair:
                        Public key (n,e):
                        n = {n}
                        e = {e}
                        Private key:
                        d = {d}""")
                return n, e, d, p, q
                
            except Exception:
                if callback:
                    callback("retry", "Invalid d value, retrying...")
                continue
                
        except Exception as e:
            if callback:
                callback("error", f"Error during key generation: {str(e)}")
            continue
