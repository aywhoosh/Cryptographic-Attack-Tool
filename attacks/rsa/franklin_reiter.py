import sympy
from Crypto.Util.number import getPrime

def franklin_reiter_attack(n, e, c1, c2, relationship, callback=None):
    """
    Implement Franklin-Reiter's related message attack on RSA.
    
    This attack works when two messages have a known linear relationship
    and are encrypted with a small public exponent (typically e = 3).
    
    Args:
        n: The modulus
        e: The public exponent
        c1: The ciphertext of the first message m1
        c2: The ciphertext of the second message m2 = a*m1 + b
        relationship: Tuple (a, b) representing the linear relationship
        callback: Function to receive step-by-step information
    
    Returns:
        Tuple (m1, m2) if successful, or None
    """
    try:
        if callback:
            callback("start", f"""Starting Franklin-Reiter attack:
            Modulus n = {n}
            Public exponent e = {e}
            First ciphertext c1 = {c1}
            Second ciphertext c2 = {c2}""")
        
        if not isinstance(relationship, tuple) or len(relationship) != 2:
            if callback:
                callback("error", "Invalid relationship format. Expected tuple (a, b)")
            return None
        
        a, b = relationship
        if callback:
            callback("info", f"Using relationship m2 = {a}·m1 + {b}")
        
        # Convert parameters to sympy integers
        import sympy
        n = sympy.Integer(n)
        e = sympy.Integer(e)
        c1 = sympy.Integer(c1)
        c2 = sympy.Integer(c2)
        a = sympy.Integer(a)
        b = sympy.Integer(b)
        
        # Create polynomial ring over Z_n
        x = sympy.Symbol('x')
        P = sympy.polys.polytools.Poly
        
        if callback:
            callback("progress", "Constructing polynomials...")
            callback("info", f"g1(x) = x^{e} - {c1} mod {n}")
            callback("info", f"g2(x) = ({a}x + {b})^{e} - {c2} mod {n}")
        
        # Construct polynomials more carefully
        g1 = P((x**e - c1) % n, x, modulus=n)
        g2_expanded = P(((a*x + b)**e - c2) % n, x, modulus=n)
        
        if callback:
            callback("progress", "Computing GCD of polynomials...")
        
        # Compute the GCD in Z_n[x]
        from sympy.polys.domains import ZZ
        K = ZZ.quo(n)  # Create quotient ring Z/nZ
        g1_K = g1.set_domain(K)
        g2_K = g2_expanded.set_domain(K)
        
        try:
            gcd_poly = sympy.gcd(g1_K, g2_K)
            
            if callback:
                callback("info", f"GCD polynomial: {gcd_poly}")
            
            if gcd_poly.is_constant():
                if callback:
                    callback("failed", "GCD is constant - attack failed")
                return None
            
            # Get the root of the GCD polynomial
            roots = sympy.polys.polyroots.roots_mod(gcd_poly, n)
            if not roots:
                if callback:
                    callback("failed", "Could not find roots of GCD polynomial")
                return None
            
            m1 = roots[0]
            m2 = (a * m1 + b) % n
            
            # Verify the solution
            if pow(m1, e, n) == c1 and pow(m2, e, n) == c2:
                if callback:
                    callback("success", f"Attack succeeded! Recovered messages:\nm1 = {m1}\nm2 = {m2}")
                return m1, m2
            else:
                if callback:
                    callback("failed", "Verification failed - invalid solution found")
                return None
            
        except Exception as e:
            if callback:
                callback("error", f"Error computing GCD: {str(e)}")
            return None
            
    except Exception as e:
        if callback:
            callback("error", f"Attack failed with error: {str(e)}")
        return None

def generate_example(bits=512, callback=None):
    """
    Generate example parameters for the Franklin-Reiter attack.
    
    Args:
        bits: Bit length for the modulus
        callback: Function to receive generation progress
    
    Returns:
        Tuple (n, e, m1, m2, c1, c2, a, b)
    """
    if callback:
        callback("start", f"Generating {bits}-bit RSA parameters vulnerable to Franklin-Reiter attack")
    
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p * q
    
    if callback:
        callback("progress", f"Generated RSA modulus n = {n}")
    
    # Use small public exponent
    e = 3
    if callback:
        callback("info", f"Using public exponent e = {e}")
    
    # Generate first message
    m1 = getPrime(bits//3)
    if callback:
        callback("progress", f"Generated first message m1 = {m1}")
    
    # Define linear relationship
    a = 2
    b = 7
    m2 = (a * m1 + b) % n
    
    if callback:
        callback("info", f"Using relationship m2 = {a}·m1 + {b}")
        callback("progress", f"Generated second message m2 = {m2}")
    
    # Encrypt messages
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)
    
    if callback:
        callback("success", f"""Generated vulnerable messages:
        First message m1 = {m1}
        Second message m2 = {m2}
        First ciphertext c1 = {c1}
        Second ciphertext c2 = {c2}
        Relationship: m2 = {a}·m1 + {b}""")
    
    return n, e, m1, m2, c1, c2, a, b

def verify_relationship(m1, m2, a, b, n):
    """
    Verify if two messages satisfy the linear relationship m2 = a·m1 + b mod n.
    
    Args:
        m1: First message
        m2: Second message
        a: Multiplier
        b: Constant term
        n: Modulus
    
    Returns:
        bool: True if relationship holds
    """
    return (a * m1 + b) % n == m2
