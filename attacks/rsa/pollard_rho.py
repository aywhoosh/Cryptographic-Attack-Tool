import random
import math

def gcd(a, b):
    """Compute the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def pollard_rho(n, max_iterations=100000, callback=None):
    """
    Implement Pollard's Rho algorithm for integer factorization.
    
    Args:
        n: Number to factorize.
        max_iterations: Maximum iterations to try.
        callback: Function to call with step-by-step information.
    
    Returns:
        A non-trivial factor of n if found, else None.
    """
    if callback:
        callback("start", f"Starting Pollard's Rho factorization for n = {n}")
    
    if n % 2 == 0:
        if callback:
            callback("found", f"Number is even, 2 is a factor")
        return 2
    
    def f(x, c, n):
        return (x*x + c) % n
    
    for c in range(1, 20):
        if callback:
            callback("iteration", f"Trying with polynomial f(x) = x² + {c} mod {n}")
        
        x, y, d = 2, 2, 1
        iterations = 0
        tortoise_values = []
        hare_values = []
        
        while d == 1 and iterations < max_iterations:
            x_old, y_old = x, y
            x = f(x, c, n)
            y = f(f(y, c, n), c, n)
            d = gcd(abs(x - y), n)
            
            tortoise_values.append(x_old)
            hare_values.append(y_old)
            
            if callback and iterations % 100 == 0:
                callback("progress", {
                    "iteration": iterations,
                    "tortoise": x,
                    "hare": y,
                    "gcd": d,
                    "c": c,
                    "tortoise_values": tortoise_values[-5:],
                    "hare_values": hare_values[-5:]
                })
            
            iterations += 1
        
        if callback:
            if d == 1:
                callback("failed", f"Failed to find factor with c = {c} after {iterations} iterations")
            elif d == n:
                callback("failed", f"Found trivial factor n with c = {c}")
            else:
                callback("success", f"Found non-trivial factor: {d}")
        
        if 1 < d < n:
            return d
    
    if callback:
        callback("failed", "Failed to find any factors after trying all c values")
    return None

def factorize(n, recursive=True, callback=None):
    """
    Factorize n into its prime factors.
    
    Args:
        n: Number to factorize.
        recursive: Whether to recursively factorize.
        callback: Function to call with step-by-step information.
    
    Returns:
        List of prime factors.
    """
    if callback:
        callback("start", f"Starting factorization of {n}")
    
    if n <= 1:
        if callback:
            callback("info", f"{n} is too small to factorize")
        return []
    
    if is_prime(n):
        if callback:
            callback("prime", f"{n} is prime")
        return [n]
    
    # Try small prime factors first
    for i in range(2, 1000):
        if n % i == 0:
            if callback:
                callback("factor", f"Found small prime factor: {i}")
            if recursive:
                left = factorize(i, recursive, callback)
                right = factorize(n // i, recursive, callback)
                return left + right
            else:
                return [i, n // i]
    
    if callback:
        callback("info", "No small prime factors found, trying Pollard's Rho")
    
    factor = pollard_rho(n, callback=callback)
    if factor:
        if callback:
            callback("factor", f"Pollard's Rho found factor: {factor}")
        if recursive:
            left = factorize(factor, recursive, callback)
            right = factorize(n // factor, recursive, callback)
            return left + right
        else:
            return [factor, n // factor]
    
    if callback:
        callback("failed", f"Failed to factorize {n}")
    return [n]

def is_prime(n):
    """Simple primality test."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i+2) == 0:
            return False
        i += 6
    return True

def pollard_rho_attack(n, max_iterations=100000, callback=None):
    """
    Wrapper for Pollard's Rho attack.
    
    Args:
        n: Number to factorize.
        max_iterations: Maximum iterations.
        callback: Function to call with step-by-step information.
    
    Returns:
        List of prime factors if found, else None.
    """
    if callback:
        callback("start", f"Starting Pollard's Rho attack on n = {n}")
    
    if n <= 1:
        if callback:
            callback("error", "Number is too small")
        return None
    
    if is_prime(n):
        if callback:
            callback("prime", f"{n} is prime")
        return [n]
    
    factors = factorize(n, callback=callback)
    
    if callback:
        if factors and len(factors) > 1:
            callback("success", f"Successfully factored {n} into {' × '.join(map(str, factors))}")
        else:
            callback("failed", "Failed to factor the number")
    
    return factors if factors else None

def generate_example():
    """
    Generate an example composite number for Pollard's Rho factorization.
    
    Returns:
        Tuple (composite_number, factors).
    """
    p = random.randint(100, 10000)
    while not is_prime(p):
        p = random.randint(100, 10000)
    q = random.randint(100, 10000)
    while not is_prime(q) or p == q:
        q = random.randint(100, 10000)
    n = p * q
    return n, [p, q]
