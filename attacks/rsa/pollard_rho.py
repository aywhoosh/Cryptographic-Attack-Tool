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
    
    Algorithm explanation:
    1. The algorithm uses a cycle-finding method to detect factors
    2. It uses a function f(x) = (x² + c) mod n which generates a pseudo-random sequence
    3. Two variables (tortoise and hare) move at different speeds through this sequence
    4. When they collide (enter a cycle), we compute gcd(|tortoise-hare|, n)
    5. If gcd is not 1 or n, it's a non-trivial factor of n
    
    Args:
        n: Number to factorize.
        max_iterations: Maximum iterations to try.
        callback: Function to call with step-by-step information.
    
    Returns:
        A non-trivial factor of n if found, else None.
    """
    if callback:
        callback("start", f"Starting Pollard's Rho factorization for n = {n}")
    
    # Check if n is even (simple case)
    if n % 2 == 0:
        if callback:
            callback("found", f"Number is even, 2 is a factor")
        return 2
    
    # Function to generate sequence: f(x) = (x² + c) mod n
    def f(x, c, n):
        return (x*x + c) % n
    
    # Try different values of c for the polynomial f(x) = x² + c mod n
    for c in range(1, 20):
        if callback:
            callback("iteration", f"Trying with polynomial f(x) = x² + {c} mod {n}")
        
        # Initialize tortoise and hare to the same position
        x, y, d = 2, 2, 1  # x is tortoise, y is hare
        iterations = 0
        
        while d == 1 and iterations < max_iterations:
            # Move tortoise one step
            x = f(x, c, n)
            
            # Move hare two steps
            y = f(y, c, n)
            y = f(y, c, n)
            
            # Check if we found a factor
            d = gcd(abs(x - y), n)
            
            # Report progress periodically via callback
            if callback and iterations % 100 == 0:
                callback("progress", {
                    "iteration": iterations,
                    "tortoise": x,
                    "hare": y,
                    "gcd": d,
                    "c": c,
                    "n": n
                })
            
            iterations += 1
        
        # Report results of this attempt
        if callback:
            if d == 1:
                callback("failed", f"Failed to find factor with c = {c} after {iterations} iterations")
            elif d == n:
                callback("failed", f"Found trivial factor n with c = {c}")
            else:
                callback("success", f"Found non-trivial factor: {d}")
        
        # If we found a non-trivial factor, return it
        if 1 < d < n:
            return d
    
    # If we've tried all values of c and found nothing
    if callback:
        callback("failed", "Failed to find any factors after trying all c values")
    return None

def factorize(n, recursive=True, callback=None):
    """
    Factorize n into its prime factors.
    
    Strategy:
    1. First check if n is prime or too small
    2. Try division by small primes (faster than Pollard's Rho for small factors)
    3. Use Pollard's Rho algorithm for larger factors
    4. Recursively factorize the found factors if needed
    
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
                callback("factor", {
                    "message": f"Found small prime factor: {i}",
                    "explanation": "Trial division found a factor"
                })
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
            callback("factor", {
                "message": f"Pollard's Rho found factor: {factor}",
                "explanation": "Using cycle detection to find larger factors"
            })
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
    """
    Simple primality test using trial division.
    
    This function checks if a number is prime by:
    1. Eliminating simple cases (n ≤ 1, n = 2 or 3)
    2. Checking if n is divisible by 2 or 3
    3. Checking divisibility by 6k±1 up to √n
    """
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
        callback("start", {
            "message": f"Starting Pollard's Rho attack on n = {n}",
            "explanation": "This algorithm works best on composite numbers with small factors"
        })
    
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
            callback("success", {
                "message": f"Successfully factored {n} into {' × '.join(map(str, factors))}",
                "factors": factors
            })
        else:
            callback("failed", "Failed to factor the number")
    
    return factors if factors else None

def generate_example():
    """
    Generate an example composite number for Pollard's Rho factorization.
    
    Returns:
        Tuple (composite_number, factors).
    """
    # Generate a small prime for easier demonstration
    p = random.randint(100, 10000)
    while not is_prime(p):
        p = random.randint(100, 10000)
    
    # Generate another small prime for the product
    q = random.randint(100, 10000)
    while not is_prime(q) or p == q:
        q = random.randint(100, 10000)
    
    # Create a composite number with small factors for better visualization
    n = p * q
    return n, [p, q]
