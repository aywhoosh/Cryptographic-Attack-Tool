"""
Test cases for Franklin-Reiter Related Message Attack

This file contains several test cases of varying complexity to validate
the Franklin-Reiter attack implementation beyond the sample data.

Each test case includes:
- Different bit sizes
- Different exponent values
- Different relationship parameters
- Edge cases to test robustness
"""

import os
import sys
import time
from Crypto.Util.number import getPrime, inverse, GCD

# Add parent directory to path to import franklin_reiter module
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from attacks.rsa.franklin_reiter import franklin_reiter_attack, generate_example

def print_test_header(test_name):
    """Print formatted test header"""
    print("\n" + "="*80)
    print(f" TEST CASE: {test_name} ".center(80, "="))
    print("="*80)

def print_result(success, expected_m1, m1, expected_m2, m2):
    """Print test result with formatting"""
    if success:
        print("\n✅ SUCCESS: Messages recovered correctly")
    else:
        print("\n❌ FAILURE: Message recovery failed")
    
    print(f"Expected m1: {expected_m1}")
    print(f"Got m1     : {m1}")
    print(f"Expected m2: {expected_m2}")
    print(f"Got m2     : {m2}")

def run_test_case(n, e, m1, m2, a, b, test_name):
    """Run a test case with the given parameters"""
    print_test_header(test_name)
    
    # Compute ciphertexts
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)
    
    # Print test parameters
    print(f"RSA Modulus n: {n} ({n.bit_length()} bits)")
    print(f"Public exponent e: {e}")
    print(f"Relationship: m2 = {a}·m1 + {b} (mod n)")
    print(f"Original messages: m1 = {m1}, m2 = {m2}")
    print(f"Ciphertexts: c1 = {c1}, c2 = {c2}")
    
    # Define a simple callback to print progress
    def callback(status, message):
        if status in ["error", "warning", "success"]:
            print(f"[{status.upper()}] {message}")
    
    # Run the attack
    print("\nRunning Franklin-Reiter attack...")
    start_time = time.time()
    result = franklin_reiter_attack(n, e, c1, c2, (a, b), callback)
    end_time = time.time()
    
    if result:
        recovered_m1, recovered_m2 = result
        success = (recovered_m1 == m1 and recovered_m2 == m2)
        print_result(success, m1, recovered_m1, m2, recovered_m2)
    else:
        print("\n❌ FAILURE: Attack returned None")
        print(f"Expected m1: {m1}")
        print(f"Expected m2: {m2}")
        success = False
    
    print(f"\nTime taken: {end_time - start_time:.4f} seconds")
    
    return success

def test_case_1():
    """Standard e=3 test case with small parameters (64-bit)"""
    n, e, m1, m2, c1, c2, a, b = generate_example(bits=64, callback=None)
    return run_test_case(n, e, m1, m2, a, b, "Standard e=3 (64-bit)")

def test_case_2():
    """Standard e=3 test case with medium parameters (128-bit)"""
    n, e, m1, m2, c1, c2, a, b = generate_example(bits=128, callback=None)
    return run_test_case(n, e, m1, m2, a, b, "Standard e=3 (128-bit)")

def test_case_3():
    """Different relationship parameters"""
    # Generate small primes for testability
    p = getPrime(32)
    q = getPrime(32)
    n = p * q
    e = 3
    
    # Use different relationship parameters
    a = 5
    b = 10
    
    # Generate small messages for easy verification
    m1 = 42
    m2 = (a * m1 + b) % n
    
    return run_test_case(n, e, m1, m2, a, b, "Different relationship (a=5, b=10)")

def test_case_4():
    """Edge case: Very small messages"""
    p = getPrime(32)
    q = getPrime(32)
    n = p * q
    e = 3
    
    # Very small messages
    m1 = 1
    a = 1
    b = 1
    m2 = (a * m1 + b) % n  # Should be 2
    
    return run_test_case(n, e, m1, m2, a, b, "Edge case: Very small messages")

def test_case_5():
    """Edge case: Large relationship parameters"""
    p = getPrime(32)
    q = getPrime(32)
    n = p * q
    e = 3
    
    # Large relationship parameters
    a = n - 2  # Using large coefficients
    b = n - 1
    
    m1 = 42
    m2 = (a * m1 + b) % n
    
    return run_test_case(n, e, m1, m2, a, b, "Edge case: Large relationship parameters")

def test_case_6():
    """Edge case: Non-invertible 'a' parameter"""
    # This may fail as expected, since 'a' needs to be invertible mod n
    p = getPrime(32)
    q = getPrime(32)
    n = p * q
    e = 3
    
    # Try to find a non-invertible 'a' (i.e., gcd(a,n) ≠ 1)
    a = p  # Not invertible mod n
    b = 1
    
    m1 = 42
    m2 = (a * m1 + b) % n
    
    return run_test_case(n, e, m1, m2, a, b, "Edge case: Non-invertible 'a' parameter")

def run_all_tests():
    """Run all test cases and summarize results"""
    test_functions = [
        test_case_1,
        test_case_2,
        test_case_3,
        test_case_4,
        test_case_5,
        test_case_6
    ]
    
    results = []
    for test_func in test_functions:
        try:
            result = test_func()
            results.append((test_func.__name__, result))
        except Exception as e:
            print(f"\n❌ EXCEPTION: {str(e)}")
            results.append((test_func.__name__, False))
    
    # Print summary
    print("\n" + "="*80)
    print(" TEST RESULTS SUMMARY ".center(80, "="))
    print("="*80)
    
    passed = 0
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")
        if result:
            passed += 1
    
    print("-"*80)
    print(f"Passed {passed}/{len(results)} tests")
    print("="*80)

if __name__ == "__main__":
    try:
        run_all_tests()
    except KeyboardInterrupt:
        print("\nTesting interrupted by user")
    except Exception as e:
        print(f"\nError running tests: {str(e)}")