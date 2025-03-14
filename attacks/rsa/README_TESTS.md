# Franklin-Reiter Attack Test Cases

This guide explains how to use the additional test cases for the Franklin-Reiter Related Message Attack algorithm.

## Running the Tests

To run the test suite, execute:

```
python franklin_reiter_tests.py
```

The test script will run all the test cases and provide detailed output for each, including the parameters used and whether the attack succeeded.

## Test Cases Included

The test suite includes multiple test cases to validate the Franklin-Reiter attack implementation:

1. **Standard e=3 (64-bit)**: Basic test with 64-bit modulus and e=3
2. **Standard e=3 (128-bit)**: Medium-sized test with 128-bit modulus and e=3
3. **Different relationship parameters**: Test with non-standard relationship values (a=5, b=10)
4. **Edge case: Very small messages**: Test with minimal message values (m1=1)
5. **Edge case: Large relationship parameters**: Test with relationship parameters close to modulus value
6. **Edge case: Non-invertible 'a' parameter**: Test a case where 'a' is not invertible mod n (expected to fail)

## Understanding Test Output

Each test case will output:
- The RSA modulus n and its bit length
- The public exponent e
- The relationship between messages m2 = a·m1 + b (mod n)
- The original messages m1 and m2
- The corresponding ciphertexts c1 and c2
- Whether the attack succeeded or failed
- Execution time

## Sample Output

```
================================================================================
 TEST CASE: Standard e=3 (64-bit) 
================================================================================
RSA Modulus n: 13407807929942597099 (64 bits)
Public exponent e: 3
Relationship: m2 = 2·m1 + 3 (mod n)
Original messages: m1 = 42, m2 = 87
Ciphertexts: c1 = 74088, c2 = 658503

Running Franklin-Reiter attack...
[SUCCESS] Attack succeeded!
m1 = 42
m2 = 87

✅ SUCCESS: Messages recovered correctly
Expected m1: 42
Got m1     : 42
Expected m2: 87
Got m2     : 87

Time taken: 0.0320 seconds
```

## Interpreting Results

- **Success**: Messages are correctly recovered
- **Failure**: Could happen if:
  - The relationship parameters don't satisfy the requirements (e.g., a is not invertible)
  - The implementation has limitations for certain cases
  - Parameter sizes exceed computational capacity

## Troubleshooting

If some tests fail:
1. Check if the failing test is the non-invertible 'a' test (#6) which is expected to fail
2. For other failures, try adjusting the parameters in the test cases
3. For large parameter tests, the algorithm may need additional optimizations

## Customizing Tests

You can add your own test cases by creating additional test functions following the pattern in the existing code:

```python
def test_case_custom():
    # Generate parameters
    p = getPrime(32)
    q = getPrime(32)
    n = p * q
    e = 3
    
    # Set relationship
    a = 123
    b = 456
    
    # Define messages
    m1 = 42
    m2 = (a * m1 + b) % n
    
    return run_test_case(n, e, m1, m2, a, b, "Custom test case")
```

Then add your function to the `test_functions` list in the `run_all_tests()` function.