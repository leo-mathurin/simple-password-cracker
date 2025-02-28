"""
Basic tests for the simple password cracker.
"""

import os
import sys
import hashlib
from cracker.hashers import get_hasher
from cracker.cracker import PasswordCracker


def test_hasher():
    """Test the hasher implementations."""
    # Test MD5
    md5_hasher = get_hasher("md5")
    test_password = "password"
    expected_hash = hashlib.md5(test_password.encode('utf-8')).hexdigest()
    
    assert md5_hasher.hash(test_password) == expected_hash
    assert md5_hasher.verify(test_password, expected_hash) is True
    
    # Test SHA-1
    sha1_hasher = get_hasher("sha1")
    expected_hash = hashlib.sha1(test_password.encode('utf-8')).hexdigest()
    
    assert sha1_hasher.hash(test_password) == expected_hash
    assert sha1_hasher.verify(test_password, expected_hash) is True
    
    # Test SHA-256
    sha256_hasher = get_hasher("sha256")
    expected_hash = hashlib.sha256(test_password.encode('utf-8')).hexdigest()
    
    assert sha256_hasher.hash(test_password) == expected_hash
    assert sha256_hasher.verify(test_password, expected_hash) is True
    
    print("All hasher tests passed!")


def test_cracker():
    """Test the password cracker implementation."""
    # Create a simple test dictionary
    dict_path = "tests/test_dict.txt"
    test_password = "password"
    
    # Make sure the directory exists
    os.makedirs(os.path.dirname(dict_path), exist_ok=True)
    
    # Create a test dictionary file
    with open(dict_path, "w") as f:
        f.write("test\n123456\npassword\nadmin\n")
    
    # Test with MD5
    md5_hasher = get_hasher("md5")
    md5_hash = md5_hasher.hash(test_password)
    
    cracker = PasswordCracker(md5_hasher)
    result, attempts = cracker.dictionary_attack(md5_hash, dict_path, verbose=True)
    
    assert result == test_password
    assert attempts == 3  # The password is the 3rd entry
    
    # Clean up
    os.remove(dict_path)
    
    print(f"Password cracking test passed! Found '{result}' in {attempts} attempts.")


if __name__ == "__main__":
    print("Running simple tests...")
    
    try:
        test_hasher()
        test_cracker()
        print("\nAll tests passed successfully!")
    except AssertionError as e:
        print(f"Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error running tests: {e}")
        sys.exit(1) 