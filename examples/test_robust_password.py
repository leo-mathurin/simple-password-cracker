#!/usr/bin/env python
"""
Example demonstrating cracking a stronger password using downloaded wordlists.
"""

import os
import sys
import hashlib
import subprocess
from pathlib import Path

# Example passwords with varying complexity
PASSWORDS = {
    "simple": "password123",  # Very common
    "medium": "P@ssw0rd!",    # Mixed case with symbols
    "complex": "Tr0ub4dor&3", # More complex (but still in some dictionaries)
}

# Generate SHA-256 hashes for each password
def generate_hashes(password_dict):
    """Generate SHA-256 hashes for the given passwords."""
    hashes = {}
    for level, password in password_dict.items():
        hash_value = hashlib.sha256(password.encode('utf-8')).hexdigest()
        hashes[level] = hash_value
    return hashes

def main():
    """Run the robust password cracking demonstration."""
    # Create the examples directory if it doesn't exist
    example_dir = Path(__file__).parent
    os.makedirs(example_dir, exist_ok=True)
    
    # Generate hashes
    password_hashes = generate_hashes(PASSWORDS)
    
    print("=== Password Cracking Example ===")
    print("\nThis example will attempt to crack passwords of increasing complexity.")
    print("Each password will be hashed with SHA-256 and the cracker will try to find it.")
    
    # Test each complexity level
    for level in ["simple", "medium", "complex"]:
        password = PASSWORDS[level]
        hash_value = password_hashes[level]
        
        print(f"\n\n=== Testing {level.upper()} password ===")
        print(f"Actual password: {password}")
        print(f"SHA-256 hash: {hash_value}")
        
        # Determine which dictionary to use based on complexity
        dictionary = None
        if level == "simple":
            dictionary = "phpbb"  # For simple passwords
        elif level == "medium":
            dictionary = "common-passwords"  # Medium-sized list
        elif level == "complex":
            dictionary = "rockyou-75"  # Larger dictionary for complex passwords
        
        print(f"\nAttempting to crack using {dictionary} wordlist...")
        
        # Build the command
        cmd = [
            "python", "-m", "cracker.cli",
            "--hash", hash_value,
            "--online-dict", dictionary,
            "--type", "sha256",
            "--verbose"
        ]
        
        # Run the command
        try:
            print(f"Running command: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running password cracker: {e}")
        except Exception as e:
            print(f"Error: {e}")
            return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main()) 