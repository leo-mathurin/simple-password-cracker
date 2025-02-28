#!/usr/bin/env python
"""
Example demonstrating how to generate hashes from plaintext passwords using the CLI.
"""

import os
import sys
import subprocess
from pathlib import Path

# Example passwords of different types
PASSWORDS = [
    "password123",           # Simple password
    "P@ssw0rd!",             # Mixed case with symbols
    "Tr0ub4dor&3",           # More complex
    "correct horse battery staple",  # Passphrase
]

# Hash types to demonstrate
HASH_TYPES = ["md5", "sha1", "sha256"]


def main():
    """Demonstrate hash generation for different passwords and hash types."""
    # Create the examples directory if it doesn't exist
    example_dir = Path(__file__).parent
    os.makedirs(example_dir, exist_ok=True)
    
    print("=== Hash Generation Example ===")
    print("\nThis example demonstrates generating hashes for various passwords using different algorithms.")
    print("You can use these hashes for testing the password cracker.")
    
    # Loop through each password and hash type combination
    for password in PASSWORDS:
        print(f"\n\n=== Password: '{password}' ===")
        
        for hash_type in HASH_TYPES:
            print(f"\nGenerating {hash_type.upper()} hash...")
            
            # Build the command to generate the hash
            cmd = [
                "python", "-m", "cracker.cli",
                "--password", password,
                "--type", hash_type,
                "--only-hash"
            ]
            
            # Run the command
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                
                # Extract the hash from the output (should be on the 3rd line)
                output_lines = result.stdout.strip().split('\n')
                hash_line = next((line for line in output_lines if line.startswith("Hash: ")), None)
                
                if hash_line:
                    hash_value = hash_line.replace("Hash: ", "")
                    print(f"{hash_type.upper()} Hash: {hash_value}")
                    
                    # Show a command example for cracking this hash
                    print("Example crack command:")
                    print(f"python -m cracker.cli --hash {hash_value} --type {hash_type} --online-dict phpbb")
                else:
                    print("Failed to extract hash from output")
            except subprocess.CalledProcessError as e:
                print(f"Error generating hash: {e}")
                print(f"Error output: {e.stderr}")
            except Exception as e:
                print(f"Error: {e}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 