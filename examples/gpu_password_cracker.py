#!/usr/bin/env python
"""
GPU Password Cracker Example

This script demonstrates how to use GPU acceleration for password cracking
using OpenCL.

Usage:
    python gpu_password_cracker.py --hash <hash> --type <type> [options]

Examples:
    # Crack a password using GPU acceleration with default options
    python gpu_password_cracker.py --hash 73f8dfc3e4d6680299ed451a208f0e9e --type md5

    # Crack a password with specific options
    python gpu_password_cracker.py --hash 73f8dfc3e4d6680299ed451a208f0e9e --type md5 --min-length 6 --max-length 8 --charset "Pas5W0rd@"

    # Specify OpenCL platform and device indices
    python gpu_password_cracker.py --hash 73f8dfc3e4d6680299ed451a208f0e9e --type md5 --platform 0 --device 0

    # Generate a hash for a password
    python gpu_password_cracker.py --password "P@s5W0rd" --type md5 --only-hash
"""

import os
import sys
import time
import argparse
from pathlib import Path
import hashlib

# Add parent directory to path to allow importing cracker module
parent_dir = str(Path(__file__).resolve().parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    print("NumPy not found. Please install with: pip install numpy")
    NUMPY_AVAILABLE = False

# Check for GPU libraries
OPENCL_AVAILABLE = False

try:
    import pyopencl as cl
    OPENCL_AVAILABLE = True
except ImportError:
    print("PyOpenCL not found. Please install with: pip install pyopencl")
    OPENCL_AVAILABLE = False

# Import from cracker module
try:
    from cracker.hashers import get_hasher
    from cracker.bruteforce import BruteForceGenerator, brute_force_attack
    if OPENCL_AVAILABLE:
        from cracker.gpu_bruteforce import gpu_brute_force_attack
except ImportError as e:
    print(f"Error importing cracker module: {e}")
    print("Make sure the cracker module is installed or in the Python path.")
    sys.exit(1)


def generate_hash(password, hash_type):
    """Generate a hash for the given password."""
    hasher = get_hasher(hash_type)
    hash_value = hasher.hash(password)
    print(f"\n=== Generated {hash_type.upper()} Hash ===")
    print(f"Password: {password}")
    print(f"Hash: {hash_value}")
    return hash_value


def crack_password_gpu(hash_value, hash_type, charset, min_length, max_length, 
                     batch_size=1000000, platform_index=None, device_index=None, verbose=False):
    """Crack a password using GPU acceleration with OpenCL."""
    hasher = get_hasher(hash_type)
    
    # Check if a compatible GPU library is available
    if not OPENCL_AVAILABLE:
        print("No GPU acceleration libraries available. Falling back to CPU.")
        return crack_password_cpu(hash_value, hash_type, charset, min_length, max_length, verbose)
    
    # Perform GPU-accelerated brute force attack
    print("\nUsing GPU-accelerated brute force attack with OpenCL")
    
    start_time = time.time()
    try:
        password, attempts = gpu_brute_force_attack(
            hasher=hasher,
            hash_to_crack=hash_value,
            charset=charset,
            min_length=min_length,
            max_length=max_length,
            batch_size=batch_size,
            verbose=verbose,
            platform_index=platform_index,
            device_index=device_index
        )
    except Exception as e:
        print(f"GPU acceleration failed: {e}")
        print("Falling back to CPU brute force.")
        return crack_password_cpu(hash_value, hash_type, charset, min_length, max_length, verbose)
        
    elapsed_time = time.time() - start_time
    
    # Display results
    print("\n============================================================")
    print(f"Hash: {hash_value}")
    print(f"Hash Type: {hash_type.upper()}")
    print(f"GPU Acceleration: OpenCL")
    print(f"Attempts: {attempts:,}")
    print(f"Time Elapsed: {elapsed_time:.2f} seconds")
    
    if attempts > 0 and elapsed_time > 0:
        print(f"Passwords Tested per Second: {attempts / elapsed_time:,.2f}")
    
    if password:
        print(f"\n🎉 PASSWORD FOUND!")
        print(f"The password is: {password}")
        return True
    else:
        print("\n❌ Password not found.")
        return False


def crack_password_cpu(hash_value, hash_type, charset, min_length, max_length, verbose=False):
    """Crack a password using CPU brute force."""
    hasher = get_hasher(hash_type)
    
    # Create a brute force generator
    generator = BruteForceGenerator(
        min_length=min_length,
        max_length=max_length,
        custom_chars=charset
    )
    
    # Perform brute force attack
    print("\nUsing CPU brute force attack")
    password, attempts = brute_force_attack(hasher, hash_value, generator, verbose)
    
    # Results will be displayed by the brute_force_attack function
    return password is not None


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="GPU-accelerated password cracker demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Hash or password input
    parser.add_argument("--hash", help="The hash to crack")
    parser.add_argument("--password", help="Password to hash (and optionally crack)")
    parser.add_argument("--only-hash", action="store_true", help="Only generate hash, don't attempt to crack")
    
    # Hash type
    parser.add_argument("--type", choices=["md5", "sha1", "sha256"], default="md5",
                        help="Hash type (default: md5)")
    
    # Brute force options
    parser.add_argument("--min-length", type=int, default=1, help="Minimum password length (default: 1)")
    parser.add_argument("--max-length", type=int, default=8, help="Maximum password length (default: 8)")
    parser.add_argument("--charset", help="Custom character set for brute force")
    parser.add_argument("--use-lowercase", action="store_true", help="Include lowercase letters")
    parser.add_argument("--use-uppercase", action="store_true", help="Include uppercase letters")
    parser.add_argument("--use-digits", action="store_true", help="Include digits")
    parser.add_argument("--use-special", action="store_true", help="Include special characters")
    
    # GPU options
    parser.add_argument("--platform", type=int, help="OpenCL platform index to use")
    parser.add_argument("--device", type=int, help="OpenCL device index to use")
    parser.add_argument("--batch-size", type=int, default=1000000, help="GPU batch size (default: 1,000,000)")
    
    # Other options
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Validate input
    if not args.hash and not args.password:
        print("Error: Either --hash or --password is required")
        return 1
    
    # Generate hash from password if provided
    if args.password:
        hash_value = generate_hash(args.password, args.type)
        if args.only_hash:
            return 0
    else:
        hash_value = args.hash
    
    # Prepare character set
    charset = args.charset
    if not charset:
        charset_parts = []
        if args.use_lowercase or not (args.use_uppercase or args.use_digits or args.use_special):
            charset_parts.append("abcdefghijklmnopqrstuvwxyz")
        if args.use_uppercase:
            charset_parts.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        if args.use_digits:
            charset_parts.append("0123456789")
        if args.use_special:
            charset_parts.append("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
        charset = "".join(charset_parts)
    
    if not charset:
        charset = "abcdefghijklmnopqrstuvwxyz"  # Default to lowercase letters
    
    # Crack the password using GPU acceleration
    crack_password_gpu(hash_value, args.type, charset, args.min_length, args.max_length,
                      args.batch_size, args.platform, args.device, args.verbose)
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 