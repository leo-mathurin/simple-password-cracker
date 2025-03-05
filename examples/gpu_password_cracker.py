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
    
    # Use multi-threaded CPU cracking instead of GPU
    python gpu_password_cracker.py --hash 73f8dfc3e4d6680299ed451a208f0e9e --type md5 --use-cpu-threads --threads 8

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
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    # Import GPU brute force attack
    from cracker.gpu_bruteforce import gpu_brute_force_attack, GPU_AVAILABLE, OPENCL_AVAILABLE
    # Import multi-threaded CPU brute force attack
    from cracker.cpu_bruteforce import cpu_multi_threaded_brute_force_attack, CPU_THREADED_AVAILABLE
    from cracker.bruteforce import BruteForceGenerator, brute_force_attack
    from cracker.hashers import get_hasher
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Make sure you've installed the required dependencies")
    sys.exit(1)

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
    """Crack a password using GPU acceleration."""
    hasher = get_hasher(hash_type)
    
    # Check if OpenCL is available
    if not OPENCL_AVAILABLE:
        print("OpenCL is not available. Make sure you have installed PyOpenCL.")
        print("Falling back to CPU brute force attack...")
        return crack_password_cpu(hash_value, hash_type, charset, min_length, max_length, verbose)
    
    # Perform GPU-accelerated brute force attack
    print("\nUsing GPU-accelerated brute force attack")
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
    
    return password is not None


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


def crack_password_threaded_cpu(hash_value, hash_type, charset, min_length, max_length, 
                              batch_size=100000, threads=None, verbose=False):
    """Crack a password using multi-threaded CPU brute force."""
    hasher = get_hasher(hash_type)
    
    # Perform multi-threaded CPU brute force attack
    print("\nUsing multi-threaded CPU brute force attack")
    password, attempts = cpu_multi_threaded_brute_force_attack(
        hasher=hasher,
        hash_to_crack=hash_value,
        charset=charset,
        min_length=min_length,
        max_length=max_length,
        batch_size=batch_size,
        threads=threads,
        verbose=verbose
    )
    
    return password is not None


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="GPU Password Cracker Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Add basic arguments
    parser.add_argument("--hash", help="The hash to crack")
    parser.add_argument("--password", help="Plaintext password to hash (alternative to --hash)")
    parser.add_argument("--type", choices=["md5", "sha1", "sha256"], default="md5",
                        help="The type of hash (md5, sha1, sha256). Default: md5")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    parser.add_argument("--only-hash", action="store_true", 
                        help="Only generate and display the hash, don't attempt to crack")
    
    # Brute force settings
    parser.add_argument("--min-length", type=int, default=1, 
                        help="Minimum password length for brute force (default: 1)")
    parser.add_argument("--max-length", type=int, default=4, 
                        help="Maximum password length for brute force (default: 4)")
    parser.add_argument("--charset", 
                        help="Custom character set for brute force (defaults to alphanumeric)")
    
    # GPU settings
    parser.add_argument("--platform", type=int, help="OpenCL platform index to use")
    parser.add_argument("--device", type=int, help="OpenCL device index to use")
    parser.add_argument("--batch-size", type=int, default=1000000, 
                        help="Batch size for GPU processing (default: 1,000,000)")
    
    # CPU threading settings
    parser.add_argument("--use-cpu-threads", action="store_true",
                        help="Use multi-threaded CPU cracking instead of GPU")
    parser.add_argument("--threads", type=int,
                        help="Number of CPU threads to use (default: auto-detect)")
    parser.add_argument("--cpu-batch-size", type=int, default=100000,
                        help="Batch size for CPU multi-threaded processing (default: 100,000)")
    
    return parser.parse_args()


def main():
    """Main function."""
    args = parse_arguments()
    
    # Validate arguments
    if not args.hash and not args.password:
        print("Error: You must provide either a hash to crack or a password to hash")
        return False
    
    # Generate a hash if a password is provided
    if args.password:
        hash_value = generate_hash(args.password, args.type)
        print(f"\nGenerated {args.type.upper()} hash for '{args.password}': {hash_value}")
        
        # If only-hash is set, don't attempt to crack
        if args.only_hash:
            return True
        
        print("Attempting to crack the hash to validate functionality...")
    else:
        hash_value = args.hash
    
    # Set default charset if not provided
    if not args.charset:
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    else:
        charset = args.charset
    
    print(f"\nAttempting to crack hash: {hash_value}")
    print(f"Hash type: {args.type}")
    print(f"Character set: {charset}")
    print(f"Length range: {args.min_length} to {args.max_length}")
    
    start_time = time.time()
    
    # Attempt to crack the password
    if args.use_cpu_threads:
        # Use multi-threaded CPU cracking
        success = crack_password_threaded_cpu(
            hash_value=hash_value,
            hash_type=args.type,
            charset=charset,
            min_length=args.min_length,
            max_length=args.max_length,
            batch_size=args.cpu_batch_size,
            threads=args.threads,
            verbose=args.verbose
        )
    else:
        # Use GPU cracking
        success = crack_password_gpu(
            hash_value=hash_value,
            hash_type=args.type,
            charset=charset,
            min_length=args.min_length,
            max_length=args.max_length,
            batch_size=args.batch_size,
            platform_index=args.platform,
            device_index=args.device,
            verbose=args.verbose
        )
    
    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    
    # Print results
    if success:
        print(f"\nSuccess! Password cracked in {elapsed_time:.2f} seconds")
    else:
        print(f"\nFailed to crack password after {elapsed_time:.2f} seconds")
        if args.max_length < 6:
            print("Try increasing --max-length for longer passwords")
    
    return success


if __name__ == "__main__":
    sys.exit(main()) 