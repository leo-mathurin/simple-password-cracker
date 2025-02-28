"""
Command-line interface for the password cracker.
"""

import argparse
import sys
import time
from . import __version__
from .hashers import get_hasher
from .cracker import PasswordCracker


def main():
    """
    Main entry point for the password cracker CLI.
    """
    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Simple Password Cracker - A tool for cracking password hashes using dictionary attacks",
        epilog="Example: password-cracker --hash 5f4dcc3b5aa765d61d8327deb882cf99 --dict wordlist.txt --type md5"
    )
    
    # Add arguments
    parser.add_argument("--hash", required=True, help="The hash to crack")
    parser.add_argument("--dict", required=True, help="Path to the dictionary file")
    parser.add_argument("--type", required=True, choices=["md5", "sha1", "sha256"], 
                        help="The type of hash (md5, sha1, sha256)")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    parser.add_argument("--version", action="version", version=f"Simple Password Cracker v{__version__}")
    
    # Parse arguments
    args = parser.parse_args()
    
    try:
        # Get the appropriate hasher
        hasher = get_hasher(args.type)
        
        # Create the password cracker
        cracker = PasswordCracker(hasher)
        
        # Record start time
        start_time = time.time()
        
        # Perform the dictionary attack
        password, attempts = cracker.dictionary_attack(args.hash, args.dict, args.verbose)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        # Display results
        print("\n" + "=" * 60)
        print(f"Hash: {args.hash}")
        print(f"Hash Type: {hasher.name}")
        print(f"Dictionary: {args.dict}")
        print(f"Attempts: {attempts:,}")
        print(f"Time Elapsed: {elapsed_time:.2f} seconds")
        print(f"Passwords Tested per Second: {attempts / elapsed_time:.2f}")
        
        if password:
            print("\n🎉 PASSWORD FOUND!")
            print(f"The password is: {password}")
            return 0
        else:
            print("\n❌ Password not found in dictionary.")
            return 1
            
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCracking interrupted by user.")
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main()) 