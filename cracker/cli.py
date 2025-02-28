"""
Command-line interface for the password cracker.
"""

import argparse
import os
import sys
import time
from . import __version__
from .hashers import get_hasher
from .cracker import PasswordCracker
try:
    from .downloader import download_wordlist, list_available_wordlists
    DOWNLOADER_AVAILABLE = True
except ImportError:
    DOWNLOADER_AVAILABLE = False


def main():
    """
    Main entry point for the password cracker CLI.
    """
    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Simple Password Cracker - A tool for cracking password hashes using dictionary attacks",
        epilog="""Examples:
        # Crack an MD5 hash using a local dictionary
        password-cracker --hash 5f4dcc3b5aa765d61d8327deb882cf99 --dict wordlist.txt --type md5
        
        # Crack a hash using an online dictionary
        password-cracker --hash 5f4dcc3b5aa765d61d8327deb882cf99 --online-dict rockyou-75 --type md5
        
        # Generate a hash from a plaintext password
        password-cracker --password "mypassword" --only-hash
        
        # Crack a plaintext password (automatically hashed with SHA-256)
        password-cracker --password "mypassword" --online-dict phpbb
        """
    )
    
    # Add arguments for hash cracking
    parser.add_argument("--hash", help="The hash to crack")
    parser.add_argument("--password", help="Plaintext password to hash (alternative to --hash)")
    parser.add_argument("--dict", help="Path to the dictionary file")
    parser.add_argument("--online-dict", help="Download and use an online dictionary by name")
    parser.add_argument("--type", choices=["md5", "sha1", "sha256"], 
                        help="The type of hash (md5, sha1, sha256). Defaults to sha256 when using --password")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    parser.add_argument("--only-hash", action="store_true", help="Only generate and display the hash, don't attempt to crack")
    
    # Add arguments for dictionary management
    parser.add_argument("--list-dicts", action="store_true", help="List available online dictionaries")
    parser.add_argument("--download", help="Download a dictionary without cracking")
    parser.add_argument("--output-dir", help="Directory to save downloaded dictionaries")
    
    # Version information
    parser.add_argument("--version", action="version", version=f"Simple Password Cracker v{__version__}")
    
    # Parse arguments
    args = parser.parse_args()
    
    # If no arguments are provided, show help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    try:
        # Handle dictionary listing and downloading
        if args.list_dicts:
            if not DOWNLOADER_AVAILABLE:
                print("Error: Dictionary downloader is not available. Install 'requests' package.", file=sys.stderr)
                return 1
            
            print("Available online dictionaries:")
            for dict_name in list_available_wordlists():
                print(f"  - {dict_name}")
            return 0
            
        if args.download:
            if not DOWNLOADER_AVAILABLE:
                print("Error: Dictionary downloader is not available. Install 'requests' package.", file=sys.stderr)
                return 1
                
            try:
                download_wordlist(args.download, args.output_dir)
                return 0
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Error downloading dictionary: {e}", file=sys.stderr)
                return 1
        
        # Set default hash type to SHA-256 when using password
        hash_type = args.type
        if args.password is not None and hash_type is None:
            hash_type = "sha256"
            print("No hash type specified, defaulting to SHA-256")
        
        # Check if hash type is provided for hash cracking
        if hash_type is None and args.hash is not None:
            print("Error: --type is required when using --hash", file=sys.stderr)
            return 1
            
        # Get the appropriate hasher
        hasher = get_hasher(hash_type)
        
        # Handle password to hash generation
        hash_to_crack = args.hash
        if args.password is not None:
            # Generate hash from password
            hash_to_crack = hasher.hash(args.password)
            print(f"\n=== Generated {hash_type.upper()} Hash ===")
            print(f"Password: {args.password}")
            print(f"Hash: {hash_to_crack}")
            
            # If only-hash flag is provided, exit after showing the hash
            if args.only_hash:
                return 0
                
        # Validate arguments for hash cracking
        if hash_to_crack is None:
            print("Error: Either --hash or --password is required for cracking", file=sys.stderr)
            return 1
            
        # Check if dictionary is provided for cracking
        if args.dict is None and args.online_dict is None:
            print("Error: Either --dict or --online-dict is required for cracking", file=sys.stderr)
            return 1
            
        # Handle online dictionary if requested
        dictionary_path = args.dict
        if args.online_dict:
            if not DOWNLOADER_AVAILABLE:
                print("Error: Dictionary downloader is not available. Install 'requests' package.", file=sys.stderr)
                return 1
                
            try:
                dictionary_path = download_wordlist(args.online_dict, args.output_dir)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Error downloading dictionary: {e}", file=sys.stderr)
                return 1
        
        # Create the password cracker
        cracker = PasswordCracker(hasher)
        
        # Record start time
        start_time = time.time()
        
        # Perform the dictionary attack
        password, attempts = cracker.dictionary_attack(hash_to_crack, dictionary_path, args.verbose)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        # Display results
        print("\n" + "=" * 60)
        print(f"Hash: {hash_to_crack}")
        print(f"Hash Type: {hasher.name}")
        print(f"Dictionary: {dictionary_path}")
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