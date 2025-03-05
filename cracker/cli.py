"""
Command-line interface for the password cracker.
"""

import argparse
import os
import sys
import time
import requests
from tqdm import tqdm
from . import __version__
from .hashers import get_hasher
from .cracker import PasswordCracker
from .bruteforce import BruteForceGenerator, brute_force_attack

# Try to import the GPU brute force module
GPU_MODULE_AVAILABLE = False
GPU_AVAILABLE = False
OPENCL_AVAILABLE = False

try:
    from .gpu_bruteforce import gpu_brute_force_attack, GPU_AVAILABLE, OPENCL_AVAILABLE
    GPU_MODULE_AVAILABLE = True
except ImportError as e:
    # More detailed error message to help with debugging
    print(f"GPU module import error: {e}")
    
    # For development - try importing the module directly if the relative import fails
    try:
        # This is a fallback for development/debugging only
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from cracker.gpu_bruteforce import gpu_brute_force_attack, GPU_AVAILABLE, OPENCL_AVAILABLE
        GPU_MODULE_AVAILABLE = True
        print("GPU module imported via fallback path")
    except ImportError as e2:
        print(f"GPU module fallback import error: {e2}")
        print("If you want GPU acceleration, make sure pyopencl is installed.")
        GPU_MODULE_AVAILABLE = False
        GPU_AVAILABLE = False
        OPENCL_AVAILABLE = False
except Exception as e:
    print(f"Unexpected error importing GPU module: {e}")
    GPU_MODULE_AVAILABLE = False
    GPU_AVAILABLE = False
    OPENCL_AVAILABLE = False

# Try to import the multi-threaded CPU brute force module
CPU_THREADED_AVAILABLE = False
try:
    from .cpu_bruteforce import cpu_multi_threaded_brute_force_attack
    CPU_THREADED_AVAILABLE = True
except ImportError as e:
    print(f"CPU multi-threading module import error: {e}")
    
    # For development - try importing the module directly if the relative import fails
    try:
        # This is a fallback for development/debugging only
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from cracker.cpu_bruteforce import cpu_multi_threaded_brute_force_attack
        CPU_THREADED_AVAILABLE = True
        print("CPU multi-threading module imported via fallback path")
    except ImportError as e2:
        print(f"CPU multi-threading fallback import error: {e2}")

try:
    from .downloader import download_wordlist, list_available_wordlists
    DOWNLOADER_AVAILABLE = True
except ImportError:
    DOWNLOADER_AVAILABLE = False


def download_from_url(url, output_dir=None):
    """
    Download a dictionary from a custom URL.
    
    Args:
        url (str): The URL to download from
        output_dir (str, optional): Directory to save the dictionary. Defaults to current directory.
        
    Returns:
        str: Path to the downloaded file
        
    Raises:
        requests.RequestException: If the download fails
    """
    # Determine output directory
    if output_dir is None:
        output_dir = os.getcwd()
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename from the URL (use the last part of the URL path)
    filename = os.path.basename(url.split('?')[0])  # Remove query parameters if any
    if not filename:
        filename = "custom_dictionary.txt"
    
    output_path = os.path.join(output_dir, filename)
    
    # Download the file with progress bar
    print(f"Downloading dictionary from {url}...")
    response = requests.get(url, stream=True)
    response.raise_for_status()  # Raise an exception for HTTP errors
    
    # Get file size from headers if available
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 KB
    
    with open(output_path, 'wb') as f:
        with tqdm(total=total_size, unit='B', unit_scale=True, desc="Dictionary") as pbar:
            for data in response.iter_content(block_size):
                f.write(data)
                pbar.update(len(data))
    
    print(f"Dictionary downloaded to {output_path}")
    return output_path


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
        
        # Use a dictionary from a custom URL
        password-cracker --hash 5f4dcc3b5aa765d61d8327deb882cf99 --online-dict-url https://example.com/wordlist.txt --type md5
        
        # Brute force attack with default settings (lowercase, length 1-8)
        password-cracker --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --bruteforce
        
        # Brute force with custom settings
        password-cracker --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --bruteforce --min-length 4 --max-length 6 --use-digits --use-special
        
        # Brute force with a plaintext password for testing 
        password-cracker --password "mypassword" --bruteforce --max-length 4
        """
    )
    
    # Add arguments for hash cracking
    parser.add_argument("--hash", help="The hash to crack")
    parser.add_argument("--password", help="Plaintext password to hash (alternative to --hash)")
    parser.add_argument("--dict", help="Path to the dictionary file")
    parser.add_argument("--online-dict", help="Download and use an online dictionary by name")
    parser.add_argument("--online-dict-url", help="Download and use a dictionary from a custom URL")
    parser.add_argument("--type", choices=["md5", "sha1", "sha256"], 
                        help="The type of hash (md5, sha1, sha256). Defaults to sha256 when using --password")
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")
    parser.add_argument("--only-hash", action="store_true", help="Only generate and display the hash, don't attempt to crack")
    
    # Add arguments for brute force attack
    parser.add_argument("--bruteforce", action="store_true", help="Use brute force attack instead of dictionary")
    parser.add_argument("--min-length", type=int, default=1, help="Minimum password length for brute force (default: 1)")
    parser.add_argument("--max-length", type=int, default=4, help="Maximum password length for brute force (default: 4)")
    parser.add_argument("--use-lowercase", action="store_true", help="Include lowercase letters in brute force (default: true)")
    parser.add_argument("--use-uppercase", action="store_true", help="Include uppercase letters in brute force")
    parser.add_argument("--use-digits", action="store_true", help="Include digits in brute force")
    parser.add_argument("--use-special", action="store_true", help="Include special characters in brute force")
    parser.add_argument("--charset", help="Custom character set for brute force (overrides other charset options)")
    
    # Add GPU acceleration arguments
    parser.add_argument("--use-gpu", action="store_true", help="Use GPU acceleration for brute force attack (if available)")
    parser.add_argument("--gpu-batch-size", type=int, default=1000000, help="Batch size for GPU processing (default: 1,000,000)")
    parser.add_argument("--opencl-platform", type=int, help="OpenCL platform index to use")
    parser.add_argument("--opencl-device", type=int, help="OpenCL device index to use")
    
    # Add CPU multi-threading arguments
    parser.add_argument("--use-threads", action="store_true", help="Use CPU multi-threading for brute force attack")
    parser.add_argument("--threads", type=int, help="Number of CPU threads to use (default: auto-detect)")
    parser.add_argument("--cpu-batch-size", type=int, default=100000, help="Batch size for CPU multi-threaded processing (default: 100,000)")
    
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
        original_password = None
        if args.password is not None:
            original_password = args.password
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
        
        # Set up the appropriate attack method
        use_bruteforce = args.bruteforce
        use_dictionary = (args.dict is not None or args.online_dict is not None or args.online_dict_url is not None)
        
        # If neither attack method is specified and we have a plaintext password, 
        # just show the hash and exit to avoid confusion
        if not use_bruteforce and not use_dictionary and original_password is not None:
            print("\nNo attack method (dictionary or brute force) specified. Use --bruteforce, --dict, --online-dict, or --online-dict-url")
            return 0
        
        # If no attack method is specified at all, error
        if not use_bruteforce and not use_dictionary:
            print("Error: Either specify --bruteforce or provide a dictionary (--dict, --online-dict, or --online-dict-url)", file=sys.stderr)
            return 1
        
        # If both brute force and dictionary are specified, prioritize brute force
        if use_bruteforce and use_dictionary:
            print("Warning: Both brute force and dictionary options specified. Using brute force attack.")
        
        # If the user provided a plaintext password and brute force is enabled, inform them 
        # that we're using the password's hash for brute force validation
        if use_bruteforce and original_password is not None:
            print(f"\nUsing brute force attack to simulate cracking the password: {original_password}")
            print(f"(This is just a demonstration to validate the brute force functionality)")
            
        # Record start time
        start_time = time.time()
        
        if use_bruteforce:
            # Handle brute force attack if requested
            custom_charset = args.charset
            if not custom_charset:
                # Build character set based on flags
                charset_parts = []
                if args.use_lowercase or (not args.use_uppercase and not args.use_digits and not args.use_special):
                    charset_parts.append("abcdefghijklmnopqrstuvwxyz")
                if args.use_uppercase:
                    charset_parts.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                if args.use_digits:
                    charset_parts.append("0123456789")
                if args.use_special:
                    charset_parts.append("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
                custom_charset = "".join(charset_parts)
            
            print(f"\n=== Brute Force Attack ===")
            print(f"Target hash: {hash_to_crack}")
            print(f"Character set: {custom_charset}")
            print(f"Min length: {args.min_length}")
            print(f"Max length: {args.max_length}")
            
            # Check if GPU acceleration should be used
            use_gpu = args.use_gpu and GPU_MODULE_AVAILABLE
            use_threads = args.use_threads and CPU_THREADED_AVAILABLE
            
            if use_gpu:
                # Use GPU-accelerated brute force
                print("\nUsing GPU-accelerated brute force attack with OpenCL")
                password, attempts = gpu_brute_force_attack(
                    hasher=hasher,
                    hash_to_crack=hash_to_crack,
                    charset=custom_charset,
                    min_length=args.min_length,
                    max_length=args.max_length,
                    batch_size=args.gpu_batch_size,
                    verbose=args.verbose,
                    platform_index=args.opencl_platform,
                    device_index=args.opencl_device
                )
            elif use_threads:
                # Use multi-threaded CPU brute force
                print("\nUsing multi-threaded CPU brute force attack")
                password, attempts = cpu_multi_threaded_brute_force_attack(
                    hasher=hasher,
                    hash_to_crack=hash_to_crack,
                    charset=custom_charset,
                    min_length=args.min_length,
                    max_length=args.max_length,
                    batch_size=args.cpu_batch_size,
                    threads=args.threads,
                    verbose=args.verbose
                )
            else:
                # Use CPU brute force
                # Create brute force generator with specified options
                generator = BruteForceGenerator(
                    min_length=args.min_length,
                    max_length=args.max_length,
                    use_lowercase=True,  # Always true unless custom charset is provided
                    use_uppercase=args.use_uppercase,
                    use_digits=args.use_digits,
                    use_special=args.use_special,
                    custom_chars=args.charset
                )
                
                # Perform brute force attack
                password, attempts = brute_force_attack(hasher, hash_to_crack, generator, args.verbose)
        else:
            # Handle dictionary options in order of preference
            dictionary_path = args.dict
            
            # Handle online dictionary by name if requested
            if dictionary_path is None and args.online_dict is not None:
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
                    
            # Handle custom URL dictionary if requested
            if dictionary_path is None and args.online_dict_url is not None:
                try:
                    dictionary_path = download_from_url(args.online_dict_url, args.output_dir)
                except requests.RequestException as e:
                    print(f"Error downloading dictionary from URL: {e}", file=sys.stderr)
                    return 1
                except Exception as e:
                    print(f"Unexpected error downloading dictionary: {e}", file=sys.stderr)
                    return 1
            
            # Create the password cracker
            cracker = PasswordCracker(hasher)
            
            # Perform the dictionary attack
            password, attempts = cracker.dictionary_attack(hash_to_crack, dictionary_path, args.verbose)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        # Display results
        print("\n" + "=" * 60)
        print(f"Hash: {hash_to_crack}")
        print(f"Hash Type: {hasher.name}")
        if not use_bruteforce:
            print(f"Dictionary: {dictionary_path}")
        else:
            char_desc = []
            if args.charset:
                char_desc.append(f"Custom charset: {args.charset}")
            else:
                char_desc.append("Lowercase letters")
                if args.use_uppercase:
                    char_desc.append("Uppercase letters")
                if args.use_digits:
                    char_desc.append("Digits")
                if args.use_special:
                    char_desc.append("Special characters")
            
            print(f"Brute Force Settings: {', '.join(char_desc)}")
            print(f"Length Range: {args.min_length} to {args.max_length}")
            if args.use_gpu and GPU_AVAILABLE:
                print("GPU Acceleration: OpenCL")
                
        print(f"Attempts: {attempts:,}")
        print(f"Time Elapsed: {elapsed_time:.2f} seconds")
        print(f"Passwords Tested per Second: {attempts / elapsed_time:.2f}")
        
        if password:
            print("\n🎉 PASSWORD FOUND!")
            print(f"The password is: {password}")
            
            # If this was a demo with a plaintext password, verify it matches
            if original_password is not None and password == original_password:
                print(f"\n✅ The cracked password matches the original input.")
            return 0
        else:
            print("\n❌ Password not found.")
            
            # If this was a demo with a plaintext password that wasn't found, show a helpful message
            if original_password is not None:
                if args.max_length < len(original_password):
                    print(f"\nHint: The original password '{original_password}' has {len(original_password)} characters, " 
                          f"but max-length was set to {args.max_length}.")
                    print(f"Try again with --max-length {len(original_password)} or higher.")
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