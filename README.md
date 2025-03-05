# Simple Password Cracker

A Python-based CLI tool for password cracking using dictionary attacks and brute force methods.

## Features

- Dictionary attack against common hash types (MD5, SHA-1, SHA-256)
- Brute force attack with customizable character sets and length ranges
- Progress tracking for long-running operations
- Online dictionary download from popular repositories
- Generate hashes from plaintext passwords
- Custom dictionary support via direct URLs
- Modular and extensible architecture to support additional attack methods
- Clear output and user-friendly CLI interface

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/simple-password-cracker.git
cd simple-password-cracker

# Create and activate a virtual environment (recommended)
python -m venv venv
# On Windows
venv\Scripts\python.exe -m pip install -e .
# On Unix/macOS
source venv/bin/activate
pip install -e .
```

## Usage

### Basic Password Cracking

```bash
# Basic usage with local dictionary
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --dict wordlist.txt --type md5

# With all options
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --dict wordlist.txt --type md5 --verbose

# Using an online dictionary
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --online-dict rockyou-75 --type md5

# Using a custom dictionary URL
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --online-dict-url https://example.com/wordlist.txt --type md5

# Using plaintext password instead of hash (defaults to SHA-256)
password-cracker --password "mypassword" --online-dict phpbb --verbose

# Specify a different hash type with plaintext password
password-cracker --password "mypassword" --online-dict phpbb --type md5 --verbose

# Using the module directly if the entry point isn't working
python -m cracker.cli --hash "5f4dcc3b5aa765d61d8327deb882cf99" --dict wordlist.txt --type md5
```

### Brute Force Attacks

```bash
# Basic brute force (lowercase letters, length 1-4)
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --type md5 --bruteforce

# Brute force with custom length range
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --type md5 --bruteforce --min-length 4 --max-length 6

# Include uppercase, digits, and special characters
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --type md5 --bruteforce --use-uppercase --use-digits --use-special

# Use a custom character set
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --type md5 --bruteforce --charset "abcdef0123456789"

# Show progress during brute force
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --type md5 --bruteforce --verbose

# Brute force with a plaintext password (for testing/demonstration)
password-cracker --password "abc" --bruteforce --max-length 3 --verbose

# Brute force with a plaintext password and different character sets
password-cracker --password "A1" --bruteforce --use-uppercase --use-digits --verbose
```

### Hash Generation

```bash
# Generate a hash from a plaintext password without cracking (defaults to SHA-256)
password-cracker --password "mypassword" --only-hash

# Generate MD5 hash
password-cracker --password "password123" --type md5 --only-hash
```

### Online Dictionary Management

```bash
# List available online dictionaries
password-cracker --list-dicts

# Download a dictionary without cracking
password-cracker --download rockyou-75

# Download a dictionary to a specific location
password-cracker --download phpbb --output-dir /path/to/save

# Download a dictionary from a custom URL
password-cracker --online-dict-url https://example.com/wordlist.txt --output-dir ./dictionaries
```

### Command-line Arguments

#### Hash Cracking Options
- `--hash`: The hash to crack
- `--password`: A plaintext password to hash (alternative to --hash)
- `--dict`: Path to the local dictionary file
- `--online-dict`: Name of an online dictionary to download and use
- `--online-dict-url`: URL to a custom dictionary to download and use
- `--type`: Hash type (md5, sha1, sha256). Required with --hash, optional with --password (defaults to sha256)
- `--verbose`: Show detailed progress information
- `--only-hash`: Only generate and display the hash, don't attempt to crack (when used with --password)

#### Brute Force Options
- `--bruteforce`: Use brute force attack instead of dictionary
- `--min-length`: Minimum password length for brute force (default: 1)
- `--max-length`: Maximum password length for brute force (default: 4)
- `--use-lowercase`: Include lowercase letters in brute force (default: true)
- `--use-uppercase`: Include uppercase letters in brute force
- `--use-digits`: Include digits in brute force
- `--use-special`: Include special characters in brute force
- `--charset`: Custom character set for brute force (overrides other charset options)

#### Dictionary Management
- `--list-dicts`: List available online dictionaries
- `--download`: Download a specific dictionary without cracking
- `--output-dir`: Directory to save downloaded dictionaries

## Brute Force Best Practices

When using brute force attacks, keep these tips in mind:

1. **Start small**: The default max-length is set to 4 characters because brute force attacks grow exponentially with length
2. **Narrow down**: If you have information about the password (e.g., it's all numeric), use `--charset` to limit possibilities
3. **Expand gradually**: Start with just lowercase, then add other character sets as needed
4. **Be patient**: Brute forcing a password longer than 8 characters with multiple character sets can take a very long time

For example, a brute force attack using all character sets (lowercase, uppercase, digits, special) for an 8-character password would need to try 6,634,204,312,890,625 combinations!

## Project Structure

```
simple-password-cracker/
├── cracker/                       # Main package
│   ├── __init__.py                # Package initialization
│   ├── cli.py                     # Command-line interface
│   ├── cracker.py                 # Core cracking functionality
│   ├── bruteforce.py              # Brute force attack implementation
│   ├── downloader.py              # Dictionary download utilities
│   └── hashers/                   # Hash algorithm implementations
│       ├── __init__.py
│       ├── base.py                # Base hasher class
│       ├── md5.py                 # MD5 implementation
│       ├── sha1.py                # SHA-1 implementation
│       └── sha256.py              # SHA-256 implementation
├── tests/                         # Test directory
├── setup.py                       # Package setup file
├── requirements.txt               # Dependencies
└── README.md                      # This file
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
