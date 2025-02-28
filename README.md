# Simple Password Cracker

A Python-based CLI tool for password cracking using dictionary attacks.

## Features

- Dictionary attack against common hash types (MD5, SHA-1, SHA-256)
- Progress tracking for long-running operations
- Online dictionary download from popular repositories
- Generate hashes from plaintext passwords
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

# Using plaintext password instead of hash (defaults to SHA-256)
password-cracker --password "mypassword" --online-dict phpbb --verbose

# Specify a different hash type with plaintext password
password-cracker --password "mypassword" --online-dict phpbb --type md5 --verbose

# Using the module directly if the entry point isn't working
python -m cracker.cli --hash "5f4dcc3b5aa765d61d8327deb882cf99" --dict wordlist.txt --type md5
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
```

### Command-line Arguments

#### Hash Cracking Options
- `--hash`: The hash to crack
- `--password`: A plaintext password to hash (alternative to --hash)
- `--dict`: Path to the local dictionary file
- `--online-dict`: Name of an online dictionary to download and use
- `--type`: Hash type (md5, sha1, sha256). Required with --hash, optional with --password (defaults to sha256)
- `--verbose`: Show detailed progress information
- `--only-hash`: Only generate and display the hash, don't attempt to crack (when used with --password)

#### Dictionary Management
- `--list-dicts`: List available online dictionaries
- `--download`: Download a specific dictionary without cracking
- `--output-dir`: Directory to save downloaded dictionaries

## Project Structure

```
simple-password-cracker/
├── cracker/                       # Main package
│   ├── __init__.py                # Package initialization
│   ├── cli.py                     # Command-line interface
│   ├── cracker.py                 # Core cracking functionality
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
