# Simple Password Cracker

A Python-based CLI tool for password cracking using dictionary attacks.

## Features

- Dictionary attack against common hash types (MD5, SHA-1, SHA-256)
- Progress tracking for long-running operations
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

```bash
# Basic usage
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --dict wordlist.txt --type md5

# With all options
password-cracker --hash "5f4dcc3b5aa765d61d8327deb882cf99" --dict wordlist.txt --type md5 --verbose

# Using the module directly if the entry point isn't working
python -m cracker.cli --hash "5f4dcc3b5aa765d61d8327deb882cf99" --dict wordlist.txt --type md5
```

### Command-line Arguments

- `--hash`: The hash to crack
- `--dict`: Path to the dictionary file
- `--type`: Hash type (md5, sha1, sha256)
- `--verbose`: Show detailed progress information

## Project Structure

```
simple-password-cracker/
├── cracker/                       # Main package
│   ├── __init__.py                # Package initialization
│   ├── cli.py                     # Command-line interface
│   ├── cracker.py                 # Core cracking functionality
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
