"""
Hash algorithm implementations for the password cracker.
"""

from .base import BaseHasher
from .md5 import MD5Hasher
from .sha1 import SHA1Hasher
from .sha256 import SHA256Hasher

# Dictionary mapping hash types to their hasher classes
HASHERS = {
    'md5': MD5Hasher,
    'sha1': SHA1Hasher,
    'sha256': SHA256Hasher,
}

def get_hasher(hash_type):
    """
    Factory function to get the appropriate hasher for a given hash type.
    
    Args:
        hash_type (str): The type of hash to use (md5, sha1, sha256)
        
    Returns:
        BaseHasher: An instance of the appropriate hasher class
        
    Raises:
        ValueError: If the hash type is not supported
    """
    hash_type = hash_type.lower()
    if hash_type not in HASHERS:
        raise ValueError(f"Unsupported hash type: {hash_type}. Supported types: {', '.join(HASHERS.keys())}")
    
    return HASHERS[hash_type]() 