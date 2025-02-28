"""
SHA-1 hasher implementation.
"""

import hashlib
from .base import BaseHasher


class SHA1Hasher(BaseHasher):
    """
    Implementation of the SHA-1 hashing algorithm.
    """
    
    def hash(self, plaintext):
        """
        Hash the given plaintext using SHA-1.
        
        Args:
            plaintext (str): The plaintext string to hash
            
        Returns:
            str: The SHA-1 hash as a hexadecimal string
        """
        # Handle both string and bytes inputs
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        return hashlib.sha1(plaintext).hexdigest()
    
    def verify(self, plaintext, hash_to_check):
        """
        Verify if the plaintext matches the given SHA-1 hash.
        
        Args:
            plaintext (str): The plaintext string to check
            hash_to_check (str): The SHA-1 hash to compare against
            
        Returns:
            bool: True if the plaintext matches the hash, False otherwise
        """
        # Convert hash to lowercase for comparison
        calculated_hash = self.hash(plaintext)
        hash_to_check = hash_to_check.lower()
        
        return calculated_hash == hash_to_check
    
    @property
    def name(self):
        """
        Get the name of the hash algorithm.
        
        Returns:
            str: 'SHA-1'
        """
        return "SHA-1" 