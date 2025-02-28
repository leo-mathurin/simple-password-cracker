"""
MD5 hasher implementation.
"""

import hashlib
from .base import BaseHasher


class MD5Hasher(BaseHasher):
    """
    Implementation of the MD5 hashing algorithm.
    """
    
    def hash(self, plaintext):
        """
        Hash the given plaintext using MD5.
        
        Args:
            plaintext (str): The plaintext string to hash
            
        Returns:
            str: The MD5 hash as a hexadecimal string
        """
        # Handle both string and bytes inputs
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        return hashlib.md5(plaintext).hexdigest()
    
    def verify(self, plaintext, hash_to_check):
        """
        Verify if the plaintext matches the given MD5 hash.
        
        Args:
            plaintext (str): The plaintext string to check
            hash_to_check (str): The MD5 hash to compare against
            
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
            str: 'MD5'
        """
        return "MD5" 