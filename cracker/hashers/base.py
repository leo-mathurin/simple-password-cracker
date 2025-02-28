"""
Base class for hash algorithm implementations.
"""

from abc import ABC, abstractmethod


class BaseHasher(ABC):
    """
    Abstract base class for all hashers.
    
    This class defines the interface that all hasher implementations must follow.
    Each specific hash algorithm should subclass this and implement the required methods.
    """
    
    @abstractmethod
    def hash(self, plaintext):
        """
        Hash the given plaintext string.
        
        Args:
            plaintext (str): The plaintext string to hash
            
        Returns:
            str: The resulting hash as a hexadecimal string
        """
        pass
    
    @abstractmethod
    def verify(self, plaintext, hash_to_check):
        """
        Verify if the plaintext matches the given hash.
        
        Args:
            plaintext (str): The plaintext string to check
            hash_to_check (str): The hash to compare against
            
        Returns:
            bool: True if the plaintext matches the hash, False otherwise
        """
        pass
    
    @property
    @abstractmethod
    def name(self):
        """
        Get the name of the hash algorithm.
        
        Returns:
            str: The name of the hash algorithm (e.g., 'MD5', 'SHA-1')
        """
        pass 