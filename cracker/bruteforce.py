"""
Brute force attack implementation.
"""

import itertools
import string
from typing import Generator, Optional
from tqdm import tqdm


class BruteForceGenerator:
    """Generator for brute force password attempts."""
    
    # Predefined character sets
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SPECIAL = string.punctuation
    
    def __init__(self, min_length: int = 1, max_length: int = 8,
                 use_lowercase: bool = True, use_uppercase: bool = False,
                 use_digits: bool = False, use_special: bool = False,
                 custom_chars: Optional[str] = None):
        """
        Initialize the brute force generator.
        
        Args:
            min_length: Minimum password length to try
            max_length: Maximum password length to try
            use_lowercase: Include lowercase letters
            use_uppercase: Include uppercase letters
            use_digits: Include digits
            use_special: Include special characters
            custom_chars: Custom character set to use (if provided, other options are ignored)
        """
        self.min_length = min_length
        self.max_length = max_length
        
        # Build character set
        if custom_chars is not None:
            self.charset = custom_chars
        else:
            charset_parts = []
            if use_lowercase:
                charset_parts.append(self.LOWERCASE)
            if use_uppercase:
                charset_parts.append(self.UPPERCASE)
            if use_digits:
                charset_parts.append(self.DIGITS)
            if use_special:
                charset_parts.append(self.SPECIAL)
            
            if not charset_parts:
                # Default to lowercase if nothing selected
                charset_parts.append(self.LOWERCASE)
            
            self.charset = ''.join(charset_parts)
            
    def generate(self) -> Generator[str, None, None]:
        """
        Generate all possible combinations.
        
        Yields:
            str: Each possible password combination
        """
        # For each length in the range
        for length in range(self.min_length, self.max_length + 1):
            # Generate all combinations of the current length
            for combo in itertools.product(self.charset, repeat=length):
                yield ''.join(combo)
                
    @property
    def total_combinations(self) -> int:
        """
        Calculate total number of combinations that will be tried.
        
        Returns:
            int: Total number of possible combinations
        """
        total = 0
        charset_length = len(self.charset)
        for length in range(self.min_length, self.max_length + 1):
            total += charset_length ** length
        return total


def brute_force_attack(hasher, hash_to_crack: str, generator: BruteForceGenerator,
                      verbose: bool = False) -> tuple[Optional[str], int]:
    """
    Perform a brute force attack.
    
    Args:
        hasher: The hasher object to use
        hash_to_crack: The hash to crack
        generator: BruteForceGenerator instance
        verbose: Whether to show progress
        
    Returns:
        tuple: (cracked password or None, number of attempts)
    """
    attempts = 0
    total = generator.total_combinations
    
    if verbose:
        print("\nStarting brute force attack...")
        print(f"Character set: {generator.charset}")
        print(f"Length range: {generator.min_length} to {generator.max_length}")
        print(f"Total combinations to try: {total:,}\n")
    
    # Try each combination
    with tqdm(total=total, desc="Trying passwords", disable=not verbose, unit="pwd") as pbar:
        for password in generator.generate():
            attempts += 1
            pbar.update(1)
                
            if hasher.verify(password, hash_to_crack):
                return password, attempts
                
    return None, attempts 