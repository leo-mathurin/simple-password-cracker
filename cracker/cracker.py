"""
Core password cracking functionality.
"""

from tqdm import tqdm


class PasswordCracker:
    """
    Core password cracking implementation.
    """
    
    def __init__(self, hasher):
        """
        Initialize the password cracker with a specific hasher.
        
        Args:
            hasher: An instance of a BaseHasher subclass for hashing passwords
        """
        self.hasher = hasher
    
    def dictionary_attack(self, target_hash, dictionary_path, verbose=False):
        """
        Perform a dictionary attack on the target hash.
        
        Args:
            target_hash (str): The hash to crack
            dictionary_path (str): Path to the dictionary file
            verbose (bool): Whether to show verbose output
            
        Returns:
            tuple: (password, attempts) if found, or (None, attempts) if not found
            
        Raises:
            FileNotFoundError: If the dictionary file cannot be found
        """
        attempts = 0
        target_hash = target_hash.lower()
        
        # Count lines for progress bar
        with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
            total_lines = sum(1 for _ in f)
        
        # Open the dictionary file and try each word
        with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
            if verbose:
                print(f"Starting dictionary attack using {self.hasher.name} algorithm...")
                print(f"Target hash: {target_hash}")
                print(f"Dictionary: {dictionary_path} ({total_lines} words)")
                print("-" * 60)
            
            # Create a progress bar
            progress_bar = tqdm(total=total_lines, desc="Trying passwords", unit="word")
            
            for line in f:
                # Strip whitespace and newlines
                password = line.strip()
                attempts += 1
                
                # Update progress bar
                progress_bar.update(1)
                if verbose and attempts % 10000 == 0:
                    progress_bar.set_description(f"Trying passwords (last: {password})")
                
                # Check if the password matches the hash
                if self.hasher.verify(password, target_hash):
                    progress_bar.close()
                    return password, attempts
            
            # If we get here, the password was not found
            progress_bar.close()
            return None, attempts
            
    def generate_hash(self, plaintext):
        """
        Generate a hash for the given plaintext.
        
        Args:
            plaintext (str): The plaintext to hash
            
        Returns:
            str: The resulting hash
        """
        return self.hasher.hash(plaintext) 