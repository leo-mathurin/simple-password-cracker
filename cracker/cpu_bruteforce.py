"""
Multi-threaded CPU brute force attack implementation.
"""

import time
import queue
import threading
import multiprocessing  # Add for cpu_count
from typing import Optional, Tuple, List, Dict, Any
from tqdm import tqdm

from .bruteforce import BruteForceGenerator

# Export this variable to indicate that CPU threading is available
CPU_THREADED_AVAILABLE = True

# Sentinel value to signal threads to terminate
SENTINEL = object()

class CpuBruteForce:
    """Multi-threaded CPU brute force password cracking."""
    
    def __init__(self, hasher, charset: str, min_length: int = 1, max_length: int = 8,
                 batch_size: int = 100000, threads: int = None, verbose: bool = False):
        """
        Initialize the multi-threaded CPU brute force password cracker.
        
        Args:
            hasher: The hasher object to use
            charset: String containing characters to use in brute force
            min_length: Minimum password length to try
            max_length: Maximum password length to try
            batch_size: Number of passwords to process in each batch
            threads: Number of threads to use (None = auto-detect)
            verbose: Whether to print progress information
        """
        self.hasher = hasher
        self.charset = charset
        self.min_length = min_length
        self.max_length = max_length
        self.batch_size = batch_size
        self.verbose = verbose
        
        # Auto-detect number of threads if not specified
        if threads is None:
            # Use cpu_count-1 to leave one CPU core free for system tasks
            # but never use less than 1 thread
            self.threads = max(1, multiprocessing.cpu_count() - 1)  # Use multiprocessing instead of threading
        else:
            self.threads = max(1, threads)  # Ensure at least 1 thread
            
        # Generator for passwords
        self.generator = BruteForceGenerator(
            min_length=min_length,
            max_length=max_length,
            custom_chars=charset
        )
        
        # Performance metrics
        self.start_time = None
        self.total_attempts = 0
        self.last_attempts = 0
        self.last_time = None
        
        # Thread synchronization
        self.password_queue = queue.Queue(maxsize=self.threads * 2)
        self.result_queue = queue.Queue()
        self.stop_event = threading.Event()
        # Add a lock for updating the total_attempts counter
        self.attempts_lock = threading.Lock()
        
    def _worker(self, worker_id: int):
        """Worker thread function that processes passwords from the queue."""
        local_attempts = 0  # Track attempts locally first
        
        while not self.stop_event.is_set():
            try:
                # Get batch of passwords from queue with timeout
                batch = self.password_queue.get(timeout=1)
                if batch is SENTINEL:
                    # Put sentinel back for other threads and exit
                    self.password_queue.put(SENTINEL)
                    break
                    
                # Process this batch of passwords
                for password in batch:
                    # Check if we should stop
                    if self.stop_event.is_set():
                        break
                    
                    local_attempts += 1
                        
                    # Check if this password matches
                    if self.hasher.verify(password, self.target_hash):
                        # Found the password, put it in the result queue
                        self.result_queue.put(password)
                        self.stop_event.set()
                        break
                
                # Update the total attempts counter with our local count
                with self.attempts_lock:
                    self.total_attempts += local_attempts
                    local_attempts = 0
                        
                # Mark task as done
                self.password_queue.task_done()
                
            except queue.Empty:
                # Queue is empty, check if we should continue
                continue
                
        # Make sure we update the total with any remaining local attempts
        if local_attempts > 0:
            with self.attempts_lock:
                self.total_attempts += local_attempts
        
    def _password_generator(self):
        """Generate passwords in batches and feed them to the worker threads."""
        # For each possible password length
        for length in range(self.min_length, self.max_length + 1):
            if self.verbose:
                print(f"Trying passwords of length {length}...")
                
                # Calculate total for this length
                charset_length = len(self.charset)
                total_for_length = charset_length ** length
                print(f"Total combinations for length {length}: {total_for_length:,}")
            
            # Process in batches
            batch = []
            batch_size = 0
            
            # Generate all combinations of the current length
            generator = self.generator.generate_length(length)
            for password in generator:
                batch.append(password)
                batch_size += 1
                
                if batch_size >= self.batch_size:
                    # Check if we should stop
                    if self.stop_event.is_set():
                        return
                        
                    # Put the batch in the queue and start a new one
                    self.password_queue.put(batch)
                    batch = []
                    batch_size = 0
            
            # Put the final batch in the queue if it's not empty
            if batch:
                self.password_queue.put(batch)
                
        # Signal the worker threads to terminate
        self.password_queue.put(SENTINEL)
            
    def _update_progress(self):
        """Update and display progress information."""
        last_status_time = time.time()
        last_status_attempts = 0
        
        while not self.stop_event.is_set():
            time.sleep(1.0)  # Update every second (reduced from 0.5)
            
            if self.stop_event.is_set():
                break
                
            current_time = time.time()
            if self.last_time is None:
                self.last_time = current_time
                continue
                
            # Calculate time elapsed since last update
            elapsed = current_time - self.last_time
            if elapsed < 2.0:  # Only update if at least 2 seconds have passed (increased from 1.0)
                continue
                
            # Calculate speed
            with self.attempts_lock:
                current_attempts = self.total_attempts
                
            attempts_since_last = current_attempts - self.last_attempts
            speed = attempts_since_last / elapsed if elapsed > 0 else 0
            
            if self.verbose:
                # Calculate overall progress stats - only every 5 seconds
                overall_elapsed = current_time - self.start_time
                if current_time - last_status_time >= 5.0:
                    last_status_time = current_time
                    overall_speed = current_attempts / overall_elapsed if overall_elapsed > 0 else 0
                    
                    # Avoid too many print statements to prevent console buffer issues
                    print(f"\rProgress: {current_attempts:,} passwords checked | "
                          f"Speed: {speed/1000000:.2f} million/s | "
                          f"Threads: {self.threads}", end="", flush=True)
                
            # Update last values
            self.last_time = current_time
            self.last_attempts = current_attempts
    
    def crack(self, target_hash: str) -> Tuple[Optional[str], int]:
        """
        Attempt to crack the password hash using multiple CPU threads.
        
        Args:
            target_hash: The hash to crack
            
        Returns:
            Tuple of (cracked password or None, number of attempts)
        """
        self.target_hash = target_hash
        self.start_time = time.time()
        self.total_attempts = 0
        self.last_attempts = 0
        self.last_time = None
        
        try:
            if self.verbose:
                print(f"Starting multi-threaded CPU brute force attack with {self.threads} threads")
                print(f"Character set: {self.charset}")
                print(f"Password length range: {self.min_length} to {self.max_length}")
                
            # Start worker threads
            threads = []
            for i in range(self.threads):
                t = threading.Thread(target=self._worker, args=(i,))
                t.daemon = True  # Make thread daemon so it doesn't prevent program exit
                t.start()
                threads.append(t)
                
            # Start progress reporting thread
            progress_thread = threading.Thread(target=self._update_progress)
            progress_thread.daemon = True
            progress_thread.start()
            
            # Start password generation - this runs on the main thread
            self._password_generator()
            
            # Wait for a result or for all threads to finish
            password = None
            try:
                # Wait for a result with timeout
                password = self.result_queue.get(timeout=1)
            except queue.Empty:
                # No result yet, wait for threads to finish
                pass
                
            # Wait for all threads to finish with timeout to prevent hanging
            for t in threads:
                t.join(timeout=1.0)
                
            # Stop the progress thread
            self.stop_event.set()
            progress_thread.join(timeout=1.0)
            
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            if self.verbose:
                print("\nCracking interrupted by user.")
            self.stop_event.set()
            return None, self.total_attempts
        except Exception as e:
            # Handle any other exceptions
            if self.verbose:
                print(f"\nError during cracking: {str(e)}")
            self.stop_event.set()
            return None, self.total_attempts
        finally:
            # Make sure the progress output gets a newline
            if self.verbose:
                print()
        
        # Calculate total time
        total_time = time.time() - self.start_time
        
        if password:
            if self.verbose:
                print(f"\nPassword found: {password}")
                print(f"Time taken: {total_time:.2f} seconds")
                print(f"Attempts: {self.total_attempts:,}")
        else:
            if self.verbose:
                print("\nPassword not found")
                print(f"Time taken: {total_time:.2f} seconds")
                print(f"Attempts: {self.total_attempts:,}")
                
        return password, self.total_attempts


def cpu_multi_threaded_brute_force_attack(hasher, hash_to_crack: str, charset: str,
                                          min_length: int = 1, max_length: int = 8,
                                          batch_size: int = 100000, threads: int = None,
                                          verbose: bool = False) -> Tuple[Optional[str], int]:
    """
    Use multi-threaded CPU acceleration to perform a brute force attack against a password hash.
    
    Args:
        hasher: Hash function to use
        hash_to_crack: Hash to attempt to crack
        charset: String containing characters to use in brute force
        min_length: Minimum password length to try
        max_length: Maximum password length to try
        batch_size: Number of passwords to try in each batch
        threads: Number of threads to use (None = auto-detect)
        verbose: Whether to print progress information
        
    Returns:
        Tuple of (cracked password or None if not found, attempts made)
    """
    # Create and run CPU brute forcer
    brute_forcer = CpuBruteForce(
        hasher=hasher,
        charset=charset,
        min_length=min_length,
        max_length=max_length,
        batch_size=batch_size,
        threads=threads,
        verbose=verbose
    )
    
    return brute_forcer.crack(hash_to_crack) 