import hashlib
from cracker.cpu_bruteforce import cpu_multi_threaded_brute_force_attack
from cracker.hashers import get_hasher

# Hash of the word 'test'
test_hash = '098f6bcd4621d373cade4e832627b4f6'

# Get the MD5 hasher
hasher = get_hasher('md5')

print("Starting CPU multithreaded brute force test")
print(f"Trying to crack hash: {test_hash}")
print(f"Expected password: 'test'")
print("-------------------------------------")

# Try to crack with 4 threads (a reasonable value for testing)
result, attempts = cpu_multi_threaded_brute_force_attack(
    hasher=hasher,
    hash_to_crack=test_hash,
    charset="abcdefghijklmnopqrstuvwxyz",  # Just lowercase letters for speed
    min_length=4,
    max_length=4,  # We know the password is 4 characters
    batch_size=10000,  # Smaller batch size for more frequent updates
    threads=4,  # Use 4 threads
    verbose=True  # Show verbose output
)

print("\n-------------------------------------")
print(f"Result: {result}")
print(f"Attempts: {attempts}") 