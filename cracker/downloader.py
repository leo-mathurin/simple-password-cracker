"""
Dictionary downloader for the password cracker.

This module provides functionality to download common password dictionaries from online sources.
"""

import os
import requests
from tqdm import tqdm


# Dictionary of common wordlists with their URLs
WORDLIST_SOURCES = {
    "rockyou-10": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/rockyou-10.txt",
    "rockyou-50": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/rockyou-50.txt",
    "rockyou-75": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/rockyou-75.txt",
    "common-passwords": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "phpbb": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/phpbb.txt",
    "xato-net-10k": "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/xato-net-10-million-passwords-10000.txt",
    "english-words": "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
}


def list_available_wordlists():
    """
    List all available wordlists that can be downloaded.
    
    Returns:
        list: Names of available wordlists
    """
    return list(WORDLIST_SOURCES.keys())


def download_wordlist(wordlist_name, output_dir=None):
    """
    Download a wordlist from online sources.
    
    Args:
        wordlist_name (str): The name of the wordlist to download
        output_dir (str, optional): Directory to save the wordlist. Defaults to current directory.
        
    Returns:
        str: Path to the downloaded wordlist
        
    Raises:
        ValueError: If the wordlist name is not recognized
        requests.RequestException: If the download fails
    """
    if wordlist_name not in WORDLIST_SOURCES:
        available = ", ".join(list_available_wordlists())
        raise ValueError(f"Unknown wordlist: {wordlist_name}. Available options: {available}")
    
    url = WORDLIST_SOURCES[wordlist_name]
    
    # Determine output directory
    if output_dir is None:
        output_dir = os.getcwd()
    os.makedirs(output_dir, exist_ok=True)
    
    # Set output filename based on wordlist name
    output_path = os.path.join(output_dir, f"{wordlist_name}.txt")
    
    # Download the file with progress bar
    print(f"Downloading {wordlist_name} wordlist...")
    response = requests.get(url, stream=True)
    response.raise_for_status()  # Raise an exception for HTTP errors
    
    # Get file size from headers if available
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 KB
    
    with open(output_path, 'wb') as f:
        with tqdm(total=total_size, unit='B', unit_scale=True, desc=wordlist_name) as pbar:
            for data in response.iter_content(block_size):
                f.write(data)
                pbar.update(len(data))
    
    print(f"Wordlist downloaded to {output_path}")
    return output_path 