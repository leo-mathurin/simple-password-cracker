"""
Simple Password Cracker - A CLI tool for cracking password hashes using dictionary attacks
and brute force methods with optional GPU acceleration.
"""

__version__ = '0.2.0'

# Check for GPU capabilities
try:
    from .gpu_bruteforce import GPU_AVAILABLE, OPENCL_AVAILABLE
    
    if GPU_AVAILABLE:
        if OPENCL_AVAILABLE:
            gpu_info = "OpenCL"
        else:
            gpu_info = "Unknown"
            
        __gpu_support__ = f"GPU acceleration available ({gpu_info})"
    else:
        __gpu_support__ = "GPU acceleration not available"
except ImportError:
    __gpu_support__ = "GPU acceleration not available (libraries not installed)" 