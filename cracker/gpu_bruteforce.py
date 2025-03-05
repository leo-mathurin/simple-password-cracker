from typing import Optional, Tuple
import time
import traceback
import numpy as np

# Try to import OpenCL library
try:
    import pyopencl as cl
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False

# Global variable for GPU availability
GPU_AVAILABLE = OPENCL_AVAILABLE

class GPUBruteForce:
    """GPU-accelerated brute force password cracking."""
    
    def __init__(self, hasher, charset: str, min_length: int = 1, 
                 max_length: int = 8, batch_size: int = 1000000, 
                 verbose: bool = False, platform_index: int = None, 
                 device_index: int = None):
        """
        Initialize the GPU-based brute force password cracker.
        
        Args:
            hasher: Hash function to use
            charset: Characters to use for brute force
            min_length: Minimum password length to try
            max_length: Maximum password length to try
            batch_size: Number of passwords to try in each batch
            verbose: Whether to print detailed progress information
            platform_index: OpenCL platform index (default: auto-select)
            device_index: OpenCL device index (default: auto-select)
        """
        self.hasher = hasher
        self.charset = charset
        self.charset_length = len(charset)
        self.min_length = min_length
        self.max_length = max_length
        self.batch_size = batch_size
        self.verbose = verbose
        self.platform_index = platform_index
        self.device_index = device_index
        
        # Flag for whether we're using GPU
        self.use_gpu = False
        
        # Try to initialize GPU
        try:
            self._initialize_gpu()
        except Exception as e:
            if self.verbose:
                print(f"GPU initialization failed: {e}")
                print("Will fall back to CPU-based approach")

    def _initialize_gpu(self):
        """Initialize GPU acceleration (OpenCL)."""
        try:
            # OpenCL specific attributes
            self.context = None
            self.queue = None
            self.program = None
            self.kernels = {}
            self.device = None
            self.work_group_size = 256  # Default, will be optimized in initialize
            
            # Initialize OpenCL
            if self.verbose:
                print("Initializing OpenCL environment")
                
            self._initialize_opencl()
            self.use_gpu = True
            return True
        except Exception as e:
            if self.verbose:
                print(f"OpenCL initialization failed: {e}")
            self.use_gpu = False
            raise e

    def _initialize_opencl(self):
        """Initialize OpenCL environment for password cracking with optimizations."""
        try:
            # Get all available platforms
            platforms = cl.get_platforms()
            if not platforms:
                raise RuntimeError("No OpenCL platforms found")
            
            # List available platforms if in verbose mode
            if self.verbose:
                print(f"Available OpenCL platforms ({len(platforms)}):")
                for i, p in enumerate(platforms):
                    print(f"  [{i}] {p.name} - {p.vendor} (Version: {p.version})")
            
            # Let user choose platform or use the specified one
            if self.platform_index is not None:
                if self.platform_index >= len(platforms):
                    raise ValueError(f"Platform index {self.platform_index} is out of range (0-{len(platforms)-1})")
                platform = platforms[self.platform_index]
            else:
                # Auto-select: prefer platforms with GPU devices
                selected_platform = None
                for p in platforms:
                    if p.get_devices(device_type=cl.device_type.GPU):
                        selected_platform = p
                        break
                
                if selected_platform is None:
                    # If no platform with GPU was found, take the first one
                    selected_platform = platforms[0]
                
                platform = selected_platform
            
            if self.verbose:
                print(f"Selected platform: {platform.name}")
            
            # Get devices for the selected platform
            gpu_devices = platform.get_devices(device_type=cl.device_type.GPU)
            cpu_devices = platform.get_devices(device_type=cl.device_type.CPU)
            
            # List available devices if in verbose mode
            if self.verbose:
                if gpu_devices:
                    print(f"  GPU devices ({len(gpu_devices)}):")
                    for i, d in enumerate(gpu_devices):
                        print(f"    [{i}] {d.name} - {d.vendor} (Compute Units: {d.max_compute_units})")
                if cpu_devices:
                    print(f"  CPU devices ({len(cpu_devices)}):")
                    for i, d in enumerate(cpu_devices):
                        print(f"    [{i}] {d.name} - {d.vendor} (Compute Units: {d.max_compute_units})")
            
            # Choose device based on priority: 
            # 1. User-specified device
            # 2. Available GPU device
            # 3. Available CPU device
            all_devices = gpu_devices + cpu_devices
            
            if not all_devices:
                raise RuntimeError("No OpenCL devices found")
            
            if self.device_index is not None:
                if self.device_index >= len(all_devices):
                    raise ValueError(f"Device index {self.device_index} is out of range (0-{len(all_devices)-1})")
                if self.device_index < len(gpu_devices):
                    device = gpu_devices[self.device_index]
                else:
                    device = cpu_devices[self.device_index - len(gpu_devices)]
            else:
                # Auto-select: prefer GPU over CPU
                device = gpu_devices[0] if gpu_devices else cpu_devices[0]
            
            self.device = device
            
            if self.verbose:
                print(f"Selected device: {device.name}")
                print(f"  - Max compute units: {device.max_compute_units}")
                print(f"  - Max work group size: {device.max_work_group_size}")
                print(f"  - Global memory size: {device.global_mem_size / (1024**2):.2f} MB")
                print(f"  - Local memory size: {device.local_mem_size / 1024:.2f} KB")
            
            # Create context and command queue with profiling enabled for performance metrics
            self.context = cl.Context([device])
            self.queue = cl.CommandQueue(self.context, 
                                         properties=cl.command_queue_properties.PROFILING_ENABLE
                                         if self.verbose else 0)
            
            # Optimize work group size based on device capabilities
            # Use a multiple of 64 for best performance but stay within device limits
            self.work_group_size = min(
                device.max_work_group_size, 
                256 if device.max_work_group_size >= 256 else device.max_work_group_size
            )
            
            # Make sure work_group_size is a multiple of 64 for optimal performance
            self.work_group_size = (self.work_group_size // 64) * 64
            if self.work_group_size == 0:
                self.work_group_size = device.max_work_group_size
            
            if self.verbose:
                print(f"Optimized work group size: {self.work_group_size}")
            
            # We'll compile the program when needed in the respective methods
            
        except cl.Error as e:
            raise RuntimeError(f"OpenCL error: {e}")

    def _run_opencl_batch(self, target_hash_bytes, password_length, start_idx, batch_size):
        """Run a batch of password checks using OpenCL."""
        try:
            # If we're at a new password length, we need to recalculate total combinations
            if not hasattr(self, 'current_password_length') or self.current_password_length != password_length:
                self.current_password_length = password_length
                self.total_combinations = self.charset_length ** password_length
                if self.verbose:
                    print(f"Trying passwords of length {password_length}")
                    print(f"Total combinations: {self.total_combinations:,}")
                
            # Convert target hash to bytes if it's a string
            if isinstance(target_hash_bytes, str):
                target_hash_bytes = bytes.fromhex(target_hash_bytes)
                
            # Adjust batch size to not exceed total combinations
            if start_idx + batch_size > self.total_combinations:
                batch_size = self.total_combinations - start_idx
                
            if batch_size <= 0:
                return None, 0  # No more combinations to try
                
            # If we haven't compiled the program yet, do it now
            if not hasattr(self, 'program') or self.program is None:
                self._compile_opencl_program()
                
            # Create OpenCL buffers
            charset_buf = cl.Buffer(self.context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, 
                                    hostbuf=np.frombuffer(self.charset.encode('utf-8'), dtype=np.uint8))
            target_hash_buf = cl.Buffer(self.context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, 
                                       hostbuf=np.frombuffer(target_hash_bytes, dtype=np.uint8))
            found_buf = cl.Buffer(self.context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, 
                                 hostbuf=np.array([0], dtype=np.uint32))
            result_buf = cl.Buffer(self.context, cl.mem_flags.READ_WRITE, size=password_length + 1)
            
            # Set kernel arguments
            kernel = self.kernels.get('md5_bruteforce')
            if kernel is None:
                kernel = self.program.md5_bruteforce
                self.kernels['md5_bruteforce'] = kernel
                
            # For large indices, we need to handle them properly to prevent overflow
            # We'll use a 64-bit unsigned integer (np.uint64) for start_idx
            start_idx_uint64 = np.uint64(start_idx)
            
            kernel.set_args(
                charset_buf,
                np.uint32(len(self.charset)),
                np.uint32(password_length),
                target_hash_buf,
                found_buf,
                result_buf,
                start_idx_uint64  # Use 64-bit unsigned integer
            )
            
            # Calculate global and local work sizes
            global_size = batch_size
            local_size = min(self.work_group_size, batch_size)
            
            # Make sure global size is a multiple of local size
            global_size = ((global_size + local_size - 1) // local_size) * local_size
            
            # Execute kernel
            start_time = time.time()
            event = cl.enqueue_nd_range_kernel(self.queue, kernel, (global_size,), (local_size,))
            event.wait()
            
            # If profiling is enabled and set to verbose, get performance metrics
            # We'll reduce the frequency of these logs
            if self.verbose and hasattr(event, 'profile') and start_idx % (100 * self.batch_size) == 0:
                start_time_ns = event.profile.start
                end_time_ns = event.profile.end
                duration_ns = end_time_ns - start_time_ns
                passwords_per_second = batch_size / (duration_ns / 1e9)
                
                print(f"Progress: {start_idx:,}/{self.total_combinations:,} ({start_idx/self.total_combinations*100:.2f}%)")
                print(f"Performance: {passwords_per_second/1e6:.2f} million passwords/second")
            
            # Check if password was found
            found = np.zeros(1, dtype=np.uint32)
            cl.enqueue_copy(self.queue, found, found_buf)
            
            if found[0] == 1:
                # Password found! Get the result
                result = np.zeros(password_length + 1, dtype=np.uint8)
                cl.enqueue_copy(self.queue, result, result_buf)
                password = bytes(result[:password_length]).decode('utf-8')
                return password, batch_size
                
            # Clean up resources for this batch
            charset_buf.release()
            target_hash_buf.release()
            found_buf.release()
            result_buf.release()
            
            return None, batch_size
            
        except cl.Error as e:
            if self.verbose:
                print(f"OpenCL error in batch: {e}")
            return None, 0

    def _compile_opencl_program(self):
        """Compile the OpenCL program for password cracking."""
        # Define the OpenCL kernel code for MD5 hashing and checking
        kernel_code = """
        // MD5 Constants
        #define MD5_A 0x67452301
        #define MD5_B 0xefcdab89
        #define MD5_C 0x98badcfe
        #define MD5_D 0x10325476
        
        // MD5 Functions
        #define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
        #define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
        #define H(x, y, z) ((x) ^ (y) ^ (z))
        #define I(x, y, z) ((y) ^ ((x) | (~z)))
        
        #define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
        
        #define FF(a, b, c, d, x, s, ac) \\
            (a) = ADD((a), ADD(ADD(F((b), (c), (d)), (x)), (ac))); \\
            (a) = ROTATE_LEFT((a), (s)); \\
            (a) = ADD((a), (b))
            
        #define GG(a, b, c, d, x, s, ac) \\
            (a) = ADD((a), ADD(ADD(G((b), (c), (d)), (x)), (ac))); \\
            (a) = ROTATE_LEFT((a), (s)); \\
            (a) = ADD((a), (b))
            
        #define HH(a, b, c, d, x, s, ac) \\
            (a) = ADD((a), ADD(ADD(H((b), (c), (d)), (x)), (ac))); \\
            (a) = ROTATE_LEFT((a), (s)); \\
            (a) = ADD((a), (b))
            
        #define II(a, b, c, d, x, s, ac) \\
            (a) = ADD((a), ADD(ADD(I((b), (c), (d)), (x)), (ac))); \\
            (a) = ROTATE_LEFT((a), (s)); \\
            (a) = ADD((a), (b))
            
        // Safe add function to prevent integer overflow
        uint ADD(uint x, uint y) {
            return x + y;
        }
        
        // MD5 transform function
        void md5_transform(uint state[4], const uchar block[64]) {
            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint x[16];
            
            // Convert block to words
            for (int i = 0, j = 0; j < 64; i++, j += 4) {
                x[i] = ((uint)block[j]) | (((uint)block[j+1]) << 8) |
                       (((uint)block[j+2]) << 16) | (((uint)block[j+3]) << 24);
            }
            
            // Round 1
            FF(a, b, c, d, x[ 0],  7, 0xd76aa478);
            FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
            FF(c, d, a, b, x[ 2], 17, 0x242070db);
            FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
            FF(a, b, c, d, x[ 4],  7, 0xf57c0faf);
            FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
            FF(c, d, a, b, x[ 6], 17, 0xa8304613);
            FF(b, c, d, a, x[ 7], 22, 0xfd469501);
            FF(a, b, c, d, x[ 8],  7, 0x698098d8);
            FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
            FF(c, d, a, b, x[10], 17, 0xffff5bb1);
            FF(b, c, d, a, x[11], 22, 0x895cd7be);
            FF(a, b, c, d, x[12],  7, 0x6b901122);
            FF(d, a, b, c, x[13], 12, 0xfd987193);
            FF(c, d, a, b, x[14], 17, 0xa679438e);
            FF(b, c, d, a, x[15], 22, 0x49b40821);
            
            // Round 2
            GG(a, b, c, d, x[ 1],  5, 0xf61e2562);
            GG(d, a, b, c, x[ 6],  9, 0xc040b340);
            GG(c, d, a, b, x[11], 14, 0x265e5a51);
            GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
            GG(a, b, c, d, x[ 5],  5, 0xd62f105d);
            GG(d, a, b, c, x[10],  9, 0x02441453);
            GG(c, d, a, b, x[15], 14, 0xd8a1e681);
            GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
            GG(a, b, c, d, x[ 9],  5, 0x21e1cde6);
            GG(d, a, b, c, x[14],  9, 0xc33707d6);
            GG(c, d, a, b, x[ 3], 14, 0xf4d50d87);
            GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
            GG(a, b, c, d, x[13],  5, 0xa9e3e905);
            GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
            GG(c, d, a, b, x[ 7], 14, 0x676f02d9);
            GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);
            
            // Round 3
            HH(a, b, c, d, x[ 5],  4, 0xfffa3942);
            HH(d, a, b, c, x[ 8], 11, 0x8771f681);
            HH(c, d, a, b, x[11], 16, 0x6d9d6122);
            HH(b, c, d, a, x[14], 23, 0xfde5380c);
            HH(a, b, c, d, x[ 1],  4, 0xa4beea44);
            HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
            HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
            HH(b, c, d, a, x[10], 23, 0xbebfbc70);
            HH(a, b, c, d, x[13],  4, 0x289b7ec6);
            HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
            HH(c, d, a, b, x[ 3], 16, 0xd4ef3085);
            HH(b, c, d, a, x[ 6], 23, 0x04881d05);
            HH(a, b, c, d, x[ 9],  4, 0xd9d4d039);
            HH(d, a, b, c, x[12], 11, 0xe6db99e5);
            HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
            HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);
            
            // Round 4
            II(a, b, c, d, x[ 0],  6, 0xf4292244);
            II(d, a, b, c, x[ 7], 10, 0x432aff97);
            II(c, d, a, b, x[14], 15, 0xab9423a7);
            II(b, c, d, a, x[ 5], 21, 0xfc93a039);
            II(a, b, c, d, x[12],  6, 0x655b59c3);
            II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
            II(c, d, a, b, x[10], 15, 0xffeff47d);
            II(b, c, d, a, x[ 1], 21, 0x85845dd1);
            II(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
            II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
            II(c, d, a, b, x[ 6], 15, 0xa3014314);
            II(b, c, d, a, x[13], 21, 0x4e0811a1);
            II(a, b, c, d, x[ 4],  6, 0xf7537e82);
            II(d, a, b, c, x[11], 10, 0xbd3af235);
            II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
            II(b, c, d, a, x[ 9], 21, 0xeb86d391);
            
            // Add back to state
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }
        
        // Calculate MD5 hash for a given message
        void md5_hash(const uchar *message, size_t length, uchar digest[16]) {
            uint state[4] = {MD5_A, MD5_B, MD5_C, MD5_D};
            ulong bit_len = length * 8;
            
            // Process each 64-byte block
            size_t block_count = (length + 8) / 64 + 1;
            uchar block[64];
            
            for (size_t i = 0; i < block_count; i++) {
                // Prepare block
                for (int j = 0; j < 64; j++) {
                    if (i * 64 + j < length) {
                        block[j] = message[i * 64 + j];
                    } else if (i * 64 + j == length) {
                        block[j] = 0x80;  // Padding: append 1 bit (1000 0000)
                    } else if (i == block_count - 1 && j >= 56) {
                        // Append length in bits
                        block[j] = (uchar)(bit_len >> ((j - 56) * 8));
                    } else {
                        block[j] = 0;  // Padding with zeros
                    }
                }
                
                md5_transform(state, block);
            }
            
            // Output hash
            for (int i = 0; i < 16; i++) {
                digest[i] = (uchar)(state[i / 4] >> ((i % 4) * 8));
            }
        }
        
        // Check if password matches target hash
        bool check_md5_hash(const uchar *password, size_t length, const uchar *target_hash) {
            uchar digest[16];
            md5_hash(password, length, digest);
            
            // Compare hashes
            for (int i = 0; i < 16; i++) {
                if (digest[i] != target_hash[i]) {
                    return false;
                }
            }
            return true;
        }
        
        // Generate passwords and check against target hash
        __kernel void md5_bruteforce(
            __global const char *charset,
            const uint charset_length,
            const uint password_length,
            __global const uchar *target_hash,
            __global uint *found,
            __global char *result_password,
            const ulong start_idx  // Use ulong (64-bit) for large indices
        ) {
            ulong id = get_global_id(0);  // Use ulong for large global IDs
            ulong global_id = start_idx + id;  // Use ulong for large indices
            
            // Skip if already found
            if (*found == 1) return;
            
            // Generate password from index
            char password[16];  // Max password length
            ulong remainder = global_id;  // Use ulong for large indices
            
            for (uint i = 0; i < password_length; i++) {
                password[i] = charset[remainder % charset_length];
                remainder /= charset_length;
            }
            
            // Check if this password matches the target hash
            if (check_md5_hash((uchar*)password, password_length, target_hash)) {
                // Mark as found
                *found = 1;
                
                // Copy the password to result
                for (uint i = 0; i < password_length; i++) {
                    result_password[i] = password[i];
                }
                result_password[password_length] = '\\0';  // Null terminator
            }
        }
        """
        
        try:
            # Add optimization flags specific to the device
            build_options = ""
            
            # Add device-specific optimizations
            if hasattr(self.device, 'type') and self.device.type == cl.device_type.GPU:
                build_options += " -cl-mad-enable -cl-fast-relaxed-math"
                
                # Add vendor-specific optimizations
                vendor = self.device.vendor.lower() if hasattr(self.device, 'vendor') else ""
                if 'nvidia' in vendor:
                    build_options += " -cl-nv-verbose"
                elif 'amd' in vendor or 'advanced micro' in vendor:
                    build_options += " -DAMD_GPU"
                elif 'intel' in vendor:
                    build_options += " -DINTEL_GPU"
            
            # Compile the program with optimization flags
            self.program = cl.Program(self.context, kernel_code).build(options=build_options)
            
            if self.verbose:
                print("OpenCL program compilation successful")
                
        except cl.Error as e:
            error_msg = f"OpenCL program compilation failed: {e}"
            if self.verbose:
                print(error_msg)
            raise RuntimeError(error_msg)

    def crack(self, target_hash: str) -> Tuple[Optional[str], int]:
        """
        Attempt to crack the given hash using GPU acceleration.
        
        Args:
            target_hash: The hash to crack
            
        Returns:
            Tuple of (cracked password or None if not found, attempts made)
        """
        if not self.use_gpu:
            # We already tried to initialize GPU and failed, use CPU
            if self.verbose:
                print("Using CPU for cracking (GPU initialization failed)")
            return self._cpu_crack(target_hash)
            
        try:
            # Convert hash to bytes if necessary
            if len(target_hash) == 32:  # MD5 hex string
                target_hash_bytes = bytes.fromhex(target_hash)
            else:
                # Assume it's already in bytes form
                target_hash_bytes = target_hash
                
            if self.verbose:
                print(f"Attempting to crack hash: {target_hash}")
                print(f"Using OpenCL for acceleration")
                
            total_attempts = 0
            start_time = time.time()
            
            # Try all password lengths from min to max
            for password_length in range(self.min_length, self.max_length + 1):
                # Initialize total combinations for this password length
                self.current_password_length = password_length
                self.total_combinations = self.charset_length ** password_length
                
                if self.verbose:
                    print(f"Trying passwords of length {password_length}...")
                    print(f"Total combinations for length {password_length}: {self.total_combinations:,}")
                    
                # Process in batches
                start_idx = 0
                last_progress_print = time.time()
                
                while start_idx < self.total_combinations:
                    # Determine batch size for this iteration
                    current_batch_size = min(self.batch_size, self.total_combinations - start_idx)
                    
                    # Run batch on GPU
                    password, attempts = self._run_opencl_batch(
                        target_hash_bytes, 
                        password_length, 
                        start_idx, 
                        current_batch_size
                    )
                        
                    total_attempts += attempts
                    
                    # If password found, return it
                    if password:
                        elapsed = time.time() - start_time
                        if self.verbose:
                            print(f"Password found: {password}")
                            print(f"Attempts: {total_attempts:,}")
                            print(f"Time: {elapsed:.2f} seconds")
                            print(f"Speed: {total_attempts / elapsed:,.2f} passwords/second")
                        return password, total_attempts
                        
                    # Move to next batch
                    start_idx += current_batch_size
                    
                    # Print progress less frequently (once every 30 seconds)
                    current_time = time.time()
                    if self.verbose and (current_time - last_progress_print) >= 30:
                        elapsed = current_time - start_time
                        percentage = (start_idx / self.total_combinations) * 100
                        rate = total_attempts / elapsed if elapsed > 0 else 0
                        
                        print(f"Progress: {percentage:.2f}% of length {password_length}")
                        print(f"Speed: {rate/1e6:.2f} million passwords/second")
                        
                        # Only estimate remaining time if we've made significant progress
                        if start_idx > 0:
                            remaining_combinations = self.total_combinations - start_idx
                            time_per_combination = elapsed / start_idx
                            estimated_remaining = remaining_combinations * time_per_combination
                            
                            # Convert to appropriate time unit
                            if estimated_remaining < 60:
                                time_str = f"{estimated_remaining:.1f} seconds"
                            elif estimated_remaining < 3600:
                                time_str = f"{estimated_remaining/60:.1f} minutes"
                            elif estimated_remaining < 86400:
                                time_str = f"{estimated_remaining/3600:.1f} hours"
                            else:
                                time_str = f"{estimated_remaining/86400:.1f} days"
                                
                            print(f"Estimated time remaining: {time_str}")
                            
                        last_progress_print = current_time
                
                if self.verbose:
                    print(f"Finished trying passwords of length {password_length}")
                    
            if self.verbose:
                elapsed = time.time() - start_time
                print(f"Password not found after {total_attempts:,} attempts")
                print(f"Time: {elapsed:.2f} seconds")
                print(f"Speed: {total_attempts / elapsed:,.2f} passwords/second")
                
            return None, total_attempts
            
        except Exception as e:
            if self.verbose:
                print(f"Error during GPU cracking: {e}")
                traceback.print_exc()  # Print the full stack trace for debugging
                print("Falling back to CPU")
            return self._cpu_crack(target_hash)

    def _cpu_crack(self, target_hash: str) -> Tuple[Optional[str], int]:
        """
        Fallback to CPU-based password cracking when GPU acceleration is not available.
        
        Args:
            target_hash: The hash to crack
            
        Returns:
            Tuple of (cracked password or None if not found, attempts made)
        """
        if self.verbose:
            print("Falling back to CPU-based password cracking")
            
        from .bruteforce import BruteForceGenerator, brute_force_attack
        
        generator = BruteForceGenerator(
            min_length=self.min_length,
            max_length=self.max_length,
            custom_chars=self.charset
        )
        
        return brute_force_attack(self.hasher, target_hash, generator, self.verbose)

    def __del__(self):
        """Cleanup resources when object is destroyed."""
        try:
            # Clean up OpenCL resources
            if hasattr(self, 'queue') and self.queue:
                self.queue.finish()
        except:
            # Silently fail during cleanup
            pass


def gpu_brute_force_attack(hasher, hash_to_crack: str, charset: str, 
                          min_length: int = 1, max_length: int = 8,
                          batch_size: int = 1000000, verbose: bool = False,
                          platform_index: int = None, device_index: int = None) -> Tuple[Optional[str], int]:
    """
    Use GPU acceleration to perform a brute force attack against a password hash.
    
    Args:
        hasher: Hash function to use
        hash_to_crack: Hash to attempt to crack
        charset: String containing characters to use in brute force
        min_length: Minimum password length to try
        max_length: Maximum password length to try
        batch_size: Number of passwords to try in each batch
        verbose: Whether to print progress information
        platform_index: OpenCL platform index (default: auto-select)
        device_index: OpenCL device index (default: auto-select)
        
    Returns:
        Tuple of (cracked password or None if not found, attempts made)
    """
    if not GPU_AVAILABLE:
        if verbose:
            print("GPU acceleration not available - no compatible GPU libraries found")
            print("Install PyOpenCL to enable GPU acceleration")
            print("Falling back to CPU brute force attack")
        
        # Import CPU implementation
        from .bruteforce import BruteForceGenerator, brute_force_attack
        generator = BruteForceGenerator(
            min_length=min_length,
            max_length=max_length,
            custom_chars=charset
        )
        return brute_force_attack(hasher, hash_to_crack, generator, verbose)
    
    # Create and run GPU brute forcer
    brute_forcer = GPUBruteForce(
        hasher=hasher,
        charset=charset,
        min_length=min_length,
        max_length=max_length,
        batch_size=batch_size,
        verbose=verbose,
        platform_index=platform_index,
        device_index=device_index
    )
    
    return brute_forcer.crack(hash_to_crack)