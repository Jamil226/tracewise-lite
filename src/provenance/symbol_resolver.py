import subprocess
import re
from functools import lru_cache

# Expanded Taint source functions
TAINT_SOURCES = {
    # Standard I/O
    "read", "fread", "fgets", "fgetc", "getc", "getchar",
    "scanf", "fscanf", "sscanf", "vscanf",
    # Network
    "recv", "recvfrom", "recvmsg",
    # Memory-mapped / file
    "mmap", "pread", "pread64",
    # String input
    "gets",                          # always dangerous
    "getline", "getdelim",
    # argv — critical for your binaries
    "__libc_start_main",             # catches argv
    "getopt", "getopt_long",
    # Environment
    "getenv",
}

# Expanded Taint sink functions
TAINT_SINKS = {
    # String operations
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "memcpy", "memmove", "memset",
    "strdup", "strndup",
    # Execution
    "system", "execv", "execve", "execvp", "execl",
    "popen",
    # Format string
    "printf", "fprintf", "vprintf",  # when first arg is tainted
    # Allocation / free — for UAF
    "malloc", "calloc", "realloc",
    "free",
}

ALWAYS_RETAIN = {
    "abort", "exit", "_exit",
    "__stack_chk_fail",              # this is WHY you miss CWE-121
    "raise", "kill",
    "__assert_fail",
}

@lru_cache(maxsize=10000)
def resolve_address(binary_path: str, address: str) -> str | None:
    """
    Resolve a hex address to a function name using nm + addr2line.
    Cached — each address is only resolved once per binary.
    """
    try:
        # Try addr2line first (needs debug symbols)
        r = subprocess.run(
            ["addr2line", "-f", "-e", binary_path, address],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            lines = r.stdout.strip().split('\n')
            if lines and lines[0] != '??':
                return lines[0]   # function name
        
        # Fallback: nm for static symbols
        r = subprocess.run(
            ["nm", "-n", binary_path],
            capture_output=True, text=True, timeout=5
        )
        # Parse nm output to find nearest symbol below address
        addr_int = int(address, 16)
        best_name = None
        best_diff = float('inf')
        
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    sym_addr = int(parts[0], 16)
                    diff = addr_int - sym_addr
                    if 0 <= diff < best_diff:
                        best_diff = diff
                        best_name = parts[2]
                except ValueError:
                    continue
        return best_name
        
    except Exception:
        return None

def is_security_relevant(function_name: str | None) -> tuple[bool, str]:
    """
    Return (is_relevant, category) for a resolved function name.
    category: 'source' | 'sink' | 'always_retain' | 'irrelevant'
    """
    if function_name is None:
        return False, 'irrelevant'
    
    fn = function_name.lower()
    
    if any(src in fn for src in TAINT_SOURCES):
        return True, 'source'
    if any(sink in fn for sink in TAINT_SINKS):
        return True, 'sink'
    if any(ar in fn for ar in ALWAYS_RETAIN):
        return True, 'always_retain'
    
    return False, 'irrelevant'
