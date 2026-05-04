"""
ReversAI File Detector
Detects file type, computes hashes, and extracts basic metadata.
"""

import os
import hashlib
import math
import struct
import subprocess
from collections import Counter
from backend.models.schemas import FileInfo, FileType


# Magic bytes for common file types
MAGIC_SIGNATURES = {
    b'\x4d\x5a': FileType.PE,                    # MZ header (PE/DOS)
    b'\x7fELF': FileType.ELF,                    # ELF
    b'\xfe\xed\xfa\xce': FileType.MACHO,         # Mach-O 32-bit
    b'\xfe\xed\xfa\xcf': FileType.MACHO,         # Mach-O 64-bit
    b'\xce\xfa\xed\xfe': FileType.MACHO,         # Mach-O 32-bit (reversed)
    b'\xcf\xfa\xed\xfe': FileType.MACHO,         # Mach-O 64-bit (reversed)
    b'\xca\xfe\xba\xbe': FileType.MACHO,         # Mach-O Universal
    b'\xbe\xba\xfe\xca': FileType.MACHO,         # Mach-O Universal (reversed)
    b'\x50\x4b\x03\x04': FileType.JAVA,          # ZIP/JAR
}

# Extensions to file types
EXT_MAP = {
    '.py': FileType.PYTHON,
    '.pyc': FileType.PYTHON,
    '.pyw': FileType.PYTHON,
    '.sh': FileType.SCRIPT,
    '.bash': FileType.SCRIPT,
    '.bat': FileType.SCRIPT,
    '.cmd': FileType.SCRIPT,
    '.ps1': FileType.SCRIPT,
    '.js': FileType.SCRIPT,
    '.vbs': FileType.SCRIPT,
    '.jar': FileType.JAVA,
    '.class': FileType.JAVA,
    '.exe': FileType.PE,
    '.dll': FileType.PE,
    '.sys': FileType.PE,
    '.so': FileType.ELF,
    '.dylib': FileType.MACHO,
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def compute_hashes(filepath: str) -> tuple[str, str]:
    """Compute MD5 and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def detect_file_type(filepath: str) -> FileType:
    """Detect file type using magic bytes and extension."""
    # Check magic bytes first
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
        
        for magic, ftype in MAGIC_SIGNATURES.items():
            if header[:len(magic)] == magic:
                # Verify JAR vs generic ZIP
                if ftype == FileType.JAVA:
                    ext = os.path.splitext(filepath)[1].lower()
                    if ext not in ('.jar', '.class', '.war', '.ear'):
                        continue
                return ftype
    except Exception:
        pass

    # Fallback to extension
    ext = os.path.splitext(filepath)[1].lower()
    if ext in EXT_MAP:
        return EXT_MAP[ext]

    # Check if it's a text/script file
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline(256)
        if first_line.startswith('#!'):
            if 'python' in first_line.lower():
                return FileType.PYTHON
            return FileType.SCRIPT
    except Exception:
        pass

    return FileType.UNKNOWN


def detect_architecture(filepath: str, file_type: FileType) -> str:
    """Detect binary architecture."""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(64)
        
        if file_type == FileType.PE:
            # PE: machine type at offset in COFF header
            if len(header) >= 2 and header[:2] == b'MZ':
                f_obj = open(filepath, 'rb')
                f_obj.seek(0x3C)
                pe_offset = struct.unpack('<I', f_obj.read(4))[0]
                f_obj.seek(pe_offset + 4)
                machine = struct.unpack('<H', f_obj.read(2))[0]
                f_obj.close()
                machines = {
                    0x14c: 'x86 (32-bit)',
                    0x8664: 'x86_64 (64-bit)',
                    0xAA64: 'ARM64',
                    0x1C0: 'ARM',
                }
                return machines.get(machine, f'Unknown (0x{machine:04x})')
        
        elif file_type == FileType.ELF:
            if len(header) >= 20:
                elf_class = header[4]
                elf_machine = struct.unpack('<H', header[18:20])[0]
                arch = {3: 'x86', 62: 'x86_64', 183: 'ARM64', 40: 'ARM'}
                bits = '64-bit' if elf_class == 2 else '32-bit'
                return f"{arch.get(elf_machine, 'Unknown')} ({bits})"
        
        elif file_type == FileType.MACHO:
            magic = struct.unpack('<I', header[:4])[0]
            if magic in (0xFEEDFACE, 0xCEFAEDFE):
                cpu = struct.unpack('<I', header[4:8])[0]
            elif magic in (0xFEEDFACF, 0xCFFAEDFE):
                cpu = struct.unpack('<I', header[4:8])[0]
            else:
                return "Universal Binary"
            cpus = {7: 'x86', 0x01000007: 'x86_64', 12: 'ARM', 0x0100000C: 'ARM64'}
            return cpus.get(cpu, f'Unknown (0x{cpu:x})')
    except Exception:
        pass
    
    # Try `file` command
    try:
        result = subprocess.run(['file', filepath], capture_output=True, text=True, timeout=5)
        return result.stdout.strip().split(': ', 1)[-1][:100]
    except Exception:
        return "Unknown"


def get_file_description(filepath: str) -> str:
    """Get a human-readable file description using the `file` command."""
    try:
        result = subprocess.run(['file', filepath], capture_output=True, text=True, timeout=5)
        return result.stdout.strip().split(': ', 1)[-1]
    except Exception:
        return "Unknown file type"


def analyze_file(filepath: str) -> FileInfo:
    """Perform complete file detection and metadata extraction."""
    file_type = detect_file_type(filepath)
    md5, sha256 = compute_hashes(filepath)
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    return FileInfo(
        filename=os.path.basename(filepath),
        file_type=file_type,
        file_size=len(data),
        mime_type="",
        md5=md5,
        sha256=sha256,
        entropy=calculate_entropy(data),
        architecture=detect_architecture(filepath, file_type),
        description=get_file_description(filepath),
    )
