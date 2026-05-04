"""
ReversAI Binary Analyzer
Deep analysis of PE, ELF, and Mach-O binaries.
"""

import struct
from backend.models.schemas import FileType, ImportInfo


# Known dangerous functions that indicate potential vulnerabilities
DANGEROUS_FUNCTIONS = {
    # C/C++ dangerous functions
    'strcpy': 'Buffer overflow risk — no bounds checking',
    'strcat': 'Buffer overflow risk — no bounds checking',
    'sprintf': 'Buffer overflow risk — no bounds checking',
    'gets': 'Critical buffer overflow — never use gets()',
    'scanf': 'Buffer overflow risk without width specifier',
    'vsprintf': 'Buffer overflow risk — use vsnprintf instead',
    'strncpy': 'May not null-terminate destination string',
    'strtok': 'Not thread-safe, modifies input string',
    'realpath': 'Buffer overflow if buffer too small',
    
    # Memory/Process
    'system': 'Command injection risk — avoid shell commands',
    'popen': 'Command injection risk via shell',
    'exec': 'Arbitrary code execution risk',
    'execve': 'Process replacement — potential for code execution',
    'fork': 'Process spawning — check for race conditions',
    
    # Windows-specific dangerous
    'LoadLibraryA': 'DLL loading — potential for DLL hijacking',
    'LoadLibraryW': 'DLL loading — potential for DLL hijacking',
    'GetProcAddress': 'Dynamic function resolution — suspicious',
    'VirtualAlloc': 'Memory allocation — common in shellcode',
    'VirtualAllocEx': 'Remote memory allocation — injection technique',
    'WriteProcessMemory': 'Process memory write — injection technique',
    'CreateRemoteThread': 'Remote thread creation — injection technique',
    'NtCreateThreadEx': 'Low-level thread creation — evasion technique',
    'VirtualProtect': 'Memory protection change — self-modifying code',
    'ShellExecuteA': 'Shell execution — command injection risk',
    'ShellExecuteW': 'Shell execution — command injection risk',
    'WinExec': 'Deprecated execution — use CreateProcess',
    'CreateProcessA': 'Process creation — monitor arguments',
    'CreateProcessW': 'Process creation — monitor arguments',
    'OpenProcess': 'Process handle — used in process manipulation',
    'ReadProcessMemory': 'Process memory read — information theft',
    'SetWindowsHookExA': 'Hook installation — keylogger technique',
    'RegOpenKeyExA': 'Registry access — persistence technique',
    'InternetOpenA': 'Network connection — data exfiltration',
    'URLDownloadToFileA': 'File download — dropper technique',
}


def analyze_pe(filepath: str) -> dict:
    """Analyze a PE (Windows executable) file."""
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed", "imports": [], "sections": [], "metadata": {}}
    
    result = {
        "imports": [],
        "exports": [],
        "sections": [],
        "metadata": {},
        "resources": [],
    }
    
    try:
        pe = pefile.PE(filepath)
        
        # Basic metadata
        result["metadata"] = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "num_sections": pe.FILE_HEADER.NumberOfSections,
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            "is_dll": pe.is_dll(),
            "is_exe": pe.is_exe(),
            "is_driver": pe.is_driver(),
        }
        
        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                lib_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else 'Unknown'
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f'ord_{imp.ordinal}'
                    is_dangerous = func_name in DANGEROUS_FUNCTIONS
                    result["imports"].append(ImportInfo(
                        library=lib_name,
                        function=func_name,
                        is_dangerous=is_dangerous,
                        risk_note=DANGEROUS_FUNCTIONS.get(func_name, ''),
                    ))
        
        # Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode('utf-8', errors='ignore') if exp.name else f'ord_{exp.ordinal}'
                result["exports"].append({"name": name, "address": hex(exp.address)})
        
        # Sections
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            result["sections"].append({
                "name": sec_name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 4),
                "characteristics": hex(section.Characteristics),
                "executable": bool(section.Characteristics & 0x20000000),
                "writable": bool(section.Characteristics & 0x80000000),
            })
        
        pe.close()
    except Exception as e:
        result["error"] = str(e)
    
    return result


def analyze_elf(filepath: str) -> dict:
    """Analyze an ELF (Linux/Unix executable) file."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"error": "pyelftools not installed", "imports": [], "sections": [], "metadata": {}}
    
    result = {
        "imports": [],
        "sections": [],
        "metadata": {},
        "symbols": [],
    }
    
    try:
        with open(filepath, 'rb') as f:
            elf = ELFFile(f)
            
            # Metadata
            result["metadata"] = {
                "class": elf.elfclass,
                "encoding": elf.little_endian and 'Little Endian' or 'Big Endian',
                "machine": elf.header.e_machine,
                "type": elf.header.e_type,
                "entry_point": hex(elf.header.e_entry),
                "num_sections": elf.num_sections(),
                "num_segments": elf.num_segments(),
            }
            
            # Sections
            for section in elf.iter_sections():
                result["sections"].append({
                    "name": section.name,
                    "type": section.header.sh_type,
                    "size": section.header.sh_size,
                    "offset": hex(section.header.sh_offset),
                    "flags": section.header.sh_flags,
                    "executable": bool(section.header.sh_flags & 0x4),
                    "writable": bool(section.header.sh_flags & 0x1),
                })
            
            # Dynamic symbols (imports)
            from elftools.elf.sections import SymbolTableSection
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        if symbol.name and symbol.entry.st_shndx == 'SHN_UNDEF':
                            func_name = symbol.name
                            is_dangerous = func_name in DANGEROUS_FUNCTIONS
                            result["imports"].append(ImportInfo(
                                library="",
                                function=func_name,
                                is_dangerous=is_dangerous,
                                risk_note=DANGEROUS_FUNCTIONS.get(func_name, ''),
                            ))
    except Exception as e:
        result["error"] = str(e)
    
    return result


def analyze_macho(filepath: str) -> dict:
    """Analyze a Mach-O (macOS executable) file."""
    result = {
        "imports": [],
        "sections": [],
        "metadata": {},
    }
    
    try:
        with open(filepath, 'rb') as f:
            magic = struct.unpack('<I', f.read(4))[0]
            
            is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
            is_swap = magic in (0xCEFAEDFE, 0xCFFAEDFE)
            
            fmt = '>' if is_swap else '<'
            
            if is_64:
                cpu, sub, ftype, ncmds, sizeofcmds, flags, _ = struct.unpack(
                    f'{fmt}IIIIIii', f.read(28))
            else:
                cpu, sub, ftype, ncmds, sizeofcmds, flags = struct.unpack(
                    f'{fmt}IIIIIi', f.read(24))
            
            cpu_types = {7: 'x86', 0x01000007: 'x86_64', 12: 'ARM', 0x0100000C: 'ARM64'}
            file_types = {1: 'Object', 2: 'Executable', 3: 'Fixed VM Lib',
                         4: 'Core', 5: 'Preload', 6: 'Dylib', 7: 'Dylinker', 8: 'Bundle'}
            
            result["metadata"] = {
                "cpu_type": cpu_types.get(cpu, f'Unknown (0x{cpu:x})'),
                "file_type": file_types.get(ftype, f'Unknown ({ftype})'),
                "num_load_commands": ncmds,
                "flags": hex(flags),
                "is_64bit": is_64,
            }
    except Exception as e:
        result["error"] = str(e)
    
    return result


def analyze_binary(filepath: str, file_type: FileType) -> dict:
    """Route binary analysis to the correct analyzer."""
    if file_type == FileType.PE:
        return analyze_pe(filepath)
    elif file_type == FileType.ELF:
        return analyze_elf(filepath)
    elif file_type == FileType.MACHO:
        return analyze_macho(filepath)
    return {"error": f"Unsupported binary type: {file_type}", "imports": [], "sections": []}
