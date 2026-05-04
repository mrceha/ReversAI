"""
ReversAI Security Checker
Checks binary security mitigations and hardening.
"""

import struct
from backend.models.schemas import FileType, SecurityCheck, Severity


def check_pe_security(filepath: str) -> list[SecurityCheck]:
    """Check PE security mitigations."""
    checks = []
    
    try:
        import pefile
        pe = pefile.PE(filepath)
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        
        # ASLR (Address Space Layout Randomization)
        aslr_enabled = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        checks.append(SecurityCheck(
            name="ASLR (Address Space Layout Randomization)",
            status="enabled" if aslr_enabled else "disabled",
            severity=Severity.INFO if aslr_enabled else Severity.HIGH,
            description="ASLR randomizes memory addresses to prevent exploitation.",
            recommendation="" if aslr_enabled else "Compile with /DYNAMICBASE linker flag to enable ASLR.",
        ))
        
        # DEP/NX (Data Execution Prevention)
        dep_enabled = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        checks.append(SecurityCheck(
            name="DEP/NX (Data Execution Prevention)",
            status="enabled" if dep_enabled else "disabled",
            severity=Severity.INFO if dep_enabled else Severity.HIGH,
            description="DEP prevents code execution from data segments.",
            recommendation="" if dep_enabled else "Compile with /NXCOMPAT linker flag to enable DEP.",
        ))
        
        # CFG (Control Flow Guard)
        cfg_enabled = bool(dll_chars & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        checks.append(SecurityCheck(
            name="CFG (Control Flow Guard)",
            status="enabled" if cfg_enabled else "disabled",
            severity=Severity.INFO if cfg_enabled else Severity.MEDIUM,
            description="CFG validates indirect calls to prevent ROP attacks.",
            recommendation="" if cfg_enabled else "Compile with /guard:cf to enable Control Flow Guard.",
        ))
        
        # High Entropy ASLR
        high_entropy = bool(dll_chars & 0x0020)  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        checks.append(SecurityCheck(
            name="High Entropy ASLR",
            status="enabled" if high_entropy else "disabled",
            severity=Severity.INFO if high_entropy else Severity.LOW,
            description="64-bit ASLR with high entropy for better randomization.",
            recommendation="" if high_entropy else "Compile as 64-bit with /HIGHENTROPYVA to enable.",
        ))
        
        # SEH Protection
        no_seh = bool(dll_chars & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH
        safe_seh = hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG')
        checks.append(SecurityCheck(
            name="SafeSEH / No SEH",
            status="enabled" if (no_seh or safe_seh) else "disabled",
            severity=Severity.INFO if (no_seh or safe_seh) else Severity.MEDIUM,
            description="SEH protection prevents exception handler hijacking.",
            recommendation="" if (no_seh or safe_seh) else "Compile with /SAFESEH to enable structured exception handling protection.",
        ))
        
        # Check for writable+executable sections (W^X violation)
        wxe_sections = []
        for section in pe.sections:
            is_writable = bool(section.Characteristics & 0x80000000)
            is_executable = bool(section.Characteristics & 0x20000000)
            if is_writable and is_executable:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                wxe_sections.append(sec_name)
        
        checks.append(SecurityCheck(
            name="W^X (Write XOR Execute)",
            status="violated" if wxe_sections else "enforced",
            severity=Severity.HIGH if wxe_sections else Severity.INFO,
            description=f"Sections both writable and executable: {', '.join(wxe_sections)}" if wxe_sections
                       else "No sections are both writable and executable.",
            recommendation="Remove write permissions from executable sections or vice versa." if wxe_sections else "",
        ))
        
        # Check for high entropy sections (possible packing/encryption)
        packed_sections = []
        for section in pe.sections:
            entropy = section.get_entropy()
            if entropy > 7.0:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                packed_sections.append(f"{sec_name} (entropy: {entropy:.2f})")
        
        if packed_sections:
            checks.append(SecurityCheck(
                name="Packing / Encryption Detection",
                status="detected",
                severity=Severity.MEDIUM,
                description=f"High entropy sections suggest packing or encryption: {', '.join(packed_sections)}",
                recommendation="Packed binaries may hide malicious code. Consider unpacking for further analysis.",
            ))
        
        # Digital signature check
        has_sig = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0)  # Security directory
        checks.append(SecurityCheck(
            name="Digital Signature",
            status="present" if has_sig else "absent",
            severity=Severity.INFO if has_sig else Severity.LOW,
            description="Binary has a digital signature." if has_sig else "Binary is not digitally signed.",
            recommendation="" if has_sig else "Consider signing the binary to establish trust and integrity.",
        ))
        
        pe.close()
    except ImportError:
        checks.append(SecurityCheck(
            name="PE Analysis",
            status="error",
            severity=Severity.INFO,
            description="pefile library not installed — PE security checks skipped.",
        ))
    except Exception as e:
        checks.append(SecurityCheck(
            name="PE Analysis Error",
            status="error",
            severity=Severity.INFO,
            description=f"Error during PE analysis: {str(e)}",
        ))
    
    return checks


def check_elf_security(filepath: str) -> list[SecurityCheck]:
    """Check ELF security mitigations."""
    checks = []
    
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.segments import Segment
        
        with open(filepath, 'rb') as f:
            elf = ELFFile(f)
            
            # PIE (Position Independent Executable)
            is_pie = elf.header.e_type == 'ET_DYN'
            checks.append(SecurityCheck(
                name="PIE (Position Independent Executable)",
                status="enabled" if is_pie else "disabled",
                severity=Severity.INFO if is_pie else Severity.HIGH,
                description="PIE enables ASLR for the main executable.",
                recommendation="" if is_pie else "Compile with -fPIE -pie flags to enable PIE.",
            ))
            
            # NX (No Execute)
            has_gnu_stack = False
            nx_enabled = False
            for segment in elf.iter_segments():
                if segment.header.p_type == 'PT_GNU_STACK':
                    has_gnu_stack = True
                    nx_enabled = not bool(segment.header.p_flags & 0x1)  # PF_X
                    break
            
            checks.append(SecurityCheck(
                name="NX (No Execute / DEP)",
                status="enabled" if nx_enabled else "disabled",
                severity=Severity.INFO if nx_enabled else Severity.HIGH,
                description="NX prevents execution of code on the stack.",
                recommendation="" if nx_enabled else "Compile without -z execstack to enable NX.",
            ))
            
            # RELRO
            has_relro = False
            full_relro = False
            for segment in elf.iter_segments():
                if segment.header.p_type == 'PT_GNU_RELRO':
                    has_relro = True
                    break
            
            # Check for BIND_NOW (Full RELRO)
            for section in elf.iter_sections():
                if section.name == '.dynamic':
                    from elftools.elf.dynamic import DynamicSection
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == 'DT_BIND_NOW':
                                full_relro = True
                                break
                            if tag.entry.d_tag == 'DT_FLAGS' and tag.entry.d_val & 0x8:
                                full_relro = True
                                break
            
            relro_status = "Full RELRO" if full_relro else ("Partial RELRO" if has_relro else "disabled")
            checks.append(SecurityCheck(
                name="RELRO (Relocation Read-Only)",
                status=relro_status,
                severity=Severity.INFO if full_relro else (Severity.MEDIUM if has_relro else Severity.HIGH),
                description="RELRO protects GOT from overwrite attacks.",
                recommendation="" if full_relro else "Compile with -Wl,-z,relro,-z,now for Full RELRO.",
            ))
            
            # Stack Canary
            has_canary = False
            for section in elf.iter_sections():
                if hasattr(section, 'iter_symbols'):
                    from elftools.elf.sections import SymbolTableSection
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if '__stack_chk_fail' in symbol.name:
                                has_canary = True
                                break
            
            checks.append(SecurityCheck(
                name="Stack Canary",
                status="enabled" if has_canary else "disabled",
                severity=Severity.INFO if has_canary else Severity.HIGH,
                description="Stack canaries detect buffer overflow attacks.",
                recommendation="" if has_canary else "Compile with -fstack-protector-all to enable stack canaries.",
            ))
            
            # Fortify Source
            has_fortify = False
            for section in elf.iter_sections():
                if hasattr(section, 'iter_symbols'):
                    from elftools.elf.sections import SymbolTableSection
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if '_chk' in symbol.name and symbol.name.startswith('__'):
                                has_fortify = True
                                break
            
            checks.append(SecurityCheck(
                name="FORTIFY_SOURCE",
                status="enabled" if has_fortify else "disabled",
                severity=Severity.INFO if has_fortify else Severity.MEDIUM,
                description="FORTIFY_SOURCE adds runtime checks to dangerous functions.",
                recommendation="" if has_fortify else "Compile with -D_FORTIFY_SOURCE=2 to enable runtime buffer overflow checks.",
            ))
    
    except ImportError:
        checks.append(SecurityCheck(
            name="ELF Analysis",
            status="error",
            severity=Severity.INFO,
            description="pyelftools library not installed — ELF security checks skipped.",
        ))
    except Exception as e:
        checks.append(SecurityCheck(
            name="ELF Analysis Error",
            status="error",
            severity=Severity.INFO,
            description=f"Error during ELF analysis: {str(e)}",
        ))
    
    return checks


def check_macho_security(filepath: str) -> list[SecurityCheck]:
    """Check Mach-O security mitigations."""
    checks = []
    
    try:
        import subprocess
        # Use codesign to check signing
        result = subprocess.run(
            ['codesign', '-dv', filepath],
            capture_output=True, text=True, timeout=10
        )
        is_signed = result.returncode == 0
        checks.append(SecurityCheck(
            name="Code Signature",
            status="signed" if is_signed else "unsigned",
            severity=Severity.INFO if is_signed else Severity.MEDIUM,
            description="Binary is code-signed." if is_signed else "Binary is not code-signed.",
            recommendation="" if is_signed else "Sign the binary with codesign for integrity verification.",
        ))
        
        # Check PIE
        result = subprocess.run(
            ['otool', '-hv', filepath],
            capture_output=True, text=True, timeout=10
        )
        is_pie = 'PIE' in result.stdout
        checks.append(SecurityCheck(
            name="PIE (Position Independent Executable)",
            status="enabled" if is_pie else "disabled",
            severity=Severity.INFO if is_pie else Severity.HIGH,
            description="PIE enables ASLR for the main executable.",
            recommendation="" if is_pie else "Compile with -pie flag to enable PIE.",
        ))
        
        # Check for ARC (Automatic Reference Counting)
        result = subprocess.run(
            ['otool', '-l', filepath],
            capture_output=True, text=True, timeout=10
        )
        has_arc = 'objc_release' in result.stdout or '__objc_methname' in result.stdout
        
    except Exception as e:
        checks.append(SecurityCheck(
            name="Mach-O Analysis",
            status="error",
            severity=Severity.INFO,
            description=f"Error during Mach-O analysis: {str(e)}",
        ))
    
    return checks


def check_security(filepath: str, file_type: FileType) -> list[SecurityCheck]:
    """Route security checks to the correct analyzer."""
    if file_type == FileType.PE:
        return check_pe_security(filepath)
    elif file_type == FileType.ELF:
        return check_elf_security(filepath)
    elif file_type == FileType.MACHO:
        return check_macho_security(filepath)
    return []
