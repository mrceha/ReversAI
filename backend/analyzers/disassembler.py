"""
ReversAI Disassembler
Interfaces with radare2 via r2pipe for disassembly.
Falls back to capstone if radare2 is not available.
"""

import shutil
import subprocess
from backend.models.schemas import FunctionInfo


def is_radare2_available() -> bool:
    """Check if radare2 is installed."""
    return shutil.which('radare2') is not None or shutil.which('r2') is not None


def disassemble_with_r2(filepath: str, max_functions: int = 30) -> list[FunctionInfo]:
    """Disassemble binary using radare2 via r2pipe."""
    functions = []
    
    try:
        import r2pipe
        
        r2 = r2pipe.open(filepath, flags=['-2'])  # -2 suppresses stderr
        r2.cmd('aaa')  # Full analysis
        
        # Get function list
        func_list = r2.cmdj('aflj') or []
        
        # Sort by size (larger functions are usually more interesting)
        func_list.sort(key=lambda f: f.get('size', 0), reverse=True)
        
        for func in func_list[:max_functions]:
            name = func.get('name', 'unknown')
            offset = func.get('offset', 0)
            size = func.get('size', 0)
            
            # Skip tiny functions
            if size < 10:
                continue
            
            # Get disassembly
            r2.cmd(f's {offset}')
            disasm = r2.cmd(f'pdf') or ''
            
            # Get callees
            callees = []
            xrefs = r2.cmdj(f'afxj {offset}') or []
            for xref in xrefs:
                if isinstance(xref, dict) and 'name' in xref:
                    callees.append(xref['name'])
            
            functions.append(FunctionInfo(
                name=name,
                address=offset,
                size=size,
                disassembly=disasm[:5000],  # Cap at 5000 chars
                callees=callees,
            ))
        
        r2.quit()
    except ImportError:
        pass
    except Exception as e:
        functions.append(FunctionInfo(
            name="[error]",
            disassembly=f"Disassembly error: {str(e)}"
        ))
    
    return functions


def disassemble_with_capstone(filepath: str, max_instructions: int = 500) -> list[FunctionInfo]:
    """Fallback disassembly using capstone (entry point region only)."""
    functions = []
    
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
        import struct
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Try to detect architecture and entry point
        mode = CS_MODE_64
        entry_offset = 0
        
        # PE
        if data[:2] == b'MZ':
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
                mode = CS_MODE_64 if machine == 0x8664 else CS_MODE_32
                entry_rva = struct.unpack_from('<I', data, pe_offset + 0x28)[0]
                # Simple section lookup for entry point file offset
                num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
                opt_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
                sec_start = pe_offset + 24 + opt_size
                for i in range(num_sections):
                    sec_off = sec_start + i * 40
                    vaddr = struct.unpack_from('<I', data, sec_off + 12)[0]
                    vsize = struct.unpack_from('<I', data, sec_off + 8)[0]
                    raw_off = struct.unpack_from('<I', data, sec_off + 20)[0]
                    if vaddr <= entry_rva < vaddr + vsize:
                        entry_offset = raw_off + (entry_rva - vaddr)
                        break
        
        # ELF
        elif data[:4] == b'\x7fELF':
            elf_class = data[4]
            mode = CS_MODE_64 if elf_class == 2 else CS_MODE_32
            if elf_class == 2:
                entry_offset = struct.unpack_from('<Q', data, 24)[0]
            else:
                entry_offset = struct.unpack_from('<I', data, 24)[0]
            # Note: this is virtual address, not file offset — simplified
            entry_offset = min(entry_offset, len(data) - 100)
        
        # Disassemble from entry
        md = Cs(CS_ARCH_X86, mode)
        md.detail = False
        
        code_region = data[entry_offset:entry_offset + 4096]
        disasm_lines = []
        for instr in md.disasm(code_region, entry_offset):
            disasm_lines.append(f"0x{instr.address:08x}:  {instr.mnemonic}\t{instr.op_str}")
            if len(disasm_lines) >= max_instructions:
                break
        
        functions.append(FunctionInfo(
            name="entry_point",
            address=entry_offset,
            size=len(code_region),
            disassembly='\n'.join(disasm_lines),
        ))
        
    except ImportError:
        functions.append(FunctionInfo(
            name="[error]",
            disassembly="capstone library not installed — install with: pip install capstone",
        ))
    except Exception as e:
        functions.append(FunctionInfo(
            name="[error]",
            disassembly=f"Disassembly error: {str(e)}",
        ))
    
    return functions


def disassemble(filepath: str, max_functions: int = 30) -> list[FunctionInfo]:
    """Disassemble binary using best available tool."""
    if is_radare2_available():
        return disassemble_with_r2(filepath, max_functions)
    return disassemble_with_capstone(filepath)
