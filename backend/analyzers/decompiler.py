"""
ReversAI Decompiler
Decompiles binary functions to pseudo-C using radare2 plugins.
"""

import shutil
from backend.models.schemas import FunctionInfo


def is_decompiler_available() -> bool:
    return shutil.which('radare2') is not None or shutil.which('r2') is not None


def decompile_functions(filepath: str, functions: list[FunctionInfo], max_functions: int = 20) -> list[FunctionInfo]:
    if not is_decompiler_available():
        return functions
    try:
        import r2pipe
        r2 = r2pipe.open(filepath, flags=['-2'])
        r2.cmd('aaa')
        decompiler_cmd = 'pdd'
        plugins = r2.cmd('Lc') or ''
        if 'ghidra' in plugins.lower():
            decompiler_cmd = 'pdg'
        decompiled_count = 0
        for func in functions[:max_functions]:
            if func.name == "[error]" or func.size < 20:
                continue
            try:
                r2.cmd(f's {func.address}')
                result = r2.cmd(decompiler_cmd) or ''
                if result and 'Cannot' not in result and len(result) > 20:
                    func.decompiled = result[:8000]
                    decompiled_count += 1
            except Exception:
                continue
        r2.quit()
    except (ImportError, Exception):
        pass
    return functions
