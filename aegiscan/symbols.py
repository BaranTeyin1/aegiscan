import dataclasses
from enum import Enum
import ast
import os
from typing import List, Dict, Optional, Any

class SymbolType(Enum):
    FUNCTION = "function"
    CLASS = "class"
    VARIABLE = "variable"
    MODULE = "module" # Not strictly a symbol, but useful for context

@dataclasses.dataclass
class SymbolInfo:
    name: str
    fully_qualified_name: str
    file_path: str
    start_line: int
    end_line: int
    symbol_type: SymbolType
    parameters: Optional[List[Dict[str, Any]]] = None  # For functions: [{'name': 'param_name', 'default': 'default_value'}]
    return_type: Optional[str] = None  # For functions
    is_exported: bool = True # Assume all top-level symbols are exported

class SymbolResolver:
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.global_symbol_table: Dict[str, SymbolInfo] = {}

    def _get_module_name_from_path(self, file_path: str) -> str:
        relative_path = os.path.relpath(file_path, self.project_root)
        module_name = relative_path.replace(os.sep, ".")
        if module_name.endswith(".py"):
            module_name = module_name[:-3]
        if module_name.endswith(".__init__"):
            module_name = module_name[:-9]
        return module_name

    def collect_symbols(self, target_directory: str):
        for root, _, files in os.walk(target_directory):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    module_name = self._get_module_name_from_path(file_path)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            file_content = f.read()
                        tree = ast.parse(file_content, filename=file_path)
                        
                        # Use the extended AegiscanVisitor to collect symbols and imports
                        from aegiscan.visitor import AegiscanVisitor
                        visitor = AegiscanVisitor(file_content, file_path, module_name)
                        visitor.visit(tree)

                        print(f"[DEBUG] Symbols collected in {module_name}:")
                        for symbol in visitor.symbols:
                            self.global_symbol_table[symbol.fully_qualified_name] = symbol
                            print(f"  - {symbol.fully_qualified_name} ({symbol.symbol_type.value}) at {symbol.file_path}:{symbol.start_line}")
                        
                        print(f"[DEBUG] Imports collected in {module_name}:")
                        for alias, fqn in visitor.imports.items():
                            print(f"  - {alias} -> {fqn}")

                    except SyntaxError as e:
                        print(f"Warning: Could not parse {file_path} due to syntax error: {e}")
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")

    def resolve_call(self, caller_module: str, call_name: str, imports_in_caller_module: Dict[str, str]) -> Optional[SymbolInfo]:
        # First, try to resolve the call_name directly if it's already fully qualified.
        if call_name in self.global_symbol_table:
            return self.global_symbol_table[call_name]

        # Next, try to resolve from the imports within the caller module
        if call_name in imports_in_caller_module:
            imported_fqn = imports_in_caller_module[call_name]
            if imported_fqn in self.global_symbol_table:
                return self.global_symbol_table[imported_fqn]
            
            # If the imported_fqn is still relative, try to resolve it by combining with the caller's parent module.
            # Example: caller_module = "vulnerable-codes.os-command-inj.app"
            # imported_fqn = "vuln.run_command" (from `from vuln import run_command`)
            # We need to construct "vulnerable-codes.os-command-inj.vuln.run_command"
            if '.' in imported_fqn and '.' in caller_module:
                # Remove the last part of caller_module (e.g., 'app') and append the imported_fqn
                caller_module_parent = '.'.join(caller_module.split('.')[:-1])
                potential_fqn = f"{caller_module_parent}.{imported_fqn}"
                if potential_fqn in self.global_symbol_table:
                    return self.global_symbol_table[potential_fqn]

        # Finally, try to resolve as a direct member of the caller's module
        potential_fqn_in_module = f"{caller_module}.{call_name}"
        if potential_fqn_in_module in self.global_symbol_table:
            return self.global_symbol_table[potential_fqn_in_module]
