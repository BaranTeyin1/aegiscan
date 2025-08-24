import ast
import os
from typing import List, Dict, Any, Optional
from aegiscan.symbols import SymbolInfo, SymbolType

class AegiscanVisitor(ast.NodeVisitor):
    def __init__(self, file_content: str, file_path: str, module_name: str):
        self.findings = []
        self.aliases: Dict[str, str] = {}
        self.imports: Dict[str, str] = {}
        self.file_content = file_content
        self.file_path = file_path
        self.module_name = module_name
        self.symbols: List[SymbolInfo] = []
        self.current_class: Optional[str] = None # To track current class for method FQN

    def _get_fully_qualified_name(self, name: str) -> str:
        if self.current_class:
            return f"{self.module_name}.{self.current_class}.{name}"
        return f"{self.module_name}.{name}"

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
                self.imports[alias.asname] = alias.name
            else:
                self.aliases[alias.name] = alias.name
                self.imports[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module if node.module else ""
        # Handle relative imports
        if node.level > 0:
            # Determine the package path
            package_path = os.path.dirname(self.file_path)
            for _ in range(node.level - 1):
                package_path = os.path.dirname(package_path)
            
            # Convert path to module name
            relative_module = os.path.relpath(package_path, os.getcwd()).replace(os.sep, ".")
            if relative_module == ".": # Top-level package
                relative_module = ""
            
            if module:
                full_module_name = f"{relative_module}.{module}" if relative_module else module
            else:
                full_module_name = relative_module
        else:
            full_module_name = module

        for alias in node.names:
            # Construct the full name of the imported object
            imported_name = alias.name
            if full_module_name:
                full_qualified_imported_name = f"{full_module_name}.{imported_name}"
            else:
                full_qualified_imported_name = imported_name

            # Store the alias mapping
            if alias.asname:
                self.aliases[alias.asname] = full_qualified_imported_name
                self.imports[alias.asname] = full_qualified_imported_name
            else:
                self.aliases[imported_name] = full_qualified_imported_name
                self.imports[imported_name] = full_qualified_imported_name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        function_name = node.name
        fully_qualified_name = self._get_fully_qualified_name(function_name)
        
        parameters = []
        for arg in node.args.args:
            param_info = {"name": arg.arg}
            if arg.annotation:
                param_info["annotation"] = ast.unparse(arg.annotation) # Convert AST node to string
            parameters.append(param_info)
        
        # Add default values for parameters
        for i, default_value in enumerate(node.args.defaults):
            param_info = parameters[len(parameters) - len(node.args.defaults) + i]
            param_info["default"] = ast.unparse(default_value)

        return_type = ast.unparse(node.returns) if node.returns else None

        self.symbols.append(
            SymbolInfo(
                name=function_name,
                fully_qualified_name=fully_qualified_name,
                file_path=self.file_path,
                start_line=node.lineno,
                end_line=node.end_lineno,
                symbol_type=SymbolType.FUNCTION,
                parameters=parameters,
                return_type=return_type,
            )
        )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        # Handle async functions similarly to regular functions
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        class_name = node.name
        fully_qualified_name = self._get_fully_qualified_name(class_name)
        
        self.symbols.append(
            SymbolInfo(
                name=class_name,
                fully_qualified_name=fully_qualified_name,
                file_path=self.file_path,
                start_line=node.lineno,
                end_line=node.end_lineno,
                symbol_type=SymbolType.CLASS,
            )
        )
        # Set current_class to handle methods within the class
        original_current_class = self.current_class
        self.current_class = class_name
        self.generic_visit(node)
        self.current_class = original_current_class # Restore previous class context

    def visit_Assign(self, node: ast.Assign):
        # Capture top-level variable assignments (not inside functions/classes)
        if not isinstance(node.targets[0], ast.Name): # Only handle simple assignments for now
            self.generic_visit(node)
            return

        if not self.current_class and not any(isinstance(a, (ast.FunctionDef, ast.AsyncFunctionDef)) for a in ast.walk(node)):
            variable_name = node.targets[0].id
            fully_qualified_name = self._get_fully_qualified_name(variable_name)
            
            self.symbols.append(
                SymbolInfo(
                    name=variable_name,
                    fully_qualified_name=fully_qualified_name,
                    file_path=self.file_path,
                    start_line=node.lineno,
                    end_line=node.end_lineno,
                    symbol_type=SymbolType.VARIABLE,
                )
            )
        self.generic_visit(node)
    
    def visit_AnnAssign(self, node: ast.AnnAssign):
        # Capture top-level annotated variable assignments
        if isinstance(node.target, ast.Name):
            if not self.current_class and not any(isinstance(a, (ast.FunctionDef, ast.AsyncFunctionDef)) for a in ast.walk(node)):
                variable_name = node.target.id
                fully_qualified_name = self._get_fully_qualified_name(variable_name)
                
                self.symbols.append(
                    SymbolInfo(
                        name=variable_name,
                        fully_qualified_name=fully_qualified_name,
                        file_path=self.file_path,
                        start_line=node.lineno,
                        end_line=node.end_lineno,
                        symbol_type=SymbolType.VARIABLE,
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # The eval finding is now handled by rule AEGISCAN-002, so removing this hardcoded finding.
        # if isinstance(node.func, ast.Name) and node.func.id == 'eval':
        #     self.findings.append({
        #         "file": "current_file.py", # This will be filled by the analyzer
        #         "startLine": node.lineno,
        #         "endLine": node.end_lineno,
        #         "ruleId": "RCE-001",
        #         "severity": "HIGH",
        #         "message": "Potential Remote Code Execution via eval()",
        #         "codeSnippet": ast.get_source_segment(self.file_content, node),
        #         "confidence": "HIGH",
        #         "fingerprint": "",
        #         "cwe": "CWE-94",
        #         "fix": "Use ast.literal_eval for safe evaluation."
        #     })
        self.generic_visit(node)

    def get_fully_qualified_name_from_alias(self, name: str) -> str:
        return self.aliases.get(name, name)
