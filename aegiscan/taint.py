from typing import List, Dict, Any, Set, Tuple, Optional
import ast

class TaintTracker:
    def __init__(self, aliases: Dict[str, str]):
        self.tainted_vars: Set[str] = set()
        self.aliases = aliases # From AegiscanVisitor
        self.tainted_call_returns: Set[str] = set() # To track tainted return values of function calls

    def is_tainted(self, name: str) -> bool:
        # Resolve alias if exists
        resolved_name = self.aliases.get(name, name)
        return resolved_name in self.tainted_vars

    def add_source(self, name: str):
        resolved_name = self.aliases.get(name, name)
        self.tainted_vars.add(resolved_name)

    def handle_call_return(self, func_name: str, return_var_name: Optional[str] = None):
        """Marks the return value of a function call as tainted if the function is a known source."""
        if func_name in {"input", "request.args.get", "request.form.get", "request.json.get"}: # Simplified list of sources
            if return_var_name:
                self.add_source(return_var_name)

    def propagate_taint(self, node: ast.AST):
        if isinstance(node, ast.Assign):
            # Propagate taint through assignment
            if isinstance(node.value, ast.Name) and self.is_tainted(node.value.id):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.add_source(target.id)
            elif isinstance(node.value, ast.Call):
                # Check if the function call itself is tainted (e.g., from a source function)
                func_name = None
                if isinstance(node.value.func, ast.Name):
                    func_name = node.value.func.id
                elif isinstance(node.value.func, ast.Attribute):
                    if isinstance(node.value.func.value, ast.Name):
                        func_name = f"{node.value.func.value.id}.{node.value.func.attr}"
                
                if func_name and func_name in self.tainted_call_returns:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.add_source(target.id)
                else: # Check if any argument to a call is tainted and propagate if needed
                    for arg in node.value.args:
                        if isinstance(arg, ast.Name) and self.is_tainted(arg.id):
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.add_source(target.id)
                                break # Taint propagates if any arg is tainted
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # For function definitions, mark arguments as tainted if they are sources.
            # This requires knowing which arguments are considered sources by rules.
            pass # This will be handled by the Analyzer when applying rules

    def get_tainted_variables(self) -> Set[str]:
        return self.tainted_vars
