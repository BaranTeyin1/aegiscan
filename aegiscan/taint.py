from typing import List, Dict, Any, Set, Tuple, Optional
import ast

class TaintTracker:
    def __init__(self, aliases: Dict[str, str], show_taint: bool = False):
        self.tainted_vars: Set[str] = set()
        self.aliases = aliases # From AegiscanVisitor
        self.tainted_call_returns: Set[str] = set() # To track tainted return values of function calls
        self.tainted_function_returns: Set[str] = set() # To track functions whose returns are tainted
        self.tainted_function_parameters: Dict[str, Set[str]] = {} # To track tainted parameters of functions
        self.show_taint = show_taint
        self.taint_log: List[str] = []
        self.logged_taint_events: Set[str] = set() # To store unique log messages for the current trace

    def is_tainted(self, name: str) -> bool:
        # Resolve alias if exists
        resolved_name = self.aliases.get(name, name)
        return resolved_name in self.tainted_vars

    def _log_taint_event(self, message: str):
        if self.show_taint and message not in self.logged_taint_events:
            self.taint_log.append(message)
            self.logged_taint_events.add(message)

    def add_source(self, name: str):
        resolved_name = self.aliases.get(name, name)
        self.tainted_vars.add(resolved_name)
        self._log_taint_event(f"Source detected: '{resolved_name}'")

    def mark_function_return_tainted(self, fully_qualified_function_name: str):
        self.tainted_function_returns.add(fully_qualified_function_name)
        self._log_taint_event(f"Function return tainted: '{fully_qualified_function_name}'")

    def is_function_return_tainted(self, fully_qualified_function_name: str) -> bool:
        return fully_qualified_function_name in self.tainted_function_returns

    def mark_function_parameter_tainted(self, fqn_function: str, parameter_name: str):
        if fqn_function not in self.tainted_function_parameters:
            self.tainted_function_parameters[fqn_function] = set()
        self.tainted_function_parameters[fqn_function].add(parameter_name)
        self._log_taint_event(f"Taint flows to function parameter: '{fqn_function}' -> parameter '{parameter_name}'")

    def is_function_parameter_tainted(self, fqn_function: str, parameter_name: str) -> bool:
        return parameter_name in self.tainted_function_parameters.get(fqn_function, set())

    def handle_call_return(self, func_name: str, return_var_name: Optional[str] = None):
        """Marks the return value of a function call as tainted if the function is a known source."""
        if func_name in {"input", "request.args.get", "request.form.get", "request.json.get"}: # Simplified list of sources
            if return_var_name:
                self.add_source(return_var_name)
                self._log_taint_event(f"Taint flows from call return: '{func_name}' -> '{return_var_name}'")
            self.tainted_call_returns.add(func_name)
            if not return_var_name: # Log if no assignment but return is tainted
                self._log_taint_event(f"Tainted call return: '{func_name}'")

    def propagate_taint(self, node: ast.AST):
        if isinstance(node, ast.Assign):
            # Propagate taint through assignment
            if isinstance(node.value, ast.Name) and self.is_tainted(node.value.id):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.add_source(target.id)
                        self._log_taint_event(f"Taint propagates by assignment: '{node.value.id}' -> '{target.id}'")
            elif isinstance(node.value, ast.Call):
                # Check if the function call itself is tainted (e.g., from a source function)
                func_name = None
                if isinstance(node.value.func, ast.Name):
                    func_name = node.value.func.id
                elif isinstance(node.value.func, ast.Attribute):
                    if isinstance(node.value.func.value, ast.Name):
                        func_name = f"{node.value.func.value.id}.{node.value.func.attr}"
                
                # If the function call return is tainted, mark the assigned variable as tainted
                if func_name and (func_name in self.tainted_call_returns or func_name in self.tainted_function_returns):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.add_source(target.id)
                            self._log_taint_event(f"Taint propagates from call return: '{func_name}' -> '{target.id}'")
                else: # Check if any argument to a call is tainted and propagate if needed
                    for arg in node.value.args:
                        if isinstance(arg, ast.Name) and self.is_tainted(arg.id):
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.add_source(target.id)
                                    self._log_taint_event(f"Taint propagates from call argument: '{arg.id}' -> '{target.id}'")
                                break # Taint propagates if any arg is tainted
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            # This handles cases where a function call is not assigned to a variable, but its arguments might be tainted
            func_name = None
            if isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                if isinstance(node.value.func.value, ast.Name):
                    func_name = f"{node.value.func.value.id}.{node.value.func.attr}"
            
            # If any argument to this unassigned call is tainted, consider the call itself as 'tainted' conceptually
            # This is more for tracking internal state for potential sinks, not for assignment propagation
            for arg in node.value.args:
                if isinstance(arg, ast.Name) and self.is_tainted(arg.id):
                    self._log_taint_event(f"Tainted argument passed to unassigned call: '{arg.id}' to '{func_name}'")
                    pass # Add pass statement to resolve IndentationError
                    # In a full dataflow, we'd mark the return value if it's a source function.
                    # For now, this just ensures we know the arguments are tainted.
                    # This specific part for unassigned calls needs more context in Analyzer to be effective
                    # if func_name and func_name in {"os.system"}: # Example for direct sink, this logic is better in Analyzer
                    #     pass

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # For function definitions, mark arguments as tainted if they are sources.
            # This requires knowing which arguments are considered sources by rules.
            pass # This will be handled by the Analyzer when applying rules

    def get_taint_trace(self) -> List[str]:
        """Returns the collected taint log and clears it."""
        trace = list(self.taint_log)
        self.taint_log.clear()
        self.logged_taint_events.clear() # Clear unique events for the next trace
        return trace

    def get_tainted_variables(self) -> Set[str]:
        return self.tainted_vars
