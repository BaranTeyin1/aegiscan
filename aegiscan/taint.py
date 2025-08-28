from typing import List, Dict, Any, Set, Tuple, Optional
import ast

class TaintTracker:
    def __init__(self, aliases: Dict[str, str], show_taint: bool = False):
        self.tainted_vars: Set[str] = set()
        self.aliases = aliases # From AegiscanVisitor
        self.tainted_call_returns: Set[str] = set() # To track tainted return values of function calls
        self.tainted_function_returns: Set[str] = set() # To track functions whose returns are tainted
        self.tainted_function_parameters: Dict[str, Set[str]] = {} # To track tainted parameters of functions
        self.tainted_attributes: Set[str] = set() # New: To track fully qualified tainted attributes (e.g., "module.Class.attribute")
        self.show_taint = show_taint
        self.taint_log: List[str] = []
        self.logged_taint_events: Set[str] = set() # To store unique log messages for the current trace

    def is_tainted(self, name: str, is_attribute: bool = False) -> bool:
        # Resolve alias if exists for variables
        if not is_attribute:
            resolved_name = self.aliases.get(name, name)
            return resolved_name in self.tainted_vars
        else:
            # For attributes, name is expected to be a FQN already
            return name in self.tainted_attributes

    def _log_taint_event(self, message: str):
        if self.show_taint and message not in self.logged_taint_events:
            self.taint_log.append(message)
            self.logged_taint_events.add(message)

    def add_source(self, name: str, is_attribute: bool = False):
        if not is_attribute:
            resolved_name = self.aliases.get(name, name)
            self.tainted_vars.add(resolved_name)
            self._log_taint_event(f"Source detected: '{resolved_name}'")
        else:
            # For attributes, name is expected to be a FQN already
            self.tainted_attributes.add(name)
            self._log_taint_event(f"Tainted attribute detected: '{name}'")

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
            # Propagate taint through assignment to variables and attributes
            is_value_tainted = False
            if isinstance(node.value, ast.Name) and self.is_tainted(node.value.id):
                is_value_tainted = True
            elif isinstance(node.value, ast.Call):
                func_name = None
                if isinstance(node.value.func, ast.Name):
                    func_name = node.value.func.id
                elif isinstance(node.value.func, ast.Attribute):
                    # This case is handled by _get_name_from_node in Analyzer.py, but here we need its FQN.
                    # For now, we'll assume func_name is the FQN from analyzer.
                    func_name = self._get_name_from_node_for_taint_propagation(node.value.func) # New helper for FQN

                if func_name and (func_name in self.tainted_call_returns or func_name in self.tainted_function_returns):
                    is_value_tainted = True
                else:
                    for arg in node.value.args:
                        if isinstance(arg, ast.Name) and self.is_tainted(arg.id):
                            is_value_tainted = True
                            break
                        elif isinstance(arg, ast.Attribute):
                            attribute_fqn = self._get_name_from_node_for_taint_propagation(arg)
                            if attribute_fqn and self.is_tainted(attribute_fqn, is_attribute=True):
                                is_value_tainted = True
                                break

            if is_value_tainted:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.add_source(target.id) # Mark variable as tainted
                        self._log_taint_event(f"Taint propagates by assignment: Value -> '{target.id}'")
                    elif isinstance(target, ast.Attribute):
                        # This requires FQN for the attribute
                        attribute_fqn = self._get_name_from_node_for_taint_propagation(target)
                        if attribute_fqn:
                            self.add_source(attribute_fqn, is_attribute=True)
                            self._log_taint_event(f"Taint propagates by assignment: Value -> '{attribute_fqn}'")

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

    def _get_name_from_node_for_taint_propagation(self, node: ast.AST) -> Optional[str]:
        """
        Helper to get the name (or FQN for attributes/calls) of a node during taint propagation.
        This is a simplified version for use *within* TaintTracker, as it doesn't have access
        to Analyzer's symbol resolver or current_module_name/visitor.
        It relies on FQNs being already established for attributes/function returns.
        """
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            # For attributes, we need a way to reconstruct the FQN
            # This is a limitation without full context from Analyzer.
            # For a basic approach, we can stringify if possible.
            # A more robust solution would involve passing FQNs from Analyzer.
            if isinstance(node.value, ast.Name):
                if node.value.id == "self": # Special handling for self.attribute
                    # This FQN will be built by Analyzer and passed to tainted_attributes
                    # For now, we rely on it being already present in tainted_attributes
                    return f"self.{node.attr}" # Placeholder, actual FQN will be more complete
                return f"{node.value.id}.{node.attr}"
            elif isinstance(node.value, ast.Attribute):
                base_name = self._get_name_from_node_for_taint_propagation(node.value)
                if base_name:
                    return f"{base_name}.{node.attr}"
            return None
        elif isinstance(node, ast.Call):
            return self._get_name_from_node_for_taint_propagation(node.func)
        return None

    def get_taint_trace(self) -> List[str]:
        """Returns the collected taint log and clears it."""
        trace = list(self.taint_log)
        self.taint_log.clear()
        self.logged_taint_events.clear() # Clear unique events for the next trace
        return trace

    def get_tainted_variables(self) -> Set[str]:
        return self.tainted_vars
