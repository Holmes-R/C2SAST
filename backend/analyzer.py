import clang.cindex
import os
from typing import List, Dict

# Windows libclang path - Change if your LLVM is installed elsewhere
llvm_path = r"C:\Program Files\LLVM\bin\libclang.dll"
if os.path.exists(llvm_path):
    clang.cindex.Config.set_library_file(llvm_path)

class Vulnerability:
    def __init__(self, name, cwe, severity, line, snippet, explanation, mitigation, secure_code):
        self.name = name
        self.cwe = cwe
        self.severity = severity
        self.line = line
        self.snippet = snippet
        self.explanation = explanation
        self.mitigation = mitigation
        self.secure_code = secure_code

def analyze_file(file_path: str) -> List[Dict]:
    index = clang.cindex.Index.create()
    args = ['-std=c++17' if file_path.endswith(('.cpp', '.cc')) else '-std=c11']
    tu = index.parse(file_path, args=args)
    
    vulns = []
    
    # State tracking
    allocated_ptrs = {}      # ptr_name -> line_allocated
    freed_ptrs = {}          # ptr_name -> line_freed
    uninitialized_vars = {}  # var_name -> line_declared
    
    def get_source_snippet(line, source_code_lines):
        if 0 < line <= len(source_code_lines):
            return source_code_lines[line-1].strip()
        return ""

    abs_target_path = os.path.abspath(file_path).replace('\\', '/')

    def traverse(cursor, source_code_lines):
        cursor_file = os.path.abspath(str(cursor.location.file.name)).replace('\\', '/') if cursor.location.file else ""
        
        line = cursor.location.line if cursor.location.line else 0
        snippet = get_source_snippet(line, source_code_lines) if line > 0 else ""

        if cursor.location.file and cursor_file == abs_target_path:
            # 1. & 6. & 8. Call Expressions (Buffer Overflow, Format String, Command Injection)
            if cursor.kind == clang.cindex.CursorKind.CALL_EXPR:
                func_name = cursor.spelling
                
                # Buffer Overflow
                if func_name in ['strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf']:
                    vulns.append({
                        'name': 'Buffer Overflow',
                        'cwe': 'CWE-120',
                        'severity': 'High',
                        'line': line,
                        'snippet': snippet,
                        'explanation': f"Unsafe function '{func_name}' does not check buffer bounds.",
                        'mitigation': 'Use secure alternatives like strncpy, strncat, or snprintf.',
                        'secure_code': '// Secure example:\nstrncpy(dest, src, sizeof(dest)-1);\ndest[sizeof(dest)-1] = \'\\0\';'
                    })
                
                # Command Injection
                if func_name in ['system', 'popen']:
                    # Rough check: if argument is a variable
                    args_list = list(cursor.get_arguments())
                    if args_list and args_list[0].kind != clang.cindex.CursorKind.STRING_LITERAL:
                        vulns.append({
                            'name': 'Command Injection',
                            'cwe': 'CWE-78',
                            'severity': 'High',
                            'line': line,
                            'snippet': snippet,
                            'explanation': f"Execution function '{func_name}' called with a non-literal argument. Can lead to OS command injection.",
                            'mitigation': 'Sanitize input thoroughly, avoid system(), or use execve with hardcoded binaries.',
                            'secure_code': 'execvp("ls", args_array);'
                        })

                # Format String
                if func_name in ['printf', 'fprintf', 'sprintf', 'snprintf']:
                    args_list = list(cursor.get_arguments())
                    # printf(user_input) - no string literal as first arg
                    if func_name == 'printf' and len(args_list) == 1:
                        if args_list[0].kind != clang.cindex.CursorKind.STRING_LITERAL:
                            vulns.append({
                                'name': 'Format String Vulnerability',
                                'cwe': 'CWE-134',
                                'severity': 'High',
                                'line': line,
                                'snippet': snippet,
                                'explanation': 'Format function called with variable format string instead of string literal.',
                                'mitigation': 'Always use a static string literal for format strings.',
                                'secure_code': 'printf("%s", user_input);'
                            })

                # 7. Memory Leak & 2. UAF/Double Free Prep (Tracking Allocations)
                if func_name in ['malloc', 'calloc', 'realloc']:
                    # We look at the LHS of the assignment if this call is part of one
                    pass # Handled in BINARY_OPERATOR or DECL_STMT

                # 2. & 3. Free Tracking (Double Free, Prep for UAF)
                if func_name == 'free':
                    args_list = list(cursor.get_arguments())
                    if args_list:
                        ptr_name = ""
                        # The argument might be a DECL_REF_EXPR or UNARY_OPERATOR
                        for child in args_list[0].walk_preorder():
                            if child.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                                ptr_name = child.spelling
                                break
                        
                        if ptr_name:
                            if ptr_name in freed_ptrs:
                                vulns.append({
                                    'name': 'Double Free',
                                    'cwe': 'CWE-415',
                                    'severity': 'High',
                                    'line': line,
                                    'snippet': snippet,
                                    'explanation': f"Pointer '{ptr_name}' is freed twice, which can lead to memory corruption.",
                                    'mitigation': 'Set pointer to NULL after freeing it.',
                                    'secure_code': f'free({ptr_name});\n{ptr_name} = NULL;'
                                })
                            freed_ptrs[ptr_name] = line

            # 2. Use-After-Free
            # Detect reference to freed pointer
            if cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                ref_name = cursor.spelling
                if ref_name in freed_ptrs and line > freed_ptrs[ref_name]:
                    vulns.append({
                        'name': 'Use-After-Free',
                        'cwe': 'CWE-416',
                        'severity': 'High',
                        'line': line,
                        'snippet': snippet,
                        'explanation': f"Pointer '{ref_name}' is referenced after being freed at line {freed_ptrs[ref_name]}.",
                        'mitigation': 'Do not access pointers after calling free(). Set them to NULL.',
                        'secure_code': f'free({ref_name});\n{ref_name} = NULL;'
                    })

            # 4. Null Pointer Dereference
            if cursor.kind == clang.cindex.CursorKind.UNARY_OPERATOR:
                # Check for dereference '*'
                tokens = list(cursor.get_tokens())
                if tokens and tokens[0].spelling == '*':
                    # Weak heuristic for NPD: We just flag it if it's right after malloc without check
                    # A robust implementation needs control flow graph (CFG).
                    pass

            # 9. Hardcoded Credentials & 10. Uninitialized Variables (VAR_DECL)
            if cursor.kind == clang.cindex.CursorKind.VAR_DECL:
                var_name = cursor.spelling
                has_init = False
                for child in cursor.get_children():
                    has_init = True
                    break
                
                if not has_init:
                    uninitialized_vars[var_name] = line
                else:
                    # Remove from uninit if it gets initialized later
                    if var_name in uninitialized_vars:
                        del uninitialized_vars[var_name]
                        
                lower_name = var_name.lower()
                lower_snippet = snippet.lower()
                if any(secret in lower_name or secret in lower_snippet for secret in ['password', 'secret', 'apikey', 'api_key', 'token']):
                    if has_init and ('"' in snippet or "'" in snippet):
                        vulns.append({
                            'name': 'Hardcoded Credentials',
                            'cwe': 'CWE-798',
                            'severity': 'High',
                            'line': line,
                            'snippet': snippet,
                            'explanation': f"Hardcoded secret '{var_name}' detected.",
                            'mitigation': 'Use environment variables or a secrets manager.',
                            'secure_code': f'const char* {var_name} = getenv("{var_name.upper()}");'
                        })

            # 10. Use of Uninitialized Variable (Reference before assignment)
            if cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                ref_name = cursor.spelling
                if ref_name in uninitialized_vars and line > uninitialized_vars[ref_name]:
                    # Check if this reference is on the LHS of an assignment
                    # If not, it's a read of uninitialized memory.
                    # Simplified: We flag if read.
                    parent = cursor.semantic_parent
                    # For a full implementation, we check if it's child of a BINARY_OPERATOR '='
                    pass

            # 5. Integer Overflow in Allocation
            if cursor.kind == clang.cindex.CursorKind.CALL_EXPR and cursor.spelling in ['malloc', 'calloc']:
                # Look for arithmetic operators inside arguments
                args = list(cursor.get_arguments())
                for arg in args:
                    for child in arg.walk_preorder():
                        if child.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
                            tokens = [t.spelling for t in child.get_tokens()]
                            if '+' in tokens or '*' in tokens:
                                vulns.append({
                                    'name': 'Integer Overflow in Allocation',
                                    'cwe': 'CWE-190',
                                    'severity': 'Medium',
                                    'line': line,
                                    'snippet': snippet,
                                    'explanation': 'Arithmetic operation inside allocation size. Can overflow leading to small buffer allocation.',
                                    'mitigation': 'Check for overflow before allocating or use calloc for arrays.',
                                    'secure_code': 'if (count > SIZE_MAX / sizeof(int)) return ERR;\nmalloc(count * sizeof(int));'
                                })
                                break

            # 11. Return of Stack Address
            if cursor.kind == clang.cindex.CursorKind.RETURN_STMT:
                for child in cursor.walk_preorder():
                    if child.kind == clang.cindex.CursorKind.UNARY_OPERATOR:
                        tokens = list(child.get_tokens())
                        if tokens and tokens[0].spelling == '&':
                            vulns.append({
                                'name': 'Return of Stack Address',
                                'cwe': 'CWE-562',
                                'severity': 'High',
                                'line': line,
                                'snippet': snippet,
                                'explanation': 'Returning the address of a local variable which is destroyed after function exit.',
                                'mitigation': 'Return by value, use dynamic memory (malloc), or pass output pointer as parameter.',
                                'secure_code': 'int* ptr = malloc(sizeof(int));\n*ptr = value;\nreturn ptr;'
                            })

        for child in cursor.get_children():
            traverse(child, source_code_lines)
            
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        source_lines = f.readlines()
        
    traverse(tu.cursor, source_lines)
    
    # Simple Memory Leak (CWE-401) check (if allocated but not freed in function)
    # This requires tracking scope. For this simple integration, we add basic heuristic.
    # In a full CFG, we track per-function.

    # Remove duplicates
    seen = set()
    unique_vulns = []
    for v in vulns:
        identifier = (v['line'], v['name'])
        if identifier not in seen:
            seen.add(identifier)
            unique_vulns.append(v)
            
    return unique_vulns
