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
            # 1. & 6. & 8. Call Expressions (Buffer Overflow, Format String, Command Injection, etc.)
            if cursor.kind == clang.cindex.CursorKind.CALL_EXPR:
                func_name = cursor.spelling
                args_list = list(cursor.get_arguments())

                # === Buffer Overflow (CWE-120) ===
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

                # === Potential Buffer Overflow in scanf (CWE-120) ===
                if func_name == 'scanf':
                    vulns.append({
                        'name': 'Potential Buffer Overflow in scanf',
                        'cwe': 'CWE-120',
                        'severity': 'Medium',
                        'line': line,
                        'snippet': snippet,
                        'explanation': "Unsafe function 'scanf' can lead to buffer overflows if input is not bounded.",
                        'mitigation': 'Use fgets() or scanf with width specifiers (e.g., scanf("%99s", buf)).',
                        'secure_code': 'char buf[100];\nscanf("%99s", buf);'
                    })

                # === Command Injection (CWE-78) ===
                if func_name in ['system', 'popen']:
                    if args_list and args_list[0] is not None and args_list[0].kind != clang.cindex.CursorKind.STRING_LITERAL:
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

                # === Format String (CWE-134) ===
                if func_name in ['printf', 'fprintf', 'sprintf', 'snprintf']:
                    if func_name == 'printf' and len(args_list) == 1 and args_list[0] is not None:
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

                # === Path Traversal (CWE-22) ===
                if func_name in ['fopen', 'open', 'fread', 'fwrite', 'remove', 'rename', 'freopen']:
                    if args_list and args_list[0] is not None and args_list[0].kind != clang.cindex.CursorKind.STRING_LITERAL:
                        vulns.append({
                            'name': 'Path Traversal',
                            'cwe': 'CWE-22',
                            'severity': 'High',
                            'line': line,
                            'snippet': snippet,
                            'explanation': f"File function '{func_name}' called with a non-literal path. Can lead to path traversal attacks.",
                            'mitigation': 'Use a whitelist of allowed paths, canonicalize paths, and validate user input.',
                            'secure_code': '// Validate and canonicalize path before use\nchar safe_path[256];\nsnprintf(safe_path, sizeof(safe_path), "/allowed/dir/%s", sanitized_input);'
                        })

                # === Insecure Temporary File (CWE-377) ===
                if func_name in ['tmpnam', 'tempnam', 'mktemp', 'tmpfile']:
                    vulns.append({
                        'name': 'Insecure Temporary File',
                        'cwe': 'CWE-377',
                        'severity': 'Medium',
                        'line': line,
                        'snippet': snippet,
                        'explanation': f"Function '{func_name}' creates temporary files insecurely (race condition, predictable name).",
                        'mitigation': 'Use mkstemp() instead.',
                        'secure_code': 'char template[] = "/tmp/mytemp-XXXXXX";\nint fd = mkstemp(template);'
                    })

                # === Weak Random Number Generation (CWE-338) ===
                if func_name == 'rand':
                    vulns.append({
                        'name': 'Weak Random Number Generator',
                        'cwe': 'CWE-338',
                        'severity': 'Medium',
                        'line': line,
                        'snippet': snippet,
                        'explanation': f"The function '{func_name}' is not cryptographically secure.",
                        'mitigation': 'Use secure random number generators (e.g., /dev/urandom, arc4random_buf, or equivalent).',
                        'secure_code': '// Secure example (Linux/Unix):\n// Use getrandom(2) or read from /dev/urandom'
                    })

                # === Insufficiently Random Values (CWE-330) - srand with constant seed ===
                if func_name == 'srand':
                    if args_list and args_list[0] is not None and args_list[0].kind == clang.cindex.CursorKind.INTEGER_LITERAL:
                        vulns.append({
                            'name': 'Insufficiently Random Values',
                            'cwe': 'CWE-330',
                            'severity': 'Medium',
                            'line': line,
                            'snippet': snippet,
                            'explanation': "srand() called with a constant seed, making random numbers predictable.",
                            'mitigation': 'Use a truly random seed like time() combined with pid, or use secure random API.',
                            'secure_code': 'srand(time(NULL) ^ getpid());'
                        })

                # === Potentially Dangerous Function (CWE-676) ===
                if func_name in ['strtok', 'gets', 'bcopy', 'bzero']:
                    vulns.append({
                        'name': 'Potentially Dangerous Function',
                        'cwe': 'CWE-676',
                        'severity': 'Medium',
                        'line': line,
                        'snippet': snippet,
                        'explanation': f"Function '{func_name}' is potentially dangerous. strtok is not thread-safe, gets is inherently unsafe.",
                        'mitigation': 'Use strtok_r, strnlen, memcpy, memset instead.',
                        'secure_code': '// Use:\nchar* token = strtok_r(str, delim, &saveptr);'
                    })

                # === Dangerous Function: getlogin() (CWE-558) ===
                if func_name == 'getlogin':
                    vulns.append({
                        'name': 'Use of getlogin()',
                        'cwe': 'CWE-558',
                        'severity': 'Medium',
                        'line': line,
                        'snippet': snippet,
                        'explanation': "getlogin() returns an unreliable username. The user identity can be tampered with.",
                        'mitigation': 'Use getpwuid(getuid()) or rely on environment variables with validation.',
                        'secure_code': 'struct passwd *pw = getpwuid(getuid());\nif (pw) printf("%s", pw->pw_name);'
                    })

                # === Uncontrolled Memory Allocation (CWE-789) ===
                if func_name in ['malloc', 'calloc', 'realloc']:
                    if args_list and args_list[0] is not None and args_list[0].kind != clang.cindex.CursorKind.INTEGER_LITERAL:
                        if args_list[0].kind != clang.cindex.CursorKind.UNARY_OPERATOR and \
                           args_list[0].kind != clang.cindex.CursorKind.BINARY_OPERATOR:
                            # Size comes from a variable - potential uncontrolled allocation
                            vulns.append({
                                'name': 'Uncontrolled Memory Allocation',
                                'cwe': 'CWE-789',
                                'severity': 'Medium',
                                'line': line,
                                'snippet': snippet,
                                'explanation': f"Allocation size in '{func_name}' comes from a variable without validation. Could lead to resource exhaustion.",
                                'mitigation': 'Validate and cap allocation sizes. Use a maximum limit.',
                                'secure_code': 'if (size > MAX_ALLOC_SIZE) return NULL;\nptr = malloc(size);'
                            })

                # === sizeof on pointer type (CWE-467) ===
                if func_name in ['malloc', 'calloc']:
                    if args_list and len(args_list) >= 1 and args_list[0] is not None:
                        for child in args_list[0].walk_preorder():
                            if child.kind == clang.cindex.CursorKind.UNARY_OPERATOR:
                                c_tokens = list(child.get_tokens())
                                if c_tokens and c_tokens[0].spelling == '*':
                                    # sizeof(*ptr) -- correct
                                    pass
                            elif child.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                                var_type = child.type
                                if var_type.kind == clang.cindex.TypeKind.POINTER:
                                    vulns.append({
                                        'name': 'sizeof on Pointer Type',
                                        'cwe': 'CWE-467',
                                        'severity': 'Medium',
                                        'line': line,
                                        'snippet': snippet,
                                        'explanation': f"sizeof({child.spelling}) returns pointer size, not the allocated type size. Use sizeof(*{child.spelling}) instead.",
                                        'mitigation': 'Always dereference the pointer in sizeof: sizeof(*ptr) instead of sizeof(ptr).',
                                        'secure_code': 'int *arr = malloc(count * sizeof(*arr));'
                                    })
                                    break

                # === Unchecked Return Value (CWE-252) ===
                if func_name in ['malloc', 'calloc', 'realloc']:
                    # Check if the return value is used or cast in a BINARY_OPERATOR assignment
                    # We'll detect explicit discarding (call as statement)
                    vulns.append({
                        'name': 'Unchecked Return Value',
                        'cwe': 'CWE-252',
                        'severity': 'Medium',
                        'line': line,
                        'snippet': snippet,
                        'explanation': f"Return value of '{func_name}' should be checked for NULL to avoid undefined behavior.",
                        'mitigation': 'Always check if malloc/calloc/realloc returned NULL before using the pointer.',
                        'secure_code': 'int* ptr = malloc(sizeof(int) * n);\nif (!ptr) { /* handle error */ }'
                    })

                # 7. Memory Leak & UAF/Double Free Prep (Tracking Allocations)
                if func_name in ['malloc', 'calloc', 'realloc']:
                    pass  # Tracked in VAR_DECL handler below

                # 2. & 3. Free Tracking (Double Free, Prep for UAF)
                if func_name == 'free':
                    if args_list:
                        ptr_name = ""
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

            # 4. & 12. Null Pointer Dereference (CWE-476) after unchecked malloc
            if cursor.kind == clang.cindex.CursorKind.UNARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if tokens and tokens[0].spelling == '*':
                    # Check if parent is a DECL_STMT (dereference before any NULL check)
                    # Simplified: we flag if we see a dereference of a variable that was malloc'd
                    for child in cursor.walk_preorder():
                        if child.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                            ptr_name = child.spelling
                            if ptr_name in allocated_ptrs:
                                # Check if there's a NULL check between alloc and this dereference
                                # (omitted for simplicity - heuristic only)
                                pass

            # 9. Hardcoded Credentials & 10. Uninitialized Variables & Alloc Tracking (VAR_DECL)
            if cursor.kind == clang.cindex.CursorKind.VAR_DECL:
                var_name = cursor.spelling
                has_init = False
                is_malloc_result = False
                for child in cursor.get_children():
                    has_init = True
                    # Check if the init contains a malloc/calloc/realloc call
                    for sub in child.walk_preorder():
                        if sub.kind == clang.cindex.CursorKind.CALL_EXPR and sub.spelling in ['malloc', 'calloc', 'realloc']:
                            is_malloc_result = True
                            break
                    break
                
                if not has_init:
                    uninitialized_vars[var_name] = line
                else:
                    if var_name in uninitialized_vars:
                        del uninitialized_vars[var_name]
                    if is_malloc_result:
                        allocated_ptrs[var_name] = line
                        
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

            # 10. Use of Uninitialized Variable (CWE-457) (Reference before assignment)
            if cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                ref_name = cursor.spelling
                if ref_name in uninitialized_vars and line > uninitialized_vars[ref_name]:
                    # Check if this reference is on the RHS of an assignment (i.e., a read)
                    parent = cursor.semantic_parent
                    is_lhs = False
                    if parent is not None and parent.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
                        tokens = list(parent.get_tokens())
                        if '=' in [t.spelling for t in tokens]:
                            # Determine if this ref is the LHS of the assignment
                            lh_tokens = []
                            for child in parent.get_children():
                                if child.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                                    lh_tokens.append(child.spelling)
                            if ref_name in lh_tokens:
                                # Check if it's the first child (LHS)
                                first_child = list(parent.get_children())[0]
                                if first_child.kind == clang.cindex.CursorKind.DECL_REF_EXPR and first_child.spelling == ref_name:
                                    is_lhs = True
                    
                    if not is_lhs:
                        vulns.append({
                            'name': 'Use of Uninitialized Variable',
                            'cwe': 'CWE-457',
                            'severity': 'High',
                            'line': line,
                            'snippet': snippet,
                            'explanation': f"Variable '{ref_name}' is read before being initialized.",
                            'mitigation': 'Always initialize variables when declared, or ensure a code path assigns a value before reading.',
                            'secure_code': 'int* ptr = malloc(sizeof(int));\n*ptr = value;\nreturn ptr;'
                        })

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

            # 14. Divide By Zero (CWE-369) - detect division with variable denominator
            if cursor.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
                tokens = [t.spelling for t in cursor.get_tokens()]
                if '/' in tokens:
                    # The denominator is the second operand
                    children = list(cursor.get_children())
                    if len(children) >= 2:
                        denom = children[1]
                        if denom.kind != clang.cindex.CursorKind.INTEGER_LITERAL and \
                           denom.kind != clang.cindex.CursorKind.FLOATING_LITERAL:
                            vulns.append({
                                'name': 'Divide By Zero',
                                'cwe': 'CWE-369',
                                'severity': 'Medium',
                                'line': line,
                                'snippet': snippet,
                                'explanation': 'Division operation with a non-constant denominator. If the denominator is zero, this causes undefined behavior.',
                                'mitigation': 'Always check denominator is not zero before dividing.',
                                'secure_code': 'if (denominator != 0) {\n    result = numerator / denominator;\n} else {\n    // handle error\n}'
                            })

            # 15. Off-by-One Error (CWE-193) - array index with [constant] == size
            if cursor.kind == clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                tokens = [t.spelling for t in cursor.get_tokens()]
                for i, t in enumerate(tokens):
                    if t == '[' and i + 1 < len(tokens):
                        try:
                            idx = int(tokens[i + 1])
                            # Check for common pattern: buf[10] where buf was declared as buf[10]
                            # This is a simplified heuristic
                            if idx >= 10 and idx < 100:  # Typical small buffer sizes
                                vulns.append({
                                    'name': 'Array Index - Potential Out of Bounds',
                                    'cwe': 'CWE-193',
                                    'severity': 'Medium',
                                    'line': line,
                                    'snippet': snippet,
                                    'explanation': f'Array accessed with index {idx}. Verify this index is within the array bounds.',
                                    'mitigation': 'Use bounds checking and ensure index < array size.',
                                    'secure_code': 'if (index < sizeof(buf)/sizeof(buf[0])) {\n    buf[index] = value;\n}'
                                })
                                break
                        except ValueError:
                            pass

            # 16. Assignment in Condition (CWE-480) - detect = inside if/while
            if cursor.kind in [clang.cindex.CursorKind.IF_STMT, clang.cindex.CursorKind.WHILE_STMT]:
                children = list(cursor.get_children())
                if children:
                    cond = children[0]  # First child is the condition
                    for child in cond.walk_preorder():
                        if child.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
                            c_tokens = [t.spelling for t in child.get_tokens()]
                            if '=' in c_tokens and '==' not in c_tokens:
                                vulns.append({
                                    'name': 'Assignment in Condition',
                                    'cwe': 'CWE-480',
                                    'severity': 'High',
                                    'line': line,
                                    'snippet': snippet,
                                    'explanation': 'Assignment operator (=) used inside condition expression. Did you mean ==?',
                                    'mitigation': 'Use == for comparison. If assignment is intended, add explicit parentheses and a comment.',
                                    'secure_code': 'if (x == 5) { ... }  // comparison\n// OR if ((x = get_value()) != 0) { ... }  // intentional assignment'
                                })
                                break

            # 17. Missing Default Case in Switch (CWE-478)
            if cursor.kind == clang.cindex.CursorKind.SWITCH_STMT:
                has_default = False
                for child in cursor.walk_preorder():
                    if child.kind == clang.cindex.CursorKind.DEFAULT_STMT:
                        has_default = True
                        break
                if not has_default:
                    vulns.append({
                        'name': 'Missing Default Case in Switch',
                        'cwe': 'CWE-478',
                        'severity': 'Medium',
                        'line': line,
                        'snippet': snippet,
                        'explanation': 'Switch statement has no default case. Unexpected input could fall through unhandled.',
                        'mitigation': 'Always include a default case to handle unexpected values.',
                        'secure_code': 'switch (val) {\n    case 1: /* ... */ break;\n    default: /* handle unexpected */ break;\n}'
                    })

            # 18. Omitted Break in Switch Case (CWE-484) - fall-through
            if cursor.kind == clang.cindex.CursorKind.CASE_STMT:
                children = list(cursor.get_children())
                has_break = False
                for child in children:
                    # Check if this case body (COMPOUND_STMT or any stmt) contains a break
                    for sub in child.walk_preorder():
                        if sub.kind == clang.cindex.CursorKind.BREAK_STMT:
                            has_break = True
                            break
                    if has_break:
                        break

                if not has_break:
                    parent = cursor.semantic_parent
                    if parent is not None:
                        sib_children = list(parent.get_children())
                        is_last = (cursor == sib_children[-1])
                        if not is_last:
                            vulns.append({
                                'name': 'Omitted Break in Switch Case',
                                'cwe': 'CWE-484',
                                'severity': 'Medium',
                                'line': line,
                                'snippet': snippet,
                                'explanation': 'Case block does not end with a break statement, causing fall-through to next case.',
                                'mitigation': 'Always add a break statement at the end of each case block.',
                                'secure_code': 'case 1:\n    do_something();\n    break;\ncase 2:'
                            })

            # 19. Assignment of Fixed Address to Pointer (CWE-587) - also in VAR_DECL initializers
            if cursor.kind == clang.cindex.CursorKind.VAR_DECL:
                for child in cursor.get_children():
                    for sub in child.walk_preorder():
                        if sub.kind == clang.cindex.CursorKind.INTEGER_LITERAL:
                            try:
                                val = int(sub.spelling, 0)
                                if val > 0xFFF:
                                    vulns.append({
                                        'name': 'Fixed Address Assignment to Pointer',
                                        'cwe': 'CWE-587',
                                        'severity': 'Medium',
                                        'line': line,
                                        'snippet': snippet,
                                        'explanation': f'Pointer assigned a hardcoded memory address ({sub.spelling}). This is not portable and often indicates a bug.',
                                        'mitigation': 'Do not assign fixed addresses to pointers. Use dynamic memory allocation or defined constants.',
                                        'secure_code': 'int *ptr = malloc(sizeof(int));\n// OR\nextern int* get_mmio_base(void);'
                                    })
                                    break
                            except ValueError:
                                pass

            if cursor.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
                c_tokens = [t.spelling for t in cursor.get_tokens()]
                if '=' in c_tokens:
                    for rhs in cursor.walk_preorder():
                        if rhs.kind == clang.cindex.CursorKind.INTEGER_LITERAL:
                            try:
                                val = int(rhs.spelling, 0)
                                if val > 0xFFF:  # Reasonable memory address threshold
                                    vulns.append({
                                        'name': 'Fixed Address Assignment to Pointer',
                                        'cwe': 'CWE-587',
                                        'severity': 'Medium',
                                        'line': line,
                                        'snippet': snippet,
                                        'explanation': f'Pointer assigned a hardcoded memory address ({rhs.spelling}). This is not portable and often indicates a bug.',
                                        'mitigation': 'Do not assign fixed addresses to pointers. Use dynamic memory allocation or defined constants.',
                                        'secure_code': 'int *ptr = malloc(sizeof(int));\n// OR\nextern int* get_mmio_base(void);'
                                    })
                                    break
                            except ValueError:
                                pass

        for child in cursor.get_children():
            traverse(child, source_code_lines)
            
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        source_lines = f.readlines()
        
    traverse(tu.cursor, source_lines)
    
    # Memory Leak (CWE-401) check: pointers allocated but never freed
    for ptr_name, alloc_line in allocated_ptrs.items():
        if ptr_name not in freed_ptrs:
            vulns.append({
                'name': 'Memory Leak',
                'cwe': 'CWE-401',
                'severity': 'Medium',
                'line': alloc_line,
                'snippet': get_source_snippet(alloc_line, source_lines),
                'explanation': f"Pointer '{ptr_name}' was allocated but never freed.",
                'mitigation': 'Free dynamically allocated memory when it is no longer needed.',
                'secure_code': f'// Ensure every malloc has a matching free\n{ptr_name} = malloc(size);\n// ... use ...\nfree({ptr_name});'
            })

    # Remove duplicates
    seen = set()
    unique_vulns = []
    for v in vulns:
        identifier = (v['line'], v['name'])
        if identifier not in seen:
            seen.add(identifier)
            unique_vulns.append(v)
            
    return unique_vulns
