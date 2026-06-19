import argparse
import sys
import os

# Ensure backend module can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from backend.analyzer import analyze_file
except ImportError:
    print("Error: Could not import backend.analyzer. Ensure you are running from the repository root.")
    sys.exit(1)

def print_gcc_format(file_path, vulns):
    """Prints vulnerabilities in GCC format for IDE integration"""
    for v in vulns:
        # file:line: severity: message
        print(f"{file_path}:{v['line']}: {v['severity'].lower()}: [{v['cwe']}] {v['name']} - {v['explanation']}")

def print_table_format(file_path, vulns):
    print(f"--- Scan Results for {file_path} ---")
    print(f"{'Line':<6} | {'Severity':<8} | {'Vulnerability':<25} | {'CWE':<8}")
    print("-" * 55)
    for v in vulns:
        print(f"{v['line']:<6} | {v['severity']:<8} | {v['name']:<25} | {v['cwe']:<8}")

def main():
    parser = argparse.ArgumentParser(description="Sentinel SAST CLI")
    parser.add_argument('file', help="C/C++ file to scan")
    parser.add_argument('--format', choices=['gcc', 'table'], default='table', help="Output format")
    parser.add_argument('--fail-on', choices=['high', 'medium', 'low', 'none'], default='medium', help="Exit with code 1 if vulnerabilities of this severity or higher are found")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)

    try:
        vulns = analyze_file(args.file)
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        sys.exit(1)

    if args.format == 'gcc':
        print_gcc_format(args.file, vulns)
    else:
        print_table_format(args.file, vulns)

    # Check for policy violation
    has_violation = False
    fail_levels = {'high': ['High'], 'medium': ['High', 'Medium'], 'low': ['High', 'Medium', 'Low'], 'none': []}
    target_levels = fail_levels.get(args.fail_on, [])

    for v in vulns:
        if v['severity'] in target_levels:
            has_violation = True
            break

    if has_violation:
        if args.format != 'gcc':
            print(f"\n[!] Build failed: Found vulnerabilities violating the '--fail-on={args.fail_on}' policy.")
        sys.exit(1)
    
    if args.format != 'gcc':
        print("\n[+] Scan completed successfully. No critical violations.")
    sys.exit(0)

if __name__ == '__main__':
    main()
