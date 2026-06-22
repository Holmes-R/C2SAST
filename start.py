import subprocess
import sys
import os
import time

BASE = os.path.dirname(os.path.abspath(__file__))
PYTHON = os.path.join(BASE, 'venv', 'Scripts', 'python.exe')
if not os.path.exists(PYTHON):
    PYTHON = sys.executable

print("Starting Flask server on http://localhost:5000 ...")
proc = subprocess.Popen([PYTHON, os.path.join(BASE, 'backend', 'app.py')], cwd=BASE)
time.sleep(2)

print("\n" + "=" * 48)
print("  Vuln AI is running!")
print(f"  Open: http://localhost:5000")
print("  Press Ctrl+C to stop.")
print("=" * 48 + "\n")

try:
    proc.wait()
except KeyboardInterrupt:
    print("\nShutting down...")
    proc.terminate()
    proc.wait()
    print("Done.")
