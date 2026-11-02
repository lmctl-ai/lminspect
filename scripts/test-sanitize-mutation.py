#!/usr/bin/env python3
"""Remove the one output policy boundary; synthetic regression tests must fail."""
import pathlib, subprocess
root = pathlib.Path(__file__).resolve().parents[1]
source = root / 'pkg/proxy/sanitize.go'
original = source.read_bytes()
needle = b'// Discover both directions first, then scrub echoes in either direction.'
assert original.count(needle) == 1
try:
    source.write_bytes(original.replace(needle, b'return f, extra\n' + needle))
    result = subprocess.run(['go', 'test', './...', '-run', 'TestCredential'], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # Keep complete synthetic diagnostic output, with no deadline or truncation.
    print(result.stdout.decode('utf-8', errors='replace'), end='')
    if result.returncode == 0 or b'credential survived output sanitization' not in result.stdout or b'lmcode print leaked credential' not in result.stdout:
        raise SystemExit('FAIL: removed output boundary was not caught by capture and print tests')
    print('CAUGHT removed SanitizeOutput boundary: capture and lmcode output suites turned red')
finally:
    source.write_bytes(original)
