#!/usr/bin/env python3
"""Check actual pinned lmmock importer without adding a production dependency."""
import json, os, pathlib, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parents[1]
source = pathlib.Path(os.environ['LMMOCK_SOURCE'])
pin = '17db1c3d708209354202c4e8b8e66e6e4b3b10c0'
original = subprocess.check_output(['git', '-C', str(source), 'show', pin + ':internal/scenario/scenario.go'])
with tempfile.TemporaryDirectory(prefix='lminspect-import-') as temp:
    work = pathlib.Path(temp)
    (work/'scenario').mkdir()
    (work/'scenario/scenario.go').write_bytes(original)
    (work/'go.mod').write_text('module capture-check\n\ngo 1.26\n\nrequire github.com/lmctl-ai/lminspect v0.0.0\nreplace github.com/lmctl-ai/lminspect => ' + json.dumps(str(root)) + '\n')
    (work/'integration_test.go').write_bytes((root/'scripts/import-check.go.txt').read_bytes())
    subprocess.run(['go', 'test', '-v', './...'], cwd=work, check=True)
