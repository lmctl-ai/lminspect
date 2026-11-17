#!/usr/bin/env node
// Maintainer-only compiler-library fixture export for Go tests.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const [input, ...scriptArgs] = args;
if (!input) {
  console.error('usage: compile-fixture.mjs <input.lms> [args...]');
  process.exit(2);
}
const source = path.resolve(input);

function resolveDistDir() {
  if (process.env.LMCODE_COMPILER_MODULE) {
    return path.dirname(path.resolve(process.env.LMCODE_COMPILER_MODULE));
  }
  let entry = process.env.LMSCRIPT_COMPILER_JS || process.env.LMSCRIPT_BIN || '';
  if (!entry) {
    const cmd = process.platform === 'win32' ? 'where' : 'which';
    entry = execFileSync(cmd, ['lmscript'], { encoding: 'utf8' }).trim().split(/\r?\n/)[0];
  }
  const realEntry = fs.realpathSync(entry);
  return path.resolve(path.dirname(realEntry), '../dist');
}

try {
  const distDir = resolveDistDir();
  const { CompiledDsl } = await import(pathToFileURL(path.join(distDir, 'dsl.js')).href);
  const { LMScript } = await import(pathToFileURL(path.join(distDir, 'lmscript.js')).href);
  const engine = new LMScript({ args: scriptArgs });
  engine.registerFunction(
    'savedsl',
    (p, out) => {
      const target = String(out ?? scriptArgs[0] ?? '');
      if (!target) throw new Error('savedsl requires an output file path');
      const resolved = path.resolve(target);
      fs.mkdirSync(path.dirname(resolved), { recursive: true });
      fs.writeFileSync(resolved, new Uint8Array(CompiledDsl.bytesOf(p)));
      return null;
    },
    { min: 1, max: 2 },
    { isDefault: true }
  );
  const raw = fs
    .readFileSync(source, 'utf8')
    .replace(/\b_dsl_\b/g, '_lmcode_')
    .replace(/\bend\s+_dsl_\b/g, 'end _lmcode_');
  const result = await engine.runAsync(raw, {
    file: source,
    platform: { cwd: path.dirname(source), env: process.env },
    hostContext: { cwd: path.dirname(source), env: process.env },
  });
  if (!result.success) {
    for (const d of result.diagnostics || []) {
      console.error(`${source}:${d.line}:${d.column}: ${d.message}`);
    }
    if (result.error) console.error(result.error);
    process.exit(result.exitCode ?? 2);
  }
} catch (e) {
  console.error(`${source}:1:1: ${e.message}`);
  process.exit(2);
}
