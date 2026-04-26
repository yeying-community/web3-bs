#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import path from 'node:path';

const DEFAULT_TEST_FILES = ['tests/central-ucan.test.mjs'];

function toPosix(value) {
  return value.split(path.sep).join('/');
}

function hasGlob(value) {
  return /[*?[\]{}]/.test(value);
}

function escapeRegexChar(value) {
  return /[|\\{}()[\]^$+?.]/.test(value) ? `\\${value}` : value;
}

function globToRegExp(pattern) {
  const normalized = toPosix(pattern);
  let output = '^';
  for (let i = 0; i < normalized.length; i += 1) {
    const current = normalized[i];
    if (current === '*') {
      const next = normalized[i + 1];
      if (next === '*') {
        const nextNext = normalized[i + 2];
        if (nextNext === '/') {
          output += '(?:.*/)?';
          i += 2;
        } else {
          output += '.*';
          i += 1;
        }
      } else {
        output += '[^/]*';
      }
      continue;
    }
    if (current === '?') {
      output += '[^/]';
      continue;
    }
    if (current === '[') {
      const endIndex = normalized.indexOf(']', i + 1);
      if (endIndex > i + 1) {
        output += normalized.slice(i, endIndex + 1);
        i = endIndex;
        continue;
      }
    }
    output += escapeRegexChar(current);
  }
  output += '$';
  return new RegExp(output);
}

function walkFiles(rootDir, output) {
  const entries = readdirSync(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(fullPath, output);
      continue;
    }
    const relativePath = toPosix(path.relative(process.cwd(), fullPath));
    output.push(relativePath);
  }
}

function findExistingBaseDir(pattern) {
  const normalized = toPosix(pattern);
  const firstGlobIndex = normalized.search(/[*?[\]{}]/);
  const prefix = firstGlobIndex === -1 ? normalized : normalized.slice(0, firstGlobIndex);
  let probe = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  if (!probe) return '.';
  while (!existsSync(probe)) {
    const parent = path.dirname(probe);
    if (parent === probe) return '.';
    probe = parent;
  }
  return probe;
}

function expandGlob(pattern) {
  const regex = globToRegExp(pattern);
  const baseDir = findExistingBaseDir(pattern);
  const candidates = [];
  walkFiles(baseDir, candidates);
  return candidates.filter(file => regex.test(file));
}

function collectNodeTestTargets(rawArgs) {
  const selected = [...DEFAULT_TEST_FILES];

  for (const rawArg of rawArgs) {
    const arg = String(rawArg || '').trim();
    if (!arg) continue;

    // Ignore legacy jest-style flags forwarded by CI release workflow.
    if (arg.startsWith('-')) {
      continue;
    }

    if (hasGlob(arg)) {
      const expanded = expandGlob(arg);
      if (expanded.length > 0) {
        selected.push(...expanded);
      }
      continue;
    }

    if (existsSync(arg)) {
      selected.push(toPosix(arg));
    }
  }

  return Array.from(new Set(selected));
}

const forwardedArgs = process.argv.slice(2);
const targets = collectNodeTestTargets(forwardedArgs);
const result = spawnSync(process.execPath, ['--test', ...targets], {
  stdio: 'inherit',
});

if (result.error) {
  throw result.error;
}
process.exit(result.status ?? 1);
