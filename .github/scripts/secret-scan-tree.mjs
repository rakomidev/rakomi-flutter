#!/usr/bin/env node
// Secret scan of the committed tree of one commit, before anything is signed, published or pushed.
//
// The tree of <ref> (git archive, never the working tree) is extracted into a temporary directory. A tree
// that could switch the scanner off is refused before gitleaks runs: any `.gitleaksignore` file, and any
// file carrying the inline allow marker of gitleaks. gitleaks then scans the tree with <config> (the
// default rules plus the narrow allowlist in .github/gitleaks.toml), redacted, failing closed, with the
// inline marker ignored and an empty ignore-file path.
//
//   node .github/scripts/secret-scan-tree.mjs --ref <commit> [--repo <dir>] [--config <file>]
//     --repo    the git repository (default: the current directory)
//     --config  the gitleaks config (default: <repo>/.github/gitleaks.toml)
//
// The log names refused paths only, never file content. Exit: 0 = clean; 1 = refused or a finding;
// 2 = cannot evaluate. Node built-ins and the gitleaks binary only.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Built from parts so this file does not carry the marker it refuses. */
export const ALLOW_MARKER = ['gitleaks', 'allow'].join(':')
export const IGNORE_FILE = '.gitleaksignore'

class ScanError extends Error {
  constructor(message, exitCode) {
    super(message)
    this.exitCode = exitCode
  }
}

/** Repo-relative POSIX paths of every file under root (symlinks are listed, never followed). */
function listFiles(root) {
  const out = []
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const abs = join(d, e.name)
      if (e.isDirectory()) walk(abs)
      else out.push({ abs, rel: relative(root, abs).split(sep).join('/'), file: e.isFile() })
    }
  }
  walk(root)
  return out.sort((a, b) => (a.rel < b.rel ? -1 : 1))
}

/**
 * Files that would switch the scanner off.
 * @param {string} root extracted tree
 * @returns {string[]} violations, by path only
 */
export function suppressionViolations(root) {
  const v = []
  const marker = Buffer.from(ALLOW_MARKER)
  for (const f of listFiles(root)) {
    if (f.rel.split('/').pop() === IGNORE_FILE) v.push(`${IGNORE_FILE} in the tree: ${f.rel}`)
    else if (f.file && readFileSync(f.abs).includes(marker)) v.push(`inline ${ALLOW_MARKER} marker: ${f.rel}`)
  }
  return v
}

/** Extract the committed tree of `ref` into a new temporary directory. */
export function extractTree(repo, ref) {
  if (!/^[0-9a-f]{40}$|^HEAD$/.test(String(ref))) throw new ScanError('--ref must be a 40-hex commit sha or HEAD', 2)
  const dir = mkdtempSync(join(tmpdir(), 'secret-scan-'))
  const archive = spawnSync('git', ['-C', repo, 'archive', '--format=tar', ref], { maxBuffer: 1024 * 1024 * 1024 })
  if (archive.status !== 0) { rmSync(dir, { recursive: true, force: true }); throw new ScanError(`git archive of ${ref} failed`, 2) }
  const tar = spawnSync('tar', ['-x', '-C', dir], { input: archive.stdout, stdio: ['pipe', 'ignore', 'pipe'] })
  if (tar.status !== 0) { rmSync(dir, { recursive: true, force: true }); throw new ScanError('extracting the tree failed', 2) }
  return dir
}

/**
 * Scan the committed tree of `ref`.
 * @returns {{ violations: string[], gitleaks: number|null }} gitleaks = its exit status, null = not run
 */
export function scanTree({ repo, ref, config, gitleaks = 'gitleaks', log = (s) => console.error(s) }) {
  const dir = extractTree(repo, ref)
  const noIgnore = mkdtempSync(join(tmpdir(), 'secret-scan-noignore-'))
  try {
    const violations = suppressionViolations(dir)
    if (violations.length) return { violations, gitleaks: null }
    const r = spawnSync(gitleaks, ['dir', '--config', config, '--redact', '--no-banner', '--exit-code', '1', '--ignore-gitleaks-allow', '--gitleaks-ignore-path', noIgnore, dir], { cwd: noIgnore, encoding: 'utf8', stdio: ['ignore', 'inherit', 'inherit'] })
    if (r.error) throw new ScanError('gitleaks is not on PATH', 2)
    log(`secret-scan-tree: gitleaks exit ${r.status}`)
    return { violations: [], gitleaks: r.status }
  } finally {
    rmSync(dir, { recursive: true, force: true })
    rmSync(noIgnore, { recursive: true, force: true })
  }
}

function arg(argv, name) {
  const i = argv.indexOf(name)
  return i === -1 ? undefined : argv[i + 1]
}

function main() {
  const argv = process.argv.slice(2)
  try {
    const repo = resolve(arg(argv, '--repo') ?? '.')
    const ref = arg(argv, '--ref')
    const config = resolve(arg(argv, '--config') ?? join(repo, '.github/gitleaks.toml'))
    if (!ref) throw new ScanError('usage: secret-scan-tree.mjs --ref <commit> [--repo <dir>] [--config <file>]', 2)
    const { violations, gitleaks } = scanTree({ repo, ref, config })
    for (const line of violations) console.error(`  - ${line}`)
    if (violations.length) throw new ScanError('the tree carries a scanner suppression; refused before scanning', 1)
    if (gitleaks !== 0) throw new ScanError(gitleaks === 1 ? 'gitleaks reported a finding' : `gitleaks could not scan (exit ${gitleaks})`, gitleaks === 1 ? 1 : 2)
    console.error('secret-scan-tree: clean')
  } catch (e) {
    console.error(`secret-scan-tree: ${e.message}`)
    process.exitCode = e instanceof ScanError ? e.exitCode : 2
  }
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
