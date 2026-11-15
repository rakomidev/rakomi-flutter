#!/usr/bin/env node
// Source-equality check for a merged release pull request of a native SDK repository.
//
// A release pull request is opened by an automated producer. Before any release tag is created this check
// re-derives the package export from the source revision (checked out by the workflow from the upstream
// trigger tag sdk-release-v<id>; the public commit names no upstream sha) and requires:
//   1. the merge changed nothing outside the release surface (everything but .github/);
//   2. the tree of the merge commit equals the tree of the pull request head (the whole tree);
//   3. the surface tree re-derived from the source revision, replayed onto the merge's first parent,
//      equals the surface tree of the pull request head;
//   4. the Source-Tree trailer names that same tree.
// The source revision itself (its checkout, its reachability from the source default branch) is checked
// by the workflow before this script runs.
//
// The workflow log is public and the source checkout is not, so this script prints only the two tree
// hashes, a closed reason code and OK/FAIL. The exporter runs with its output discarded, and every error
// is reduced to a reason code.
//
// Exit: 0 = OK; 1 = FAIL (a mismatch); 2 = cannot evaluate (missing input, exporter failure).
import { execFileSync, spawnSync } from 'node:child_process'
import { appendFileSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  isSurfacePath,
  parseTrailers,
  replayStageOntoBase,
  SURFACE,
  surfaceTree,
  TRAILER_SOURCE_TREE,
} from './lib/release-source-surface.mjs'

export const REASONS = Object.freeze({
  missingInput: 'missing-input',
  notAMerge: 'not-a-merge-of-the-head',
  trailers: 'release-trailers-missing',
  outsideSurface: 'change-outside-release-surface',
  mergeDiffers: 'merge-differs-from-head',
  deriveFailed: 'source-derivation-failed',
  treeMismatch: 'tree-mismatch',
  trailerMismatch: 'source-tree-trailer-mismatch',
  internal: 'internal-error',
})

const FULL_SHA_RE = /^[0-9a-f]{40}$/

/**
 * Pure verdict over the gathered facts.
 * @param {{headSha:string, mergeParents:string[], trailers:Record<string,string>,
 *          changedPaths:string[], mergeTree:string, headTree:string, headSurface:string,
 *          derivedSurface:string|null}} f
 * @returns {{ok:boolean, code:number, reason:string|null}}
 */
export function decide(f) {
  if (!f.mergeParents || f.mergeParents.length !== 2 || f.mergeParents[1] !== f.headSha) {
    return { ok: false, code: 1, reason: REASONS.notAMerge }
  }
  const claimedTree = (f.trailers[TRAILER_SOURCE_TREE] || '').toLowerCase()
  if (!FULL_SHA_RE.test(claimedTree)) return { ok: false, code: 1, reason: REASONS.trailers }
  if (f.changedPaths.some((p) => !isSurfacePath(p))) return { ok: false, code: 1, reason: REASONS.outsideSurface }
  if (!FULL_SHA_RE.test(f.mergeTree || '') || f.mergeTree !== f.headTree) return { ok: false, code: 1, reason: REASONS.mergeDiffers }
  if (!f.derivedSurface) return { ok: false, code: 2, reason: REASONS.deriveFailed }
  if (f.derivedSurface !== f.headSurface) return { ok: false, code: 1, reason: REASONS.treeMismatch }
  if (claimedTree !== f.headSurface) return { ok: false, code: 1, reason: REASONS.trailerMismatch }
  return { ok: true, code: 0, reason: null }
}

/** The one line this check prints. Only hashes and a closed reason code; the derived tree only on OK. */
export function renderLine({ derived, published, verdict }) {
  const d = verdict.ok && FULL_SHA_RE.test(derived || '') ? derived : 'none'
  const p = FULL_SHA_RE.test(published || '') ? published : 'none'
  return `source-equality derived=${d} published=${p} ${verdict.ok ? 'OK' : `FAIL ${verdict.reason}`}`
}

/** The message of the first commit on the first-parent chain of `rev` that carries a Source-Tree trailer. */
function releaseMessage(git, rev) {
  const out = git(['log', '--first-parent', '-n', '20', '--format=%B%x00', rev])
  for (const msg of out.split('\0')) {
    if (parseTrailers(msg)[TRAILER_SOURCE_TREE]) return msg
  }
  return ''
}

/** Environment names the upstream exporter never receives: tokens and the GitHub Actions file commands. */
export const UPSTREAM_ENV_DENY = /^(SOURCE_TOKEN|GH_TOKEN|GITHUB_TOKEN|ACTIONS_[A-Z_]+|GITHUB_(OUTPUT|ENV|PATH|STATE|STEP_SUMMARY))$/

/**
 * Export the package from the source checkout with the source revision's own exporter
 * (`node <exporter> --out <stageDir>`, the exporter named in release-surface.json). Its output is
 * discarded so nothing of the source tree reaches the log.
 */
export function deriveStage({ sourceRoot, stageDir, surface = SURFACE }) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !UPSTREAM_ENV_DENY.test(k)))
  const r = spawnSync(process.execPath, [join(sourceRoot, surface.exporter), '--out', stageDir], { cwd: sourceRoot, stdio: 'ignore', env })
  return r.status === 0
}

/**
 * Gather the facts and decide. All failures are reduced to a reason code.
 * @param {{publicRoot:string, sourceRoot:string, mergeSha:string, headSha:string, derive?:Function}} args
 */
export function verify({ publicRoot, sourceRoot, mergeSha, headSha, derive = deriveStage }) {
  const git = (args) => execFileSync('git', ['-C', publicRoot, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 512 * 1024 * 1024 }).trim()
  let derived = null
  let published = null
  const stageParent = mkdtempSync(join(tmpdir(), 'release-stage-'))
  try {
    const mergeParents = git(['rev-list', '--parents', '-n', '1', mergeSha]).split(/\s+/).slice(1)
    const trailers = parseTrailers(releaseMessage(git, headSha))
    const changedPaths = mergeParents.length === 2
      ? git(['diff', '--name-only', '-z', '--no-renames', mergeParents[0], mergeSha]).split('\0').filter(Boolean)
      : []
    const mergeTree = git(['rev-parse', `${mergeSha}^{tree}`])
    const headTree = git(['rev-parse', `${headSha}^{tree}`])
    published = surfaceTree(publicRoot, headSha)
    const stageDir = join(stageParent, 'stage')
    if (mergeParents.length === 2 && derive({ sourceRoot, stageDir })) {
      derived = surfaceTree(publicRoot, replayStageOntoBase({ repoDir: publicRoot, baseRev: mergeParents[0], stageDir }))
    }
    const verdict = decide({ headSha, mergeParents, trailers, changedPaths, mergeTree, headTree, headSurface: published, derivedSurface: derived })
    return { derived, published, verdict }
  } catch {
    return { derived, published, verdict: { ok: false, code: 2, reason: REASONS.internal } }
  } finally {
    rmSync(stageParent, { recursive: true, force: true })
  }
}

function main() {
  const { PUBLIC_ROOT, SOURCE_ROOT, MERGE_SHA, HEAD_SHA } = process.env
  const ok = [MERGE_SHA, HEAD_SHA].every((s) => FULL_SHA_RE.test(String(s || '').toLowerCase())) && PUBLIC_ROOT && SOURCE_ROOT
  if (!ok) {
    console.log(renderLine({ derived: null, published: null, verdict: { ok: false, reason: REASONS.missingInput } }))
    process.exit(2)
  }
  const r = verify({ publicRoot: PUBLIC_ROOT, sourceRoot: SOURCE_ROOT, mergeSha: MERGE_SHA.toLowerCase(), headSha: HEAD_SHA.toLowerCase() })
  console.log(renderLine(r))
  if (r.verdict.ok && process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `source_tree=${r.published}\n`)
  process.exit(r.verdict.code)
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
