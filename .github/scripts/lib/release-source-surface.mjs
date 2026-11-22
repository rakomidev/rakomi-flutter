// The source surface of a native SDK release commit: the one definition the release producer and the
// release verifier share.
//
// The repository holds one exported package. Everything outside `.github/` is the export of the package
// at the source revision: a release commit replaces it wholesale. `.github/` is the reviewed workflow
// template and never changes in a release commit. Paths listed as `releaseTimeFiles` in
// `.github/release-surface.json` are produced when the release is built (not re-derivable from the
// source revision alone) and are left out of the comparison.
//
// The surface tree of a commit is a git tree object holding exactly the compared entries. Two commits
// with equal surface trees carry byte-identical package source.
//
// The per-repository facts (package, tag format, version file, exporter) live in
// `.github/release-surface.json`, read once when this module loads. A missing or malformed file throws
// at import, so every script that depends on it fails closed.
//
// Node built-ins only: this file runs in the public repository's workflows with no install step.
import { execFileSync } from 'node:child_process'
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export class ReleaseSurfaceError extends Error {}

const FULL_SHA_RE = /^[0-9a-f]{40}$/
/** A release version: SemVer core with an optional pre-release, no build metadata. */
export const VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/
const SURFACE_NAME_RE = /^[a-z][a-z-]*$/
const VERSION_KINDS = Object.freeze(['cyclonedx', 'pubspec'])

/** The directory a release commit never touches. */
export const TEMPLATE_DIR = '.github'

/**
 * Validate a release-surface declaration.
 * @param {any} c
 * @returns {Readonly<{surface:string, repository:string, package:string, tagFormat:string,
 *   versionFile:string, versionKind:string, sbom:string, releaseTimeFiles:readonly string[], exporter:string}>}
 */
export function parseSurfaceConfig(c) {
  const bad = (m) => { throw new ReleaseSurfaceError(`release-surface.json: ${m}`) }
  if (!c || typeof c !== 'object') bad('not an object')
  if (typeof c.surface !== 'string' || !SURFACE_NAME_RE.test(c.surface)) bad('surface must match ^[a-z][a-z-]*$')
  if (typeof c.repository !== 'string' || !/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(c.repository)) bad('repository must be owner/name')
  if (typeof c.package !== 'string' || c.package === '') bad('package is empty')
  if (typeof c.tagFormat !== 'string' || c.tagFormat.split('{{version}}').length !== 2 || /[\s/]/.test(c.tagFormat)) {
    bad('tagFormat must contain {{version}} exactly once and no space or slash')
  }
  const v = c.version
  if (!v || typeof v.file !== 'string' || v.file === '' || !VERSION_KINDS.includes(v.kind)) bad(`version must be {file, kind: ${VERSION_KINDS.join('|')}}`)
  if (typeof c.sbom !== 'string' || c.sbom === '') bad('sbom is empty')
  if (!Array.isArray(c.releaseTimeFiles) || c.releaseTimeFiles.some((p) => typeof p !== 'string' || p === '' || p.startsWith(`${TEMPLATE_DIR}/`))) {
    bad('releaseTimeFiles must be repository paths outside .github/')
  }
  if (typeof c.exporter !== 'string' || !/^scripts\/[A-Za-z0-9._/-]+\.mjs$/.test(c.exporter) || c.exporter.includes('..')) bad('exporter must be a scripts/*.mjs path')
  return Object.freeze({
    surface: c.surface,
    repository: c.repository,
    package: c.package,
    tagFormat: c.tagFormat,
    versionFile: v.file,
    versionKind: v.kind,
    sbom: c.sbom,
    releaseTimeFiles: Object.freeze([...c.releaseTimeFiles]),
    exporter: c.exporter,
  })
}

/** @param {string|URL} file */
export function loadSurfaceConfig(file = new URL('../../release-surface.json', import.meta.url)) {
  let raw
  try { raw = JSON.parse(readFileSync(file, 'utf8')) } catch (e) { throw new ReleaseSurfaceError(`release-surface.json unreadable: ${e.message}`) }
  return parseSurfaceConfig(raw)
}

/** This repository's release surface. */
export const SURFACE = loadSurfaceConfig()

/** @param {string} p repo-relative POSIX path */
export function isSurfacePath(p) {
  return typeof p === 'string' && p !== '' && p !== TEMPLATE_DIR && !p.startsWith(`${TEMPLATE_DIR}/`)
}

/** @param {string} p repo-relative POSIX path */
export function isReleaseTimePath(p, surface = SURFACE) {
  return surface.releaseTimeFiles.includes(p)
}

/** A path that the surface tree compares. */
export function isComparedPath(p, surface = SURFACE) {
  return isSurfacePath(p) && !isReleaseTimePath(p, surface)
}

/** The release tag of a version (`0.2.0` -> `0.2.0` or `v0.2.0`, by the tag format). */
export function tagForVersion(version, surface = SURFACE) {
  if (!VERSION_RE.test(String(version))) throw new ReleaseSurfaceError(`not a release version: ${JSON.stringify(version)}`)
  return surface.tagFormat.replace('{{version}}', version)
}

/** The version a release tag names, or null when the tag does not have this repository's tag format. */
export function versionFromTag(tag, surface = SURFACE) {
  const [pre, post] = surface.tagFormat.split('{{version}}')
  if (typeof tag !== 'string' || !tag.startsWith(pre) || !tag.endsWith(post) || tag.length <= pre.length + post.length) return null
  const v = tag.slice(pre.length, tag.length - post.length)
  return VERSION_RE.test(v) ? v : null
}

/**
 * The package version declared by the text of the version file.
 * @param {string} text
 * @returns {string|null}
 */
export function readDeclaredVersion(text, surface = SURFACE) {
  if (typeof text !== 'string') return null
  if (surface.versionKind === 'cyclonedx') {
    try {
      const v = JSON.parse(text)?.metadata?.component?.version
      return typeof v === 'string' && VERSION_RE.test(v) ? v : null
    } catch { return null }
  }
  const m = /^version:[ \t]*["']?([0-9A-Za-z.+-]+)["']?[ \t]*(?:#.*)?$/m.exec(text)
  return m && VERSION_RE.test(m[1]) ? m[1] : null
}

/**
 * Shape of the CycloneDX SBOM a release carries: a CycloneDX document with at least one component whose
 * metadata names this package at `version`.
 * @returns {string[]} violations
 */
export function sbomViolations(text, version, surface = SURFACE) {
  let s
  try { s = JSON.parse(text) } catch { return [`${surface.sbom} is not JSON`] }
  const v = []
  if (s?.bomFormat !== 'CycloneDX') v.push(`${surface.sbom} is not a CycloneDX document`)
  if (!Array.isArray(s?.components) || s.components.length === 0) v.push(`${surface.sbom} lists no components`)
  if (s?.metadata?.component?.version !== version) v.push(`${surface.sbom} names version ${s?.metadata?.component?.version}, not ${version}`)
  return v
}

const defaultGit = (repoDir, args, { env, input } = {}) =>
  execFileSync('git', ['-C', repoDir, ...args], {
    encoding: 'utf8',
    env: env ? { ...process.env, ...env } : process.env,
    input,
    stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
    maxBuffer: 512 * 1024 * 1024,
  })

/**
 * Parse `git ls-tree -r -z` output into entries.
 * @param {string} out
 * @returns {Array<{mode:string,type:string,oid:string,path:string}>}
 */
export function parseLsTree(out) {
  const entries = []
  for (const rec of out.split('\0')) {
    if (!rec) continue
    const tab = rec.indexOf('\t')
    const [mode, type, oid] = rec.slice(0, tab).split(' ')
    entries.push({ mode, type, oid, path: rec.slice(tab + 1) })
  }
  return entries
}

/**
 * The surface tree of `treeish` in `repoDir`: a git tree object holding only the compared paths.
 * Written into the repository's object store through a throwaway index, which is removed afterwards.
 * @param {string} repoDir
 * @param {string} treeish a commit or tree
 * @returns {string} tree oid
 */
export function surfaceTree(repoDir, treeish, { git = defaultGit, surface = SURFACE } = {}) {
  const entries = parseLsTree(git(repoDir, ['ls-tree', '-r', '-z', '--full-tree', treeish]))
  const kept = entries.filter((e) => isComparedPath(e.path, surface))
  const tmp = mkdtempSync(join(tmpdir(), 'surface-index-'))
  try {
    const env = { GIT_INDEX_FILE: join(tmp, 'index') }
    git(repoDir, ['read-tree', '--empty'], { env })
    if (kept.length) {
      const input = kept.map((e) => `${e.mode} ${e.oid}\t${e.path}\0`).join('')
      git(repoDir, ['update-index', '-z', '--index-info'], { env, input })
    }
    return git(repoDir, ['write-tree'], { env }).trim()
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
}

/**
 * Copy an exported package into a working copy the way a release does: every top-level entry except
 * `.git` and `.github` is removed, then the export is copied in. An export that carries `.git` or
 * `.github` is refused.
 * @param {string} stageDir
 * @param {string} workDir
 */
export function syncStageIntoWorkTree(stageDir, workDir) {
  const staged = readdirSync(stageDir)
  if (staged.length === 0) throw new ReleaseSurfaceError('the export is empty')
  if (staged.includes('.git') || staged.includes(TEMPLATE_DIR)) throw new ReleaseSurfaceError('the export carries .git or .github')
  for (const e of readdirSync(workDir)) {
    if (e === '.git' || e === TEMPLATE_DIR) continue
    rmSync(join(workDir, e), { recursive: true, force: true })
  }
  for (const e of staged) cpSync(join(stageDir, e), join(workDir, e), { recursive: true })
}

/**
 * Replay a release onto `baseRev` in a throwaway worktree of `repoDir` and return the resulting tree.
 * @param {{repoDir:string, baseRev:string, stageDir:string}} args
 * @returns {string} full tree oid
 */
export function replayStageOntoBase({ repoDir, baseRev, stageDir }, { git = defaultGit } = {}) {
  const parent = mkdtempSync(join(tmpdir(), 'surface-replay-'))
  const wt = join(parent, 'wt')
  try {
    git(repoDir, ['worktree', 'add', '-q', '--detach', wt, baseRev])
    syncStageIntoWorkTree(stageDir, wt)
    git(wt, ['add', '-A'])
    return git(wt, ['write-tree']).trim()
  } finally {
    try { git(repoDir, ['worktree', 'remove', '--force', wt]) } catch { /* removed below */ }
    rmSync(parent, { recursive: true, force: true })
    try { git(repoDir, ['worktree', 'prune']) } catch { /* nothing to prune */ }
  }
}

/** Trailer keys a release commit carries (last paragraph of its message). */
export const TRAILER_SOURCE_TREE = 'Source-Tree'
export const TRAILER_RELEASE_TAGS = 'Release-Tags'

/**
 * Trailers of a commit or tag message: `Key: value` lines of its last paragraph.
 * @param {string} message
 * @returns {Record<string,string>}
 */
export function parseTrailers(message) {
  const paragraphs = String(message).replace(/\r\n/g, '\n').trim().split(/\n{2,}/)
  const last = paragraphs[paragraphs.length - 1] || ''
  const out = {}
  for (const line of last.split('\n')) {
    const m = /^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*?)[ \t]*$/.exec(line)
    if (m && !(m[1] in out)) out[m[1]] = m[2]
  }
  return out
}

/**
 * The trailer block a release commit ends with. It names no upstream revision: the verifier finds the
 * revision through the upstream trigger tag `sdk-release-v<id>` with its read-only token.
 * @param {{sourceTree:string, tags:string[]}} args
 */
export function buildReleaseTrailers({ sourceTree, tags }) {
  if (!FULL_SHA_RE.test(sourceTree)) throw new ReleaseSurfaceError('buildReleaseTrailers: sourceTree is not a full 40-hex tree oid')
  if (!Array.isArray(tags) || tags.length === 0) throw new ReleaseSurfaceError('buildReleaseTrailers: no release tags')
  return [`${TRAILER_SOURCE_TREE}: ${sourceTree}`, `${TRAILER_RELEASE_TAGS}: ${tags.join(' ')}`].join('\n')
}

/**
 * Read and validate the release trailers of a message.
 * @param {string} message
 * @returns {{ok:true, sourceTree:string, tags:string[]}|{ok:false, reason:string}}
 */
export function readReleaseTrailers(message) {
  const t = parseTrailers(message)
  const sourceTree = (t[TRAILER_SOURCE_TREE] || '').toLowerCase()
  const tags = (t[TRAILER_RELEASE_TAGS] || '').split(/\s+/).filter(Boolean)
  if (!FULL_SHA_RE.test(sourceTree)) return { ok: false, reason: 'missing-source-tree' }
  if (tags.length === 0) return { ok: false, reason: 'missing-release-tags' }
  return { ok: true, sourceTree, tags }
}

/** The upstream trigger tag prefix; `release/<id>` here pairs with `sdk-release-v<id>` upstream. */
export const RELEASE_TRIGGER_TAG_PREFIX = 'sdk-release-v'
export const RELEASE_BRANCH_PREFIX = 'release/'
const RELEASE_ID_RE = /^(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\+([a-z][a-z-]*)$/

/**
 * The release id of a release branch (`release/0.3.0+swift` -> `0.3.0+swift`), or null when the branch is
 * not a well-formed release branch of THIS repository's surface. The id names the upstream trigger tag,
 * so its charset is closed.
 * @param {string} headRef
 */
export function releaseIdFromBranch(headRef, surface = SURFACE) {
  if (typeof headRef !== 'string' || !headRef.startsWith(RELEASE_BRANCH_PREFIX)) return null
  const id = headRef.slice(RELEASE_BRANCH_PREFIX.length)
  const m = RELEASE_ID_RE.exec(id)
  return m && m[2] === surface.surface ? id : null
}

/** The version part of a release id (`0.3.0+swift` -> `0.3.0`), or null. */
export function versionFromReleaseId(id, surface = SURFACE) {
  const m = RELEASE_ID_RE.exec(String(id))
  return m && m[2] === surface.surface ? m[1] : null
}

/**
 * Every 40-hex value in `text` that is one of `privateShas` (the object ids of the upstream repository).
 * The public commit message, the tag annotation and the verification log must return [].
 * @param {string} text
 * @param {Iterable<string>} privateShas
 */
export function privateShaLeaks(text, privateShas) {
  const known = new Set([...privateShas].map((s) => s.toLowerCase()))
  return [...new Set((String(text).toLowerCase().match(/[0-9a-f]{40}/g) || []).filter((s) => known.has(s)))]
}
