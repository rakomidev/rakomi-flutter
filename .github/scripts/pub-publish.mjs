#!/usr/bin/env node
// pub.dev publishing for this repository. The job that holds the OIDC id-token runs only Node and git: the
// Flutter toolchain and dependency resolution run in another job, which only checks the publish set. The
// publishing job packs the archive itself from the git objects of the tag commit; no file crosses jobs.
//
//   check-set               `dart pub publish --dry-run` must list exactly the files of the checked-out
//                           commit outside .github/ and REPOSITORY_ONLY (and nothing produced locally) —
//                           what pub.dev receives is the reviewed tree.
//   pack <archive>          write that set of HEAD as a .tar.gz built from the git blobs (never the working
//                           tree): regular files only, one entry per path. A symlink, a submodule or a
//                           duplicate path among the package files is refused.
//   verify-archive <archive> the archive holds exactly that set as regular-file entries, each path once,
//                           byte-identical to HEAD; any other entry type or a repeated path is refused.
//   upload <archive>        mint the GitHub Actions OIDC id-token for audience https://pub.dev, mask it and
//                           upload the archive with pub.dev's publishing API (versions/new, the signed
//                           upload form, finalize). The token goes only to https://pub.dev, never to argv,
//                           GITHUB_ENV or disk. Needs `permissions: id-token: write`.
//   read-back <pkg> <ver>   poll https://pub.dev/api/packages/<pkg>/versions/<ver> until pub.dev serves
//                           that version (at most ~10 minutes).
//
// Exit: 0 = OK; 1 = refused or failed; 2 = cannot evaluate.
import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { gunzipSync, gzipSync } from 'node:zlib'

export const PUB_DEV = 'https://pub.dev'
const PUB_API_ACCEPT = 'application/vnd.pub.v2+json'

export class PubError extends Error {
  constructor(message, exitCode) {
    super(message)
    this.exitCode = exitCode
  }
}

/**
 * The file list of the tree `dart pub publish --dry-run` prints after its `Publishing ... to ...:` header.
 * @param {string} out
 * @returns {string[]} package-relative POSIX paths
 */
export function parsePubTree(out) {
  const lines = String(out).split('\n')
  const header = lines.findIndex((l) => /^Publishing \S+ \S+ to https?:\/\//.test(l))
  if (header === -1) throw new PubError('the dry run printed no "Publishing ... to ...:" header', 2)
  const rows = []
  for (const raw of lines.slice(header + 1)) {
    const m = /^((?:[│ ] {3})*)(?:├── |└── )(.+)$/.exec(raw)
    if (!m) break
    const depth = m[1].length / 4
    if (!Number.isInteger(depth)) throw new PubError('unparseable publish-set tree indentation', 2)
    const sized = / \((?:<1|[\d.]+) ?[KMG]?B\)$/.test(m[2])
    rows.push({ depth, name: m[2].replace(/ \((?:<1|[\d.]+) ?[KMG]?B\)$/, '').trim(), sized })
  }
  const stack = []
  const files = []
  for (let i = 0; i < rows.length; i++) {
    const { depth, name, sized } = rows[i]
    if (depth > stack.length) throw new PubError('publish-set tree skips a level', 2)
    stack.length = depth
    const isDir = !sized && i + 1 < rows.length && rows[i + 1].depth === depth + 1
    if (isDir) stack.push(name)
    else files.push([...stack, name].join('/'))
  }
  if (files.length === 0) throw new PubError('the dry run listed no files', 2)
  return files
}

/**
 * Committed paths that stay in this repository and never reach pub.dev: the tests (this repository runs
 * `flutter test`), the `.pubignore` that keeps them out, and the release SBOM (signed and attached to the
 * GitHub Release instead). The `.pubignore` lists exactly the two directories/files besides itself.
 */
export const REPOSITORY_ONLY = Object.freeze(['test/', '.pubignore', 'sbom.cdx.json'])

/** @param {string} p repo-relative POSIX path */
export function isRepositoryOnly(p) {
  return REPOSITORY_ONLY.some((e) => (e.endsWith('/') ? p.startsWith(e) : p === e))
}

/**
 * The publish set must be exactly the committed files outside .github/ and REPOSITORY_ONLY.
 * @param {string[]} published
 * @param {string[]} committed `git ls-tree -r --name-only HEAD`
 * @returns {string[]} violations
 */
export function publishSetViolations(published, committed) {
  const want = new Set(committed.filter((p) => p !== '' && !p.startsWith('.github/') && !isRepositoryOnly(p)))
  const got = new Set(published)
  const v = []
  for (const p of got) if (!want.has(p)) v.push(`published but not committed: ${p}`)
  for (const p of want) if (!got.has(p)) v.push(`committed but not published: ${p}`)
  return v
}

/** The id-token request URL with the pub.dev audience. */
export function buildIdTokenUrl(requestUrl) {
  if (typeof requestUrl !== 'string' || requestUrl === '') throw new PubError('ACTIONS_ID_TOKEN_REQUEST_URL is not set — the job needs `permissions: id-token: write`', 2)
  const url = new URL(requestUrl)
  url.searchParams.set('audience', PUB_DEV)
  return url.toString()
}

export async function mintIdToken(env, { fetchFn = fetch } = {}) {
  const url = buildIdTokenUrl(env.ACTIONS_ID_TOKEN_REQUEST_URL)
  const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (typeof bearer !== 'string' || bearer === '') throw new PubError('ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set — the job needs `permissions: id-token: write`', 2)
  let res
  try { res = await fetchFn(url, { headers: { Authorization: `Bearer ${bearer}`, Accept: 'application/json' } }) } catch { throw new PubError('the id-token request failed', 2) }
  if (!res.ok) throw new PubError(`the id-token request returned HTTP ${res.status}`, 2)
  let body
  try { body = await res.json() } catch { throw new PubError('the id-token response is not JSON', 2) }
  const token = body?.value
  if (typeof token !== 'string' || token.split('.').length !== 3) throw new PubError('the id-token response carries no JWT', 2)
  return token
}

const gitOut = (args, opts = {}) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, ...opts })

/** Git modes a package file may have: a regular blob, executable or not. */
const FILE_MODES = Object.freeze({ '100644': 0o644, '100755': 0o755 })

/**
 * The package entries of a commit, from `git ls-tree -r -z --full-tree <rev>` output.
 * @param {string} lsTree NUL-separated `<mode> <type> <oid>\t<path>` records
 * @returns {{ entries: {path:string, mode:number, oid:string}[], violations: string[] }}
 */
export function packageEntries(lsTree) {
  const entries = []
  const violations = []
  const seen = new Set()
  for (const rec of String(lsTree).split('\0')) {
    if (rec === '') continue
    const m = /^(\d{6}) (\w+) ([0-9a-f]{40,64})\t(.+)$/s.exec(rec)
    if (!m) { violations.push('unparseable git ls-tree record'); continue }
    const [, mode, type, oid, path] = m
    if (path.startsWith('.github/') || isRepositoryOnly(path)) continue
    if (seen.has(path)) { violations.push(`duplicate tree entry: ${path}`); continue }
    seen.add(path)
    if (path.startsWith('/') || path.split('/').some((seg) => seg === '' || seg === '.' || seg === '..') || path.includes('\\')) violations.push(`unsafe path: ${path}`)
    else if (mode === '120000') violations.push(`symlink: ${path}`)
    else if (type !== 'blob' || !(mode in FILE_MODES)) violations.push(`not a regular file (mode ${mode}): ${path}`)
    else entries.push({ path, mode: FILE_MODES[mode], oid })
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  return { entries, violations }
}

const TAR_BLOCK = 512

function octal(buf, off, len, n) {
  const s = n.toString(8)
  if (s.length > len - 1) throw new PubError('tar field overflow', 2)
  buf.write(`${s.padStart(len - 1, '0')}\0`, off, len, 'ascii')
}

function splitTarPath(path) {
  const b = Buffer.byteLength(path)
  if (b <= 100) return { name: path, prefix: '' }
  for (let i = path.indexOf('/'); i !== -1; i = path.indexOf('/', i + 1)) {
    const prefix = path.slice(0, i)
    const name = path.slice(i + 1)
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100 && name !== '') return { name, prefix }
  }
  throw new PubError(`path too long for a ustar entry: ${path}`, 1)
}

/**
 * A gzipped ustar archive of the given entries, in order. `type` and `linkname` exist for the tests that
 * build refused archives; `pack` writes regular files ('0') only.
 * @param {{path:string, data:Buffer, mode?:number, mtime?:number, type?:string, linkname?:string}[]} entries
 */
export function buildTarGz(entries) {
  const parts = []
  for (const e of entries) {
    const h = Buffer.alloc(TAR_BLOCK)
    const { name, prefix } = splitTarPath(e.path)
    h.write(name, 0, 100, 'utf8')
    octal(h, 100, 8, e.mode ?? 0o644)
    octal(h, 108, 8, 0)
    octal(h, 116, 8, 0)
    octal(h, 124, 12, e.data.length)
    octal(h, 136, 12, e.mtime ?? 0)
    h.fill(0x20, 148, 156)
    h.write(e.type ?? '0', 156, 1, 'ascii')
    if (e.linkname) h.write(e.linkname, 157, 100, 'utf8')
    h.write('ustar\0', 257, 6, 'ascii')
    h.write('00', 263, 2, 'ascii')
    h.write(prefix, 345, 155, 'utf8')
    let sum = 0
    for (const byte of h) sum += byte
    h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii')
    parts.push(h, e.data, Buffer.alloc((TAR_BLOCK - (e.data.length % TAR_BLOCK)) % TAR_BLOCK))
  }
  parts.push(Buffer.alloc(TAR_BLOCK * 2))
  return gzipSync(Buffer.concat(parts), { level: 9 })
}

const cstr = (buf, off, len) => { const b = buf.subarray(off, off + len); const z = b.indexOf(0); return (z === -1 ? b : b.subarray(0, z)).toString('utf8') }

/**
 * Parse a gzipped tar. Every entry is returned with its type flag; the caller refuses what is not a
 * regular file. A bad checksum, a truncated entry or a missing end marker is a violation.
 * @returns {{ entries: {name:string, type:string, data:Buffer}[], violations: string[] }}
 */
export function readTarGz(gz) {
  let buf
  try { buf = gunzipSync(gz) } catch { return { entries: [], violations: ['not a gzip archive'] } }
  const entries = []
  const violations = []
  let off = 0
  for (;;) {
    if (off + TAR_BLOCK > buf.length) { violations.push('truncated archive (no end marker)'); break }
    const h = buf.subarray(off, off + TAR_BLOCK)
    if (h.every((b) => b === 0)) break
    let sum = 0
    for (let i = 0; i < TAR_BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i]
    const want = parseInt(cstr(h, 148, 8).trim(), 8)
    if (sum !== want) { violations.push(`bad header checksum at offset ${off}`); break }
    const size = parseInt(cstr(h, 124, 12).trim() || '0', 8)
    const prefix = cstr(h, 345, 155)
    const base = cstr(h, 0, 100)
    const name = prefix ? `${prefix}/${base}` : base
    const type = String.fromCharCode(h[156] || 0x30)
    const dataEnd = off + TAR_BLOCK + size
    if (!Number.isSafeInteger(size) || dataEnd > buf.length) { violations.push(`truncated entry: ${name}`); break }
    entries.push({ name, type, data: buf.subarray(off + TAR_BLOCK, dataEnd) })
    off = dataEnd + ((TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK)
  }
  return { entries, violations }
}

const lsTreeHead = () => gitOut(['ls-tree', '-r', '-z', '--full-tree', 'HEAD'])
const blobOf = (oid) => execFileSync('git', ['cat-file', 'blob', oid], { maxBuffer: 256 * 1024 * 1024 })

/** Write the package files of HEAD, read from the git objects, as a .tar.gz (paths relative to the package root). */
export function pack(archive, { lsTree = lsTreeHead(), blob = blobOf, mtime = Number(gitOut(['log', '-1', '--format=%ct', 'HEAD']).trim()) } = {}) {
  const { entries, violations } = packageEntries(lsTree)
  if (violations.length) {
    for (const line of violations) console.error(`  - ${line}`)
    throw new PubError('the commit carries package entries pub.dev must not receive', 1)
  }
  if (entries.length === 0) throw new PubError('the commit has no package files', 2)
  writeFileSync(archive, buildTarGz(entries.map((e) => ({ path: e.path, mode: e.mode, mtime, data: blob(e.oid) }))))
  return entries.length
}

/**
 * The archive must hold exactly the package files of HEAD, each once, as regular files with their
 * committed bytes.
 * @returns {string[]} violations
 */
export function archiveViolations(archive, { lsTree = lsTreeHead(), blob = blobOf, readArchive = (f) => readFileSync(f) } = {}) {
  const want = packageEntries(lsTree)
  const got = readTarGz(readArchive(archive))
  const v = [...want.violations, ...got.violations]
  const byPath = new Map(want.entries.map((e) => [e.path, e]))
  const seen = new Set()
  for (const e of got.entries) {
    if (e.type !== '0') { v.push(`not a regular file entry (type ${JSON.stringify(e.type)}): ${e.name}`); continue }
    if (seen.has(e.name)) { v.push(`duplicate entry: ${e.name}`); continue }
    seen.add(e.name)
    const w = byPath.get(e.name)
    if (!w) v.push(`in the archive but not a package file: ${e.name}`)
    else if (!e.data.equals(blob(w.oid))) v.push(`differs from the commit: ${e.name}`)
  }
  for (const p of byPath.keys()) if (!seen.has(p)) v.push(`package file missing from the archive: ${p}`)
  return v
}

/**
 * Upload an archive with pub.dev's publishing API, the protocol `dart pub publish` speaks:
 * GET /api/packages/versions/new (bearer) -> a signed upload form {url, fields}; POST the archive to that
 * form (no bearer: the form is the credential); its redirect names the finalize URL on pub.dev, read with
 * the bearer. The token never leaves https://pub.dev.
 */
export async function upload(archive, { env = process.env, fetchFn = fetch, write = (s) => process.stdout.write(s), readArchive = (f) => readFileSync(f) } = {}) {
  const token = await mintIdToken(env, { fetchFn })
  write(`::add-mask::${token}\n`)
  const auth = { Authorization: `Bearer ${token}`, Accept: PUB_API_ACCEPT }
  const json = async (res, what) => {
    let body = null
    try { body = await res.json() } catch { /* reported below */ }
    if (!res.ok || !body || body.error) throw new PubError(`${what} failed (HTTP ${res.status}${body?.error?.message ? `: ${body.error.message}` : ''})`, 1)
    return body
  }
  const form = await json(await fetchFn(`${PUB_DEV}/api/packages/versions/new`, { headers: auth, redirect: 'error' }), 'versions/new')
  if (typeof form.url !== 'string' || !form.url.startsWith('https://') || !form.fields || typeof form.fields !== 'object') throw new PubError('versions/new returned no upload form', 1)
  const body = new globalThis.FormData()
  for (const [k, v] of Object.entries(form.fields)) body.append(k, String(v))
  body.append('file', new globalThis.Blob([readArchive(archive)]), 'package.tar.gz')
  const posted = await fetchFn(form.url, { method: 'POST', body, redirect: 'manual' })
  const location = posted.headers.get('location')
  if (!location || !location.startsWith(`${PUB_DEV}/`)) throw new PubError(`the upload was refused (HTTP ${posted.status})`, 1)
  const done = await json(await fetchFn(location, { headers: auth, redirect: 'error' }), 'finalize')
  return done?.success?.message ?? 'uploaded'
}

/** Poll pub.dev until it serves `version` of `pkg`. */
export async function readBack(pkg, version, { fetchFn = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), tries = 30, delayMs = 20000 } = {}) {
  if (!/^[a-z][a-z0-9_]*$/.test(pkg || '') || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version || '')) throw new PubError('read-back needs a package name and a version', 2)
  const url = `${PUB_DEV}/api/packages/${pkg}/versions/${version}`
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetchFn(url, { headers: { Accept: 'application/json' }, redirect: 'error' })
      if (res.ok) {
        const body = await res.json()
        if (body?.version === version && body?.pubspec?.name === pkg && typeof body?.archive_sha256 === 'string') return body.archive_sha256
      }
    } catch { /* retried below */ }
    if (i + 1 < tries) await sleep(delayMs)
  }
  throw new PubError(`pub.dev does not serve ${pkg} ${version}`, 1)
}

function checkSet() {
  const r = spawnSync('dart', ['pub', 'publish', '--dry-run'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  if (r.error) throw new PubError('dart is not on PATH', 2)
  const published = parsePubTree(`${r.stdout}\n${r.stderr}`)
  const committed = execFileSync('git', ['ls-tree', '-r', '--name-only', '--full-tree', 'HEAD'], { encoding: 'utf8' }).split('\n')
  const v = publishSetViolations(published, committed)
  if (v.length) {
    for (const line of v) console.error(`  - ${line}`)
    throw new PubError('the publish set differs from the committed tree', 1)
  }
  if (r.status !== 0) throw new PubError(`dart pub publish --dry-run exited ${r.status}`, 1)
  console.error(`pub-publish: publish set = committed tree (${published.length} files)`)
}

async function main() {
  const [mode, ...rest] = process.argv.slice(2)
  try {
    if (mode === 'check-set') checkSet()
    else if (mode === 'pack' && rest[0]) console.error(`pub-publish: packed ${pack(rest[0])} files`)
    else if (mode === 'verify-archive' && rest[0]) {
      const v = archiveViolations(rest[0])
      for (const line of v) console.error(`  - ${line}`)
      if (v.length) throw new PubError('the archive is not the package files of this commit', 1)
      console.error('pub-publish: archive = package files of this commit')
    } else if (mode === 'upload' && rest[0]) console.error(`pub-publish: ${await upload(rest[0])}`)
    else if (mode === 'read-back') console.error(`pub-publish: pub.dev serves ${rest[0]} ${rest[1]} (archive sha256 ${await readBack(rest[0], rest[1])})`)
    else throw new PubError('usage: pub-publish.mjs check-set | pack <archive> | verify-archive <archive> | upload <archive> | read-back <package> <version>', 2)
  } catch (e) {
    console.error(`pub-publish: ${e.message}`)
    process.exitCode = e instanceof PubError ? e.exitCode : 1
  }
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
