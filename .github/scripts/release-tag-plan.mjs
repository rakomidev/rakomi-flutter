#!/usr/bin/env node
// Plan the release tag for a verified release pull request head of a native SDK repository.
//
// The tag comes from the head's Release-Tags trailer and must hold up against the head itself:
//   - exactly one tag, in this repository's tag format (release-surface.json `tagFormat`);
//   - its version equals the version of the release id (release/<version>+<surface>);
//   - its version equals the version the head's version file declares;
//   - the tag does not exist yet;
//   - the version is above every existing release tag of this repository (no downgrade, no re-release).
import { execFileSync } from 'node:child_process'
import { appendFileSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import {
  parseTrailers,
  readDeclaredVersion,
  readReleaseTrailers,
  SURFACE,
  TRAILER_SOURCE_TREE,
  versionFromReleaseId,
  versionFromTag,
} from './lib/release-source-surface.mjs'

const SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/

/** semver precedence: <0, 0, >0. Returns null when either side is not a semver. */
export function compareSemver(a, b) {
  const x = SEMVER_RE.exec(a)
  const y = SEMVER_RE.exec(b)
  if (!x || !y) return null
  for (let i = 1; i <= 3; i++) {
    const d = Number(x[i]) - Number(y[i])
    if (d !== 0) return d
  }
  if (!x[4] && !y[4]) return 0
  if (!x[4]) return 1
  if (!y[4]) return -1
  const pa = x[4].split('.')
  const pb = y[4].split('.')
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (pa[i] === undefined) return -1
    if (pb[i] === undefined) return 1
    const na = /^\d+$/.test(pa[i])
    const nb = /^\d+$/.test(pb[i])
    if (na && nb && Number(pa[i]) !== Number(pb[i])) return Number(pa[i]) - Number(pb[i])
    if (na !== nb) return na ? -1 : 1
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1
  }
  return 0
}

/**
 * @param {{tags:string[], releaseId:string, versionAtHead:string|null, existingTags:string[]}} f
 * @returns {{ok:boolean, tag:string|null, version:string|null, violations:string[]}}
 */
export function planReleaseTag({ tags, releaseId, versionAtHead, existingTags }, surface = SURFACE) {
  const v = []
  if (!Array.isArray(tags) || tags.length !== 1) {
    v.push(`exactly one release tag is required (got ${Array.isArray(tags) ? tags.length : 'none'})`)
    return { ok: false, tag: null, version: null, violations: v }
  }
  const [tag] = tags
  const version = versionFromTag(tag, surface)
  if (!version) {
    v.push(`${tag} is not a release tag of this repository (format ${surface.tagFormat})`)
    return { ok: false, tag: null, version: null, violations: v }
  }
  const idVersion = versionFromReleaseId(releaseId, surface)
  if (idVersion !== version) v.push(`${tag} does not match the release id ${releaseId}`)
  if (versionAtHead !== version) v.push(`${tag} does not match ${surface.versionFile} at the head (${versionAtHead ?? 'absent'})`)
  const existing = new Set(existingTags)
  if (existing.has(tag)) v.push(`${tag} already exists`)
  for (const e of existing) {
    const ev = versionFromTag(e, surface)
    if (!ev) continue
    const c = compareSemver(version, ev)
    if (c !== null && c <= 0 && e !== tag) v.push(`${tag} is not above the existing ${e}`)
  }
  return { ok: v.length === 0, tag: v.length ? null : tag, version: v.length ? null : version, violations: v }
}

function main() {
  const { HEAD_SHA, SOURCE_TREE, RELEASE_ID, GITHUB_OUTPUT } = process.env
  const git = (args) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  if (!/^[0-9a-f]{40}$/.test(HEAD_SHA || '') || !/^[0-9a-f]{40}$/.test(SOURCE_TREE || '') || !RELEASE_ID) {
    console.error('release-tag-plan: CANNOT-EVALUATE — HEAD_SHA and SOURCE_TREE must be full 40-hex values and RELEASE_ID set')
    process.exit(2)
  }
  const messages = git(['log', '--first-parent', '-n', '20', '--format=%B%x00', HEAD_SHA]).split('\0')
  const message = messages.find((m) => parseTrailers(m)[TRAILER_SOURCE_TREE]) || ''
  const trailers = readReleaseTrailers(message)
  if (!trailers.ok) {
    console.error(`release-tag-plan: REFUSED — ${trailers.reason}`)
    process.exit(1)
  }
  if (trailers.sourceTree !== SOURCE_TREE) {
    console.error('release-tag-plan: REFUSED — the Source-Tree trailer differs from the verified tree')
    process.exit(1)
  }
  let versionAtHead
  try { versionAtHead = readDeclaredVersion(git(['show', `${HEAD_SHA}:${SURFACE.versionFile}`])) } catch { versionAtHead = null }
  const existingTags = git(['tag', '--list']).split('\n').filter(Boolean)
  const plan = planReleaseTag({ tags: trailers.tags, releaseId: RELEASE_ID, versionAtHead, existingTags })
  if (!plan.ok) {
    console.error('release-tag-plan: REFUSED')
    for (const line of plan.violations) console.error(`  - ${line}`)
    process.exit(1)
  }
  if (GITHUB_OUTPUT) appendFileSync(GITHUB_OUTPUT, `tags=${plan.tag}\nall_tags=${plan.tag}\nversion=${plan.version}\n`)
  console.error(`release-tag-plan: ${plan.tag}`)
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
