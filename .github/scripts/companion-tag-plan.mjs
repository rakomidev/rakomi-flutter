#!/usr/bin/env node
// The release tags of the second package this repository publishes (pub.dev `rakomi`, kept under
// .github/packages/rakomi), planned on the verified head of a release pull request.
//
// release-tag.yml creates them next to the rakomi_flutter release tag, on the same reviewed head and with
// the same annotation (Source-Tree), so publish-rakomi.yml's check-release-tag-reviewed.mjs holds for them
// exactly as for the v<version> tag. A companion tag is planned when its package directory exists at the
// head, its pubspec.yaml declares a release version, and the tag does not exist yet; otherwise none is
// planned (an unchanged version is never re-tagged). The plan never refuses: a companion must not hold
// back the rakomi_flutter release.
//
// Writes `companion_tags=<space-separated tags>` to GITHUB_OUTPUT.
// Exit: 0 = planned (possibly none); 2 = cannot evaluate.
import { execFileSync } from 'node:child_process'
import { appendFileSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { VERSION_RE } from './lib/release-source-surface.mjs'

/** pub.dev automated publishing of each package is configured with exactly this tag pattern. */
export const COMPANIONS = Object.freeze([
  Object.freeze({ package: 'rakomi', dir: '.github/packages/rakomi', tagPrefix: 'rakomi-v' }),
])

/** @param {string|null} pubspec */
export function pubspecVersion(pubspec) {
  if (typeof pubspec !== 'string') return null
  const m = /^version:[ \t]*["']?([0-9A-Za-z.+-]+)["']?[ \t]*(?:#.*)?$/m.exec(pubspec)
  return m && VERSION_RE.test(m[1]) ? m[1] : null
}

/**
 * @param {{pubspecs: Record<string, string|null>, existingTags: string[]}} f pubspec.yaml text per package dir
 * @returns {string[]} the tags to create
 */
export function planCompanionTags({ pubspecs, existingTags }, companions = COMPANIONS) {
  const existing = new Set(existingTags)
  const tags = []
  for (const c of companions) {
    const version = pubspecVersion(pubspecs[c.dir] ?? null)
    if (!version) continue
    const tag = `${c.tagPrefix}${version}`
    if (!existing.has(tag)) tags.push(tag)
  }
  return tags
}

function main() {
  const { HEAD_SHA, GITHUB_OUTPUT } = process.env
  if (!/^[0-9a-f]{40}$/.test(HEAD_SHA || '')) {
    console.error('companion-tag-plan: CANNOT-EVALUATE — HEAD_SHA must be a full 40-hex sha')
    process.exit(2)
  }
  const git = (args) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
  const show = (p) => { try { return git(['show', `${HEAD_SHA}:${p}`]) } catch { return null } }
  const pubspecs = Object.fromEntries(COMPANIONS.map((c) => [c.dir, show(`${c.dir}/pubspec.yaml`)]))
  const existingTags = git(['tag', '--list']).split('\n').filter(Boolean)
  const tags = planCompanionTags({ pubspecs, existingTags })
  if (GITHUB_OUTPUT) appendFileSync(GITHUB_OUTPUT, `companion_tags=${tags.join(' ')}\n`)
  console.error(`companion-tag-plan: ${tags.length ? tags.join(' ') : 'none'}`)
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
