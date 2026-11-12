#!/usr/bin/env node
// The version a release tag publishes, checked against the tag commit.
//
// Run after check-release-tag-reviewed.mjs, on the commit the tag points at. Requires:
//   - the tag name has this repository's tag format (release-surface.json `tagFormat`);
//   - the version file at the tag commit declares that same version;
//   - the SBOM at the tag commit is a CycloneDX document with components, naming that version.
// Writes `version=<version>` and `tag=<tag>` to GITHUB_OUTPUT.
// Exit: 0 = OK; 1 = refused; 2 = cannot evaluate.
import { execFileSync } from 'node:child_process'
import { appendFileSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { readDeclaredVersion, sbomViolations, SURFACE, versionFromTag } from './lib/release-source-surface.mjs'

/**
 * @param {{tagRef:string, versionText:string|null, sbomText:string|null}} f
 * @returns {{ok:boolean, tag:string|null, version:string|null, violations:string[]}}
 */
export function evaluateTagVersion({ tagRef, versionText, sbomText }, surface = SURFACE) {
  const tag = typeof tagRef === 'string' && tagRef.startsWith('refs/tags/') ? tagRef.slice('refs/tags/'.length) : null
  const version = tag ? versionFromTag(tag, surface) : null
  if (!version) return { ok: false, tag, version: null, violations: [`${tagRef} is not a release tag of this repository (format ${surface.tagFormat})`] }
  const v = []
  const declared = readDeclaredVersion(versionText, surface)
  if (declared !== version) v.push(`${surface.versionFile} at the tag commit declares ${declared ?? 'no version'}, not ${version}`)
  if (typeof sbomText !== 'string') v.push(`${surface.sbom} is missing at the tag commit`)
  else v.push(...sbomViolations(sbomText, version, surface))
  return { ok: v.length === 0, tag, version, violations: v }
}

function main() {
  const { TAG_REF, TAG_SHA, GITHUB_OUTPUT } = process.env
  if (!TAG_REF || !/^[0-9a-f]{40}$/.test(TAG_SHA || '')) {
    console.error('release-tag-version: CANNOT-EVALUATE — TAG_REF and a full 40-hex TAG_SHA are required')
    process.exit(2)
  }
  const show = (path) => {
    try { return execFileSync('git', ['show', `${TAG_SHA}:${path}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 }) } catch { return null }
  }
  const r = evaluateTagVersion({ tagRef: TAG_REF, versionText: show(SURFACE.versionFile), sbomText: show(SURFACE.sbom) })
  if (!r.ok) {
    console.error('release-tag-version: REFUSED')
    for (const line of r.violations) console.error(`  - ${line}`)
    process.exit(1)
  }
  if (GITHUB_OUTPUT) appendFileSync(GITHUB_OUTPUT, `version=${r.version}\ntag=${r.tag}\n`)
  console.error(`release-tag-version: OK — ${SURFACE.package} ${r.version}`)
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
