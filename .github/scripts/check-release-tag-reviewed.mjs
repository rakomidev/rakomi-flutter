#!/usr/bin/env node
// Release-tag review check for the publish workflow.
//
// A release tag may publish ONLY when the commit it points at is the reviewed head of a pull request
// merged into the default branch — i.e. a non-first parent of a merge commit on the default branch's
// first-parent chain. That one condition implies both halves the release policy names:
//   (1) the commit is an ancestor of origin/<default branch>, and
//   (2) the public sha equals the sha that was reviewed: the pull request head that the merge recorded.
// A tag on an unmerged branch, a direct commit, an intermediate commit of a merged branch, or the merge
// commit itself all fail. Fail-closed throughout: missing input, a shallow clone, an unreadable ref ->
// exit 2 ("cannot evaluate"); a violation -> exit 1. Neither lets the job reach the publish step.
//
// Residual, stated with the claim: this proves the tag commit went through a MERGED pull request into the
// default branch; it does not prove what review that pull request received — that is the default
// branch's ruleset (required checks / approvals). It also protects only commits that carry it: a tag
// pushed on a branch commit runs THAT commit's publish.yml, so a commit whose publish.yml drops or
// weakens this step is not stopped by it. Against that, the controls are the tag-creation ruleset (only
// the release-push App may create a release tag) and the release environment's tag deployment policy.
//
// Source equality: the release-tag workflow creates a release tag only after re-deriving the release
// surface from the upstream source and finding it equal to the merged head, and records that tree in the
// annotated tag (Source-Tree). This check recomputes the surface tree of the tag commit and refuses a tag
// whose annotation does not name exactly that tree (a lightweight tag has no annotation and is refused).
import { execFileSync } from 'node:child_process'
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { parseTrailers, surfaceTree, TRAILER_SOURCE_TREE } from './lib/release-source-surface.mjs'

export class CannotEvaluateError extends Error {}

const FULL_SHA_RE = /^[0-9a-f]{40}$/

/**
 * Pure decision core.
 * @param {{tagRef:string, eventSha:string, tagCommitSha:string|null, defaultBranch:string,
 *          mainSha:string|null, isAncestor:boolean, shallow:boolean, mergedHeads:Set<string>,
 *          tagSourceTree:string|null, commitSourceTree:string|null}} f
 * @returns {{ok:boolean, violations:string[]}}
 */
export function evaluateReleaseTag(f) {
  const v = []
  if (typeof f.tagRef !== 'string' || !f.tagRef.startsWith('refs/tags/')) {
    v.push(`ref "${f.tagRef}" is not a tag ref (refs/tags/...)`)
  }
  if (typeof f.eventSha !== 'string' || !FULL_SHA_RE.test(f.eventSha)) {
    v.push('the event sha is not a full 40-hex commit sha')
  }
  if (typeof f.defaultBranch !== 'string' || f.defaultBranch === '') {
    v.push('the default branch name is missing')
  }
  if (f.shallow) {
    v.push('the checkout is shallow — the default branch history needed for this check is absent (use fetch-depth: 0)')
  }
  if (typeof f.mainSha !== 'string' || !FULL_SHA_RE.test(f.mainSha)) {
    v.push(`origin/${f.defaultBranch} could not be resolved to a commit`)
  }
  if (v.length) return { ok: false, violations: v }

  if (f.tagCommitSha !== f.eventSha) {
    v.push(`the event sha ${f.eventSha} differs from the commit the tag points at (${f.tagCommitSha})`)
  }
  if (!f.isAncestor) {
    v.push(`the tag commit ${f.eventSha} is not an ancestor of origin/${f.defaultBranch} — it never reached the default branch`)
  } else if (!(f.mergedHeads instanceof Set) || !f.mergedHeads.has(f.eventSha)) {
    v.push(`the tag commit ${f.eventSha} is on origin/${f.defaultBranch} but is not the reviewed head of a merged pull request (the public sha must equal the reviewed sha)`)
  }
  if (typeof f.tagSourceTree !== 'string' || !FULL_SHA_RE.test(f.tagSourceTree)) {
    v.push('the tag annotation names no Source-Tree (release tags are created by the release-tag workflow after the source-equality check)')
  } else if (f.tagSourceTree !== f.commitSourceTree) {
    v.push(`the release surface tree of the tag commit (${f.commitSourceTree}) differs from the verified Source-Tree in the tag annotation (${f.tagSourceTree})`)
  }
  return { ok: v.length === 0, violations: v }
}

/**
 * Non-first parents of every merge commit on the first-parent chain of `mainSha` — the heads that were
 * merged into the default branch. Input is `git rev-list --first-parent --parents <sha>` output.
 * @param {string} revListParents
 * @returns {Set<string>}
 */
export function mergedHeadsFromRevList(revListParents) {
  const heads = new Set()
  for (const line of revListParents.split('\n')) {
    const shas = line.trim().split(/\s+/).filter(Boolean)
    // shas[0] = commit, shas[1] = first parent, shas[2..] = merged heads
    for (const s of shas.slice(2)) if (FULL_SHA_RE.test(s)) heads.add(s)
  }
  return heads
}

function gatherFacts(env, git) {
  for (const k of ['TAG_REF', 'TAG_SHA', 'DEFAULT_BRANCH']) {
    if (typeof env[k] !== 'string' || env[k] === '') throw new CannotEvaluateError(`missing required environment variable ${k}`)
  }
  const tagRef = env.TAG_REF
  const eventSha = env.TAG_SHA.toLowerCase()
  const defaultBranch = env.DEFAULT_BRANCH
  const tryRev = (spec) => { try { return git(['rev-parse', '--verify', '--quiet', spec]) } catch { return null } }

  const shallow = git(['rev-parse', '--is-shallow-repository']) === 'true'
  const tagCommitSha = tagRef.startsWith('refs/tags/') ? tryRev(`${tagRef}^{commit}`) : null
  const mainSha = tryRev(`refs/remotes/origin/${defaultBranch}^{commit}`)
  let isAncestor = false
  let mergedHeads = new Set()
  if (!shallow && mainSha && FULL_SHA_RE.test(eventSha)) {
    try { git(['merge-base', '--is-ancestor', eventSha, mainSha]); isAncestor = true } catch { isAncestor = false }
    if (isAncestor) mergedHeads = mergedHeadsFromRevList(git(['rev-list', '--first-parent', '--parents', mainSha]))
  }
  let tagSourceTree = null
  let commitSourceTree = null
  if (tagRef.startsWith('refs/tags/') && tagCommitSha) {
    if (tryRev(`${tagRef}^{tag}`)) {
      const named = parseTrailers(git(['for-each-ref', '--format=%(contents)', tagRef]))[TRAILER_SOURCE_TREE]
      tagSourceTree = typeof named === 'string' ? named.toLowerCase() : null
    }
    commitSourceTree = surfaceTree('.', tagCommitSha)
  }
  return { tagRef, eventSha, tagCommitSha, defaultBranch, mainSha, isAncestor, shallow, mergedHeads, tagSourceTree, commitSourceTree }
}

function main() {
  const git = (args) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 }).trim()
  let facts
  try {
    facts = gatherFacts(process.env, git)
  } catch (e) {
    console.error(`release-tag-reviewed: CANNOT-EVALUATE — ${e.message}`)
    process.exit(2)
  }
  const { ok, violations } = evaluateReleaseTag(facts)
  if (ok) {
    console.error(`release-tag-reviewed: OK — ${facts.eventSha} is the reviewed head of a pull request merged into origin/${facts.defaultBranch}`)
    process.exit(0)
  }
  console.error('release-tag-reviewed: REFUSED — this tag will not publish:')
  for (const line of violations) console.error(`  - ${line}`)
  process.exit(facts.shallow || !facts.mainSha ? 2 : 1)
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
