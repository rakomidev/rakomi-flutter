#!/usr/bin/env node
// Decide whether a push to the default branch is the merge of a release pull request.
//
// The release-tag workflow runs on every push to the default branch (a pull_request-triggered run cannot
// enter an environment restricted to the default branch, and it runs the pull request's own copy of the
// workflow). The pull request is found ONLY through the API, by the pushed sha
// (GET /repos/{owner}/{repo}/commits/{sha}/pulls), and:
//   - EXACTLY ONE of the returned pull requests must be merged with merge_commit_sha == the pushed sha;
//     none, or more than one, is refused (fail-closed: main only moves through merged pull requests);
//   - that pull request's head branch not starting with `release/` is a normal merge: release=false, exit 0;
//   - a `release/` pull request is a release only when ALL hold: same repository (no fork), merged into the
//     default branch, author on the allow-list, a well-formed release id, and the pushed commit is a
//     two-parent merge whose second parent is the pull request head. Any miss is refused (exit 1);
//   - a release is also refused (exit 1, reason `source-read-disabled`) while the repository variable
//     RELEASE_TAG_SOURCE_READ is not `true`: the read-only source token does not exist until a director
//     creates its App, and without it no release can be verified.
import { appendFileSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { RELEASE_BRANCH_PREFIX, releaseIdFromBranch } from './lib/release-source-surface.mjs'

/** Bot logins allowed to author a release pull request. */
export const RELEASE_PR_AUTHORS = Object.freeze(['rakomi-pr-autoupdate[bot]'])
export const SOURCE_READ_DISABLED = 'source-read-disabled'

const FULL_SHA_RE = /^[0-9a-f]{40}$/

/**
 * @param {{pushSha:string, parents:string[], pulls:Array<object>, defaultBranch:string, repoFullName:string,
 *          sourceReadEnabled:boolean, allowedAuthors?:readonly string[]}} f
 * @returns {{release:boolean, ok:boolean, prNumber?:number, headSha?:string, releaseId?:string,
 *            reason?:string, violations:string[]}}
 */
export function evaluateReleaseMerge(f) {
  const allowed = f.allowedAuthors || RELEASE_PR_AUTHORS
  const pushSha = String(f.pushSha || '').toLowerCase()
  if (!FULL_SHA_RE.test(pushSha)) return { release: false, ok: false, violations: ['the pushed sha is not a full 40-hex sha'] }
  if (!Array.isArray(f.pulls)) return { release: false, ok: false, violations: ['the pull request list is unreadable'] }
  const mine = f.pulls.filter((p) => p && p.merged_at && String(p.merge_commit_sha || '').toLowerCase() === pushSha)
  if (mine.length !== 1) {
    return { release: false, ok: false, violations: [`${mine.length} merged pull requests have ${pushSha} as their merge commit (exactly one required)`] }
  }
  const pr = mine[0]
  if (typeof pr.head?.ref !== 'string' || !pr.head.ref.startsWith(RELEASE_BRANCH_PREFIX)) {
    return { release: false, ok: true, prNumber: pr.number, violations: [] }
  }
  const v = []
  if (pr.base?.ref !== f.defaultBranch) v.push(`#${pr.number} was merged into ${pr.base?.ref}, not ${f.defaultBranch}`)
  if (pr.head?.repo?.full_name !== f.repoFullName || pr.base?.repo?.full_name !== f.repoFullName) v.push(`#${pr.number} comes from another repository`)
  if (!allowed.includes(pr.user?.login)) v.push(`#${pr.number} was opened by ${pr.user?.login}, not by an allowed release App`)
  const releaseId = releaseIdFromBranch(pr.head.ref)
  if (!releaseId) v.push(`#${pr.number} head branch is not release/<version>[+<prefix>]`)
  const headSha = String(pr.head?.sha || '').toLowerCase()
  if (!FULL_SHA_RE.test(headSha)) v.push(`#${pr.number} has no head sha`)
  if (!Array.isArray(f.parents) || f.parents.length !== 2 || String(f.parents[1]).toLowerCase() !== headSha) {
    v.push(`${pushSha} is not a merge commit whose second parent is the head of #${pr.number} (merge with a merge commit, never squash or rebase)`)
  }
  if (v.length) return { release: false, ok: false, prNumber: pr.number, violations: v }
  if (f.sourceReadEnabled !== true) {
    return { release: false, ok: false, prNumber: pr.number, reason: SOURCE_READ_DISABLED, violations: [`${SOURCE_READ_DISABLED}: no release is verified or tagged until RELEASE_TAG_SOURCE_READ is true`] }
  }
  return { release: true, ok: true, prNumber: pr.number, headSha, releaseId, violations: [] }
}
export class GateApiError extends Error {}

async function api(path, token) {
  const r = await fetch(`${process.env.GITHUB_API_URL || 'https://api.github.com'}${path}`, {
    headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, 'X-GitHub-Api-Version': '2022-11-28' },
    redirect: 'error',
  })
  if (!r.ok) throw new GateApiError(`GitHub API ${path} returned ${r.status}`)
  return r.json()
}

async function main() {
  const { GH_TOKEN, REPO, PUSH_SHA, DEFAULT_BRANCH, GITHUB_OUTPUT } = process.env
  if (!GH_TOKEN || !REPO || !PUSH_SHA || !DEFAULT_BRANCH) {
    console.error('release-tag-gate: CANNOT-EVALUATE — missing GH_TOKEN, REPO, PUSH_SHA or DEFAULT_BRANCH')
    process.exit(2)
  }
  let commit, pulls
  try {
    commit = await api(`/repos/${REPO}/commits/${PUSH_SHA}`, GH_TOKEN)
    pulls = await api(`/repos/${REPO}/commits/${PUSH_SHA}/pulls`, GH_TOKEN)
  } catch (e) {
    console.error(`release-tag-gate: CANNOT-EVALUATE — ${e.message}`)
    process.exit(2)
  }
  const parents = (commit.parents || []).map((p) => p.sha)
  const sourceReadEnabled = process.env.SOURCE_READ_ENABLED === 'true'
  const r = evaluateReleaseMerge({ pushSha: PUSH_SHA, parents, pulls, defaultBranch: DEFAULT_BRANCH, repoFullName: REPO, sourceReadEnabled })
  if (GITHUB_OUTPUT) {
    appendFileSync(GITHUB_OUTPUT, `release=${r.release}\npr_number=${r.prNumber ?? ''}\nhead_sha=${r.headSha ?? ''}\nrelease_id=${r.releaseId ?? ''}\n`)
  }
  if (!r.ok) {
    console.error(`release-tag-gate: REFUSED${r.reason ? ` ${r.reason}` : ''}`)
    for (const line of r.violations) console.error(`  - ${line}`)
    process.exit(1)
  }
  console.error(r.release ? `release-tag-gate: release pull request #${r.prNumber}, head ${r.headSha}` : 'release-tag-gate: not a release merge — nothing to tag')
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
