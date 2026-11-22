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
// A workflow_dispatch run (input pr_number) completes the release of one already-merged release pull request
// after a partial run: its merge commit is resolved from GET /pulls/{n} and must pass the same checks, belong
// to that pull request, be a release and be reachable from the default branch (evaluateDispatchedRelease).
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

export const PR_NUMBER_RE = /^[1-9][0-9]{0,9}$/

/**
 * A dispatched run completes the release of ONE already-merged release pull request (a partial earlier run).
 * Its merge commit (`merge_commit_sha` of that pull request) goes through exactly the push-path checks
 * (evaluateReleaseMerge with pushSha = the merge commit), and in addition: the requested number is digits
 * only, the checks resolve to THAT pull request, it is a release (a normal merge is refused, not "nothing
 * to do"), and the merge commit is reachable from the default branch.
 * @param {{requestedPr:string, mergeSha:string, mergeReachable:boolean, parents:string[], pulls:Array<object>,
 *          defaultBranch:string, repoFullName:string, sourceReadEnabled:boolean, allowedAuthors?:readonly string[]}} f
 */
export function evaluateDispatchedRelease(f) {
  if (!PR_NUMBER_RE.test(String(f.requestedPr ?? ''))) {
    return { release: false, ok: false, violations: ['pr_number must be the number of a pull request (digits only)'] }
  }
  const requested = Number(f.requestedPr)
  const r = evaluateReleaseMerge({ ...f, pushSha: f.mergeSha })
  if (!r.ok) return r
  const v = []
  if (r.prNumber !== requested) v.push(`the merge commit belongs to #${r.prNumber}, not to the requested #${requested}`)
  if (!r.release) v.push(`#${requested} is not a release pull request (head branch outside release/) — nothing to complete`)
  if (f.mergeReachable !== true) v.push(`the merge commit of #${requested} is not reachable from ${f.defaultBranch}`)
  if (v.length) return { release: false, ok: false, prNumber: r.prNumber, violations: v }
  return r
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
  // EVENT_NAME=workflow_dispatch: PR_NUMBER names the merged release pull request to complete; otherwise the
  // pushed sha (PUSH_SHA) is the candidate merge commit.
  const { GH_TOKEN, REPO, PUSH_SHA, DEFAULT_BRANCH, GITHUB_OUTPUT, EVENT_NAME, PR_NUMBER } = process.env
  const dispatched = EVENT_NAME === 'workflow_dispatch'
  if (!GH_TOKEN || !REPO || !DEFAULT_BRANCH || (!dispatched && !PUSH_SHA)) {
    console.error('release-tag-gate: CANNOT-EVALUATE — missing GH_TOKEN, REPO, PUSH_SHA or DEFAULT_BRANCH')
    process.exit(2)
  }
  if (dispatched && !PR_NUMBER_RE.test(PR_NUMBER || '')) {
    console.error('release-tag-gate: REFUSED')
    console.error('  - pr_number must be the number of a pull request (digits only)')
    process.exit(1)
  }
  const sourceReadEnabled = process.env.SOURCE_READ_ENABLED === 'true'
  let r
  let mergeSha = String(PUSH_SHA || '').toLowerCase()
  try {
    let mergeReachable = false
    if (dispatched) {
      const pr = await api(`/repos/${REPO}/pulls/${PR_NUMBER}`, GH_TOKEN)
      mergeSha = String(pr.merge_commit_sha || '').toLowerCase()
      if (!FULL_SHA_RE.test(mergeSha) || !pr.merged_at) {
        console.error('release-tag-gate: REFUSED')
        console.error(`  - #${PR_NUMBER} is not merged`)
        process.exit(1)
      }
      // base...head = <merge commit>...<default branch>: "identical" or "ahead" = the merge commit is an
      // ancestor of the default branch tip.
      const cmp = await api(`/repos/${REPO}/compare/${mergeSha}...${encodeURIComponent(DEFAULT_BRANCH)}`, GH_TOKEN)
      mergeReachable = (cmp.status === 'identical' || cmp.status === 'ahead') && cmp.behind_by === 0
    }
    const commit = await api(`/repos/${REPO}/commits/${mergeSha}`, GH_TOKEN)
    const pulls = await api(`/repos/${REPO}/commits/${mergeSha}/pulls`, GH_TOKEN)
    const parents = (commit.parents || []).map((p) => p.sha)
    const facts = { parents, pulls, defaultBranch: DEFAULT_BRANCH, repoFullName: REPO, sourceReadEnabled }
    r = dispatched
      ? evaluateDispatchedRelease({ ...facts, requestedPr: PR_NUMBER, mergeSha, mergeReachable })
      : evaluateReleaseMerge({ ...facts, pushSha: mergeSha })
  } catch (e) {
    console.error(`release-tag-gate: CANNOT-EVALUATE — ${e.message}`)
    process.exit(2)
  }
  if (GITHUB_OUTPUT) {
    appendFileSync(GITHUB_OUTPUT, `release=${r.release}\npr_number=${r.prNumber ?? ''}\nhead_sha=${r.headSha ?? ''}\nmerge_sha=${r.release ? mergeSha : ''}\nrelease_id=${r.releaseId ?? ''}\n`)
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
