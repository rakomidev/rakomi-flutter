#!/usr/bin/env node
// No personal e-mail address in the identity of the commit a release tag points at.
//
// The release archive of the tag commit is signed and recorded in a public transparency log, so the
// author, the committer and every `Co-authored-by:` / `Signed-off-by:` trailer of that commit must carry
// only the release role mailbox. Runs before any signing or publishing step.
//
//   node .github/scripts/check-build-identity.mjs [--ref <commit>]     (default: HEAD)
//
// Exit: 0 = only role mailboxes; 1 = a personal address; 2 = cannot evaluate. Node built-ins only.
import { execFileSync } from 'node:child_process'
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const ROLE_MAILBOXES = Object.freeze(['release-bot@rakomi.com'])
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[^\s<>,;"']+/g

/**
 * Identity strings of a commit: the author and committer lines plus every Co-authored-by: /
 * Signed-off-by: trailer of the body (CRLF-safe).
 * @param {string} idLines `Name <email>` lines, newline-separated
 * @param {string} body the commit message
 */
export function collectCommitIdentities(idLines, body) {
  const out = []
  for (const l of String(idLines).split(/\r?\n/)) if (l.trim()) out.push(l.trim())
  for (const l of String(body).split(/\r?\n/)) {
    const m = /^\s*(?:co-authored-by|signed-off-by)\s*:\s*(.+)$/i.exec(l)
    if (m) out.push(m[1].trim())
  }
  return out
}

/**
 * Violations name the identity by position only (author, committer, trailer n), never by its text: the
 * log of the public workflow must not repeat the address it refuses.
 * @param {string[]} identities as collectCommitIdentities returns them
 * @returns {string[]} violations (empty = clean)
 */
export function personalEmailViolations(identities, allowed = ROLE_MAILBOXES) {
  const allow = new Set(allowed)
  const v = []
  identities.forEach((t, i) => {
    const who = i === 0 ? 'author' : i === 1 ? 'committer' : `trailer ${i - 1}`
    const emails = t.match(EMAIL_RE) || []
    if (emails.length === 0) v.push(`${who}: no e-mail address`)
    if (emails.some((e) => !allow.has(e.toLowerCase()))) v.push(`${who}: not the release role mailbox`)
  })
  return v
}

function main() {
  const i = process.argv.indexOf('--ref')
  const ref = i >= 0 ? process.argv[i + 1] : 'HEAD'
  if (!ref || ref.startsWith('-')) {
    console.error('check-build-identity: --ref needs a commit')
    process.exit(2)
  }
  let author, committer, body
  try {
    const git = (fmt) => execFileSync('git', ['show', '-s', `--format=${fmt}`, ref], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
    author = git('%an <%ae>').trim()
    committer = git('%cn <%ce>').trim()
    body = git('%B')
  } catch {
    console.error('check-build-identity: CANNOT-EVALUATE — the commit could not be read')
    process.exit(2)
  }
  const v = personalEmailViolations(collectCommitIdentities(`${author}\n${committer}`, body))
  if (v.length) {
    for (const line of v) console.error(`  - ${line}`)
    console.error('check-build-identity: FAIL — only the release role mailbox may sign a release commit')
    process.exit(1)
  }
  console.log('check-build-identity: OK — role mailbox only')
}

const isCliEntry = (() => {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const real = (p) => { try { return realpathSync(p) } catch { return p } }
  try { return real(argv1) === real(fileURLToPath(import.meta.url)) } catch { return false }
})()
if (isCliEntry) main()
