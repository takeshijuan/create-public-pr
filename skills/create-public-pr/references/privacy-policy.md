# Public PR privacy policy

## Audit boundary

The audit covers the current branch name, changed filenames, every commit in the base-to-HEAD range, commit messages, author and committer identities, every added line in each commit, intended tracked and untracked worktree paths, symlinks, binaries, and proposed title/body/commit-message files.

Only the scanner may inspect potentially sensitive values. Reports expose category, severity, source kind, safe path identifier, safe commit identifier, and remediation. Never copy a match into terminal output, notes, a PR, or a review record.

## Profiles and outcomes

Use `community` unless repository instructions require future-public or no-internal-links handling. `community` marks an external repository link for review so its public status and relevance can be proven. Use `locked-down` automatically for stricter repositories; every cross-repository link or external tracker reference is then blocking.

Scanner outcomes are fixed:

| Outcome | Meaning | Action |
|---|---|---|
| Exit 0 | Complete and clean | Continue to the next gate |
| Exit 1 | Blocking or review findings | Remediate or complete every allowed manual review |
| Exit 2 | Invalid input, Git failure, or incomplete scan | Stop immediately |

Credentials, private keys, credential-bearing URLs, collaboration-tool URLs, private/local hosts, local filesystem paths, non-example emails, external trackers, unsafe symlinks, and locked-down external repository links are hard blocks. Generic product names such as Slack, Notion, or ClickUp may identify a prohibited category, but links or internal context from those systems must not enter a public PR.

## Manual-review evidence

Only `repository-link` under `community`, `binary`, and `identity` findings are eligible for manual resolution. Store a JSON array at `.git/public-pr-review.json`, keep it out of commits, and create one object per finding without including the matched value. Include `commit` and `path_id` if and only if the finding contains them:

```json
[
  {
    "category": "repository-link",
    "severity": "review",
    "source": "scanner source kind",
    "commit": "0123456789ab",
    "path_id": "abcdef012345",
    "checks": {
      "public_without_credentials": "pass",
      "relevant_to_change": "pass",
      "no_internal_context": "pass",
      "provenance_and_license": "not-applicable"
    },
    "decision": "approved",
    "reviewer": "accountable role",
    "rationale": "public-safe summary without the matched value"
  }
]
```

For a community repository link, independently confirm public access without private credentials, direct relevance, and absence of internal context. For a binary, set the first two checks to `not-applicable`, verify no internal context plus provenance/license, and avoid printing extracted strings. For an identity, only the no-internal-context check is `pass`; the other checks are `not-applicable`. If the decision is remove or replace, remediate and rerun the audit instead of retaining a record. Never expose an address.

An assertion of harmlessness, a successful page load with private credentials, or a clean final diff is not evidence. The standard-library comparator rejects every blocking finding and matches the exact one-to-one set of eligible findings by category, severity, source, commit when present, and path identifier when present. Duplicate, unexpected, stale, missing, or invalid records stop the workflow. If verification is inconclusive, remove or replace the material.

## History and scope boundaries

If a finding exists in any published branch commit, another deletion commit does not remove the exposure. Do not amend, rebase, reset, or force-push. Stop and ask whether to build a new clean branch from the base. Closing or replacing an existing PR is a strategy change and requires explicit user authorization.

For mixed work, do not infer scope from the index or untracked files. Obtain exact paths/hunks. If separating them would disturb unrelated work, stop and request a clean worktree or a specifically authorized preservation method.
