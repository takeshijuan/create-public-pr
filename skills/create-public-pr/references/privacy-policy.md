# Public PR privacy policy

## Audit boundary

The audit covers the current branch name, changed filenames, every commit in the base-to-HEAD range, commit messages, author and committer identities, every added line in each commit, intended tracked and untracked worktree paths, symlinks, binaries, and proposed title/body/commit-message files.

Only the scanner may inspect potentially sensitive values. Reports expose category, severity, source kind, safe path identifier, safe commit identifier, and remediation. Never copy a match into terminal output, notes, a PR, or a review record.

## Pre-existing history classification

A repository-wide history finding is pre-existing only when its safe commit identifier is proven reachable from `origin/$base` and outside `origin/$base..HEAD`. The current PR publication delta contains every commit in `origin/$base..HEAD`, intended tracked and untracked worktree paths, and proposed title, body, and commit message. Unclassified or current-PR findings remain blocking.

Accepting proven pre-existing contamination does not create a manual-review exception or suppress any finding in the current PR publication delta. Choosing to clean history first ends this skill without rewriting history; cleanup requires a separately authorized workflow and a fresh audit afterward. Changing the base or HEAD invalidates the classification and the user's prior choice. Throughout classification, matched values remain scanner-only and only safe identifiers may be handled.

## Profiles and outcomes

Use `community` for ordinary OSS publication, including repositories described only as future-public. It marks an external repository link for review so its public status and relevance can be proven. Use `locked-down` only when repository instructions explicitly require no-external-links, no-internal-links, or an equivalent prohibition; every cross-repository link is then blocking.

Scanner outcomes are fixed:

| Outcome | Meaning | Action |
|---|---|---|
| Exit 0 | Complete and clean | Continue to the next gate |
| Exit 1 | Blocking or review findings | Remediate or complete every allowed manual review |
| Exit 2 | Invalid input, Git failure, or incomplete scan | Stop immediately |

Private keys, raw credential-token shapes, credential-bearing URLs, collaboration-tool URLs, local filesystem paths, non-example emails, external trackers, unsafe symlinks, and locked-down external repository links are hard blocks. Credential-assignment or private-host-shaped text remains blocking unless it is content in an exact checksum-bound public artifact reviewed under the rule below. Generic product names such as Slack, Notion, or ClickUp may identify a prohibited category, but links or internal context from those systems must not enter a public PR.

## Manual-review evidence

Only `repository-link` under `community`, `binary`, `identity`, and `public-artifact` findings are eligible for manual resolution. Store a JSON array at `.git/public-pr-review.json`, keep it out of commits, and create one object per finding without including the matched value. Include `commit`, `path_id`, and `artifact_id` if and only if the finding contains them:

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

For a community repository link, independently confirm public access without private credentials, direct relevance, and absence of internal context. For a binary, set the first two checks to `not-applicable`, verify no internal context plus provenance/license, and avoid printing extracted strings. For an identity, only the no-internal-context check is `pass`; the other checks are `not-applicable`.

For a retained public upstream fixture whose literal test data resembles a credential assignment or private host, create `.git/public-pr-public-artifacts.txt` with one line per artifact in the exact form `<lowercase SHA-256><two spaces><repo-relative path>`. The path must identify a current regular file with no symlink component and include a recognized test or fixture directory component. Independently verify unauthenticated public access, byte-for-byte equality with the named upstream source, relevance to the change, absence of internal context, and license or NOTICE coverage. The five structured review checks, including `upstream_bytes_match`, must pass. The scanner binds the review to the safe path identifier and full artifact digest, and validates each commit blob independently. A malformed row, duplicate path, non-test path, control character, absolute or parent path, symlink, missing file, or digest mismatch makes the audit incomplete. This mechanism never makes private keys, raw token shapes, credential URLs, collaboration links, proposal text, branch names, commit messages, identities, or runtime source/configuration files reviewable.

If the decision is remove or replace, remediate and rerun the audit instead of retaining a record. Never expose an address.

An assertion of harmlessness, a successful page load with private credentials, or a clean final diff is not evidence. The standard-library comparator rejects every blocking finding and matches the exact one-to-one set of eligible findings by category, severity, source, commit when present, path identifier when present, and artifact digest when present. Duplicate, unexpected, stale, missing, or invalid records stop the workflow. If verification is inconclusive, remove or replace the material.

## History and scope boundaries

If a finding exists in any published branch commit, another deletion commit does not remove the exposure. Do not amend, rebase, reset, or force-push. Stop and ask whether to build a new clean branch from the base. Closing or replacing an existing PR is a strategy change and requires explicit user authorization.

For mixed work, do not infer scope from the index or untracked files. Obtain exact paths/hunks. If separating them would disturb unrelated work, stop and request a clean worktree or a specifically authorized preservation method.
