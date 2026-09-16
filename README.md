# create-public-pr

[![skills.sh](https://skills.sh/b/takeshijuan/create-public-pr)](https://skills.sh/takeshijuan/create-public-pr)

`create-public-pr` is a portable Agent Skill for preparing or refreshing a privacy-safe public pull request. It combines exact scope control, a redacting standard-library Python scanner, explicit validation gates, and draft-first GitHub CLI commands.

## Install

```sh
npx skills@latest add takeshijuan/create-public-pr --skill create-public-pr
```

Inspect the skill in a local checkout without installing it:

```sh
npx skills@latest add . --list
```

User-facing installation commands intentionally track the latest CLI. Continuous integration pins repository discovery for reproducibility:

```sh
npx --yes skills@1.5.17 add . --list
```

## What it enforces

- Confirmed public-repository PR requests, or explicit `create-public-pr` / public-safe opt-in. Ordinary private, internal, future-public, and unverified repositories use their normal PR workflow; review-only, commit-only, merge, issue, and deployment requests do not trigger it.
- Complete history and worktree scanning without printing matched sensitive values.
- A fail-closed two-choice gate for proven pre-existing history contamination: accept only the old contamination and audit the complete current PR publication delta, or leave the skill and clean history in a separately authorized workflow. The choice never waives current-PR findings and expires when the base or HEAD changes.
- Exact staging, repository-local GitHub noreply identity, normal pushes, draft creation, and existing-PR refresh.
- No implicit reviewers, labels, projects, milestones, merges, deployments, history rewrites, or force-pushes.
- A `community` profile for ordinary OSS publication and a stricter `locked-down` profile only for explicit no-external-links or no-internal-links policies.
- Exact SHA-256-bound review evidence for retained public upstream fixtures whose literal test data resembles a credential assignment or private host.

The scanner uses only the Python standard library at runtime and supports Python 3.10 and newer.

Visibility must be checked before announcing use or starting audit gates. A generic “create a PR and deploy” request, an auto-loaded skill attachment, or a question/fix request about this skill is not explicit opt-in. The command sequence also exits before PR discovery or mutation unless visibility is `PUBLIC` or `CREATE_PUBLIC_PR_EXPLICIT_OPT_IN=true` records an actual user instruction for that PR.

## v0.1.0 beta limitations

This release is a beta with deliberately conservative stop conditions.

- The scanner is heuristic and cannot prove that every form of sensitive or proprietary context is absent. Review the proposed public surface and complete every required manual-review record.
- The documented GitHub mutation paths are tested with a deterministic fake `gh`; repository tests do not create or refresh a live GitHub pull request.
- Community-profile repository links, changed binaries, non-noreply commit identities, and checksum-bound public fixtures require explicit review evidence. Locked-down blocking findings cannot be waived.
- Public-artifact review is intentionally narrow: malformed manifests, digest drift, symlinks, raw credential-token shapes, private keys, and credential-bearing URLs still stop the workflow.
- The skill prepares or refreshes pull requests only. It does not merge, deploy, rewrite history, or force-push.

## Validate a checkout

```sh
python3 -m unittest discover -s tests -v
python3 scripts/validate_skill.py --repo .
npx --yes skills@1.5.17 add . --list
```

## License

MIT. See [LICENSE](LICENSE).
