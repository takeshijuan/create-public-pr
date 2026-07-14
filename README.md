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

- Explicit public-PR requests only; review-only, commit-only, merge, issue, and deployment requests do not trigger it.
- Complete history and worktree scanning without printing matched sensitive values.
- Exact staging, repository-local GitHub noreply identity, normal pushes, draft creation, and existing-PR refresh.
- No implicit reviewers, labels, projects, milestones, merges, deployments, history rewrites, or force-pushes.
- A stricter `locked-down` profile for future-public or no-internal-links repositories.

The scanner uses only the Python standard library at runtime and supports Python 3.10 and newer.

## v0.1.0 beta limitations

This release is a beta with deliberately conservative stop conditions.

- The scanner is heuristic and cannot prove that every form of sensitive or proprietary context is absent. Review the proposed public surface and complete every required manual-review record.
- The documented GitHub mutation paths are tested with a deterministic fake `gh`; repository tests do not create or refresh a live GitHub pull request.
- Community-profile repository links, changed binaries, and non-noreply commit identities require explicit review evidence. Locked-down blocking findings cannot be waived.
- The skill prepares or refreshes pull requests only. It does not merge, deploy, rewrite history, or force-push.

## Validate a checkout

```sh
python3 -m unittest discover -s tests -v
python3 scripts/validate_skill.py --repo .
npx --yes skills@1.5.17 add . --list
```

## License

MIT. See [LICENSE](LICENSE).
