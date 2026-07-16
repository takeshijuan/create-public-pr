---
name: create-public-pr
description: Use when a user explicitly asks to create, open, prepare, publish, or refresh a public-safe pull request; do not use for review-only, local commit-only, issue, merge, or deployment requests.
---

# Create Public PR

## Overview

Create a new public-safe draft pull request, or safely refresh one existing pull request, only after its exact scope and complete branch history pass a redacting audit. A clean final diff is not enough: intermediate commits, identities, proposed PR text, binaries, symlinks, and intended worktree changes are all part of the boundary.

Read [privacy-policy.md](references/privacy-policy.md) before resolving findings. Read [pr-writing.md](references/pr-writing.md) before drafting the title and body.

## Ordered contract

1. **Inspect.** Read repository instructions and PR templates. Resolve the repository root, current branch, remote, authentication state, default base, working tree, existing branch commits, and any open PR for the head branch. Stop on detached HEAD, an ambiguous PR, an unexpected base, or incomplete repository access.
2. **Scope.** Name the intended change and obtain an explicit path or hunk boundary. Treat staged and untracked content as observations, not authorization. If approved and unrelated changes are mixed, stop and confirm the exact scope; do not use stash, reset, restore, or destructive index manipulation to separate it without authorization.
3. **Branch.** Enforce a focused non-default branch with only related commits. When the current branch is the base, create a branch using the repository convention or `codex/<short-description>`. Require the branch to differ from the base and `origin/$base` to be an ancestor of `HEAD`. If sensitive material exists in published history, do not amend, rebase, reset, or force-push. Stop before changing PR strategy; a clean replacement branch and replacement PR require explicit user authorization.
4. **Prepare.** Follow the repository template. Write the title, body, commit message, confirmed repo-relative paths, audit output, and manual-review records to files inside `.git/`. Follow the repository's commit convention; when none exists, use Conventional Commits. Resolve the skill directory from the loaded `SKILL.md`; never assume the target repository contains the scanner. Use `community` for ordinary OSS publication, including repositories described only as future-public. Select `locked-down` only when repository instructions explicitly impose no-external-links, no-internal-links, or an equivalent prohibition.
5. **Audit.** Run the scanner and audit/review comparator exactly as shown below. Exit 2 or an incomplete result is a hard stop. Exit 1 may continue only after a review file exists and the comparator proves an exact record for every eligible finding and no blocking finding; never weaken the profile, omit inputs, or substitute commands that print matched values.
6. **Validate.** Run the repository's relevant tests and checks. Resolve every blocking finding. Resolve each review finding using the evidence contract in the privacy reference.
7. **Stage.** Stage only confirmed paths or hunks with explicit pathspecs. Compare the staged set to the approved scope without printing raw paths, then run `git diff --cached --check`. Never use broad staging for a mixed worktree.
8. **Commit and re-audit.** Require repository-local GitHub noreply identity. Commit only the verified index, then audit the complete base-to-HEAD range and proposed PR text again.
9. **Push.** Push normally with no force option. Never merge, deploy, or rewrite history as part of this skill.
10. **Create or refresh and verify.** Refresh the single existing PR; otherwise create one draft. Creation passes explicit base, head, title, and body-file arguments. Refresh first verifies the immutable head, then passes explicit base, title, and body-file arguments. Preserve an existing PR's draft/readiness state unless the user explicitly requests a state change. Do not add reviewers, labels, projects, or milestones unless the user separately requests them. Verify number, URL, draft state, base, head, state, and checks.

## Quick reference

| Signal | Required response |
|---|---|
| `community` repository-link review | Verify it is public without credentials, relevant, and free of internal context; record evidence |
| `locked-down` repository-link | Remove or replace it; it is blocking |
| Checksum-bound public test artifact | Require a test/fixture-owned path; verify exact upstream bytes, relevance, public access, provenance, and license |
| Binary or non-noreply identity | Complete the manual-review record or remove/replace the affected material |
| Unsafe symlink, raw token, private key, or unverified private context | Remediate; never waive a blocking category |
| Mixed staged/untracked scope | Stop and obtain an exact scope without destructive index changes |
| Sensitive material in published history | Stop; no rewrite or force-push; replacement needs explicit authorization |
| Scanner exit 2 / incomplete | Stop; no commit, push, create, or refresh |

## Complete adaptable command sequence

Replace the angle-bracket path lists with the confirmed repository-relative paths and replace `short-description` with the focused branch slug. Keep proposal files under `.git/` so they cannot be committed accidentally.

```bash
repo_root=$(git rev-parse --show-toplevel) || exit 2
cd "$repo_root" || exit 2
branch=$(git branch --show-current)
test -n "$branch" || exit 2
gh auth status || exit 2
pr_count=$(gh pr list --head "$branch" --state open --json number --jq 'length') || exit 2
case "$pr_count" in
  0) base=$(gh repo view --json defaultBranchRef --jq '.defaultBranchRef.name') || exit 2 ;;
  1)
    pr_number=$(gh pr list --head "$branch" --state open --json number --jq '.[0].number') || exit 2
    base=$(gh pr view "$pr_number" --json baseRefName --jq '.baseRefName') || exit 2
    pr_head=$(gh pr view "$pr_number" --json headRefName --jq '.headRefName') || exit 2
    test "$pr_head" = "$branch" || exit 2
    existing_is_draft=$(gh pr view "$pr_number" --json isDraft --jq '.isDraft') || exit 2
    ;;
  *) exit 2 ;;
esac
git fetch origin "$base" || exit 2
git merge-base --is-ancestor "origin/$base" HEAD || exit 2
if test "$branch" = "$base"; then
  branch_name="codex/short-description"
  git switch -c "$branch_name" || exit 2
  branch="$branch_name"
fi
test "$branch" != "$base" || exit 2

profile=community
skill_root=${CREATE_PUBLIC_PR_SKILL_DIR:?set to the directory containing the loaded SKILL.md}
scanner="$skill_root/scripts/audit_public_pr.py"
comparator="$skill_root/scripts/validate_audit_review.py"
test -f "$scanner" || exit 2
test -f "$comparator" || exit 2
paths_file="$repo_root/.git/public-pr-paths.txt"
public_artifacts_file="$repo_root/.git/public-pr-public-artifacts.txt"
title_file="$repo_root/.git/public-pr-title.txt"
body_file="$repo_root/.git/public-pr-body.md"
commit_message_file="$repo_root/.git/public-pr-commit.txt"
audit_file="$repo_root/.git/public-pr-audit.json"
review_file="$repo_root/.git/public-pr-review.json"
staged_file="$repo_root/.git/public-pr-staged.txt"
diff_check_file="$repo_root/.git/public-pr-diff-check.txt"
public_artifact_args=()
if test -f "$public_artifacts_file"; then
  public_artifact_args=(--public-artifacts-from "$public_artifacts_file")
fi
printf '%s\n' <confirmed-paths> > "$paths_file"
IFS= read -r title < "$title_file"

python3 "$scanner" \
  --repo "$repo_root" --base "origin/$base" --profile "$profile" \
  --paths-from "$paths_file" --title-file "$title_file" \
  --body-file "$body_file" --commit-message-file "$commit_message_file" \
  "${public_artifact_args[@]}" \
  --format json > "$audit_file"
audit_status=$?
case "$audit_status" in
  0) printf '%s\n' '[]' > "$review_file" ;;
  1) test -f "$review_file" || exit 2 ;;
  *) exit 2 ;;
esac
python3 "$comparator" --audit-file "$audit_file" --review-file "$review_file" || exit 2

git add -- <confirmed-paths>
git add -p -- <confirmed-partial-paths>
git diff --cached --name-only > "$staged_file"
python3 -c 'import pathlib,sys; expected=set(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()); actual=set(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()); raise SystemExit(0 if expected == actual else 2)' "$paths_file" "$staged_file" || exit 2
if ! git diff --cached --check > "$diff_check_file" 2>&1; then printf '%s\n' 'staged diff check failed'; exit 2; fi
git config --local --get user.name | grep -Eq '[^[:space:]]' || exit 2
git config --local --get user.email | grep -Eq '@users\.noreply\.github\.com$' || exit 2
git commit --quiet -F "$commit_message_file" || exit 2

python3 "$scanner" \
  --repo "$repo_root" --base "origin/$base" --profile "$profile" \
  --paths-from "$paths_file" --title-file "$title_file" \
  --body-file "$body_file" --commit-message-file "$commit_message_file" \
  "${public_artifact_args[@]}" \
  --format json > "$audit_file"
audit_status=$?
case "$audit_status" in
  0) printf '%s\n' '[]' > "$review_file" ;;
  1) test -f "$review_file" || exit 2 ;;
  *) exit 2 ;;
esac
python3 "$comparator" --audit-file "$audit_file" --review-file "$review_file" || exit 2

git push -u origin "$branch" || exit 2
```

When audit exit 1 contains only eligible review findings, pause to write the records defined in the privacy reference to `public-pr-review.json`, then resume at the comparator. It compares the exact full key: `category`, `severity`, `source`, plus `commit`, `path_id`, and `artifact_id` whenever present. It rejects blocking findings, duplicates, unexpected/stale/missing records, invalid checks, and non-approved decisions without echoing values. Run it after each audit; an assertion without the file and successful comparator is not resolution.

After the open-PR query returns exactly one result, set its number and refresh it:

```sh
gh pr edit "$pr_number" --base "$base" --title "$title" --body-file "$body_file"
test "$(gh pr view "$pr_number" --json headRefName --jq '.headRefName')" = "$branch" || exit 2
test "$(gh pr view "$pr_number" --json isDraft --jq '.isDraft')" = "$existing_is_draft" || exit 2
```

When the query returns no result, create one draft:

```sh
gh pr create --draft --base "$base" --head "$branch" --title "$title" --body-file "$body_file"
pr_number=$(gh pr view "$branch" --json number --jq '.number') || exit 2
test "$(gh pr view "$pr_number" --json isDraft --jq '.isDraft')" = true || exit 2
```

Verify either path:

```sh
gh pr view "$pr_number" --json number,url,isDraft,baseRefName,headRefName,state,statusCheckRollup
```

## Common mistakes and red flags

- A clean tip diff does not clear sensitive material from intermediate commits.
- Existing staging does not define the user's intended PR scope.
- A maintainer assertion is not evidence that an external link or binary is public-safe.
- A review finding is not clean until its structured resolution is recorded.
- Never print matched values, raw potentially sensitive names or paths, addresses, URLs, tokens, or binary strings while investigating; use only safe identifiers.
- Never bypass the scanner, omit proposal files, downgrade an explicitly required `locked-down` policy, use broad staging, create a duplicate PR, rewrite published history, or force-push.
- Stop if any required fact, scan, test, manual review, or verification is incomplete.
