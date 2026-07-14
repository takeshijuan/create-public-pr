# Public PR writing guide

## Title

Use an imperative, specific title that describes the public change without private project names, local paths, internal ticket identifiers, or deployment context. Follow the repository's title convention when present.

## Body contract

Honor the repository PR template and keep these sections in its order:

1. **Summary** — what changes for users or maintainers.
2. **Why** — the public problem or rationale.
3. **Testing** — exact checks run and their outcomes.
4. **Privacy audit** — profile, complete/clean status, and safe manual-review record identifiers when applicable.
5. **Limitations** — what was intentionally not changed or not verified.

Write the body to a file and pass it with `--body-file`. Do not inline a multi-line body in a shell argument. Audit both title and body files before commit and after the final commit.

## Adaptable example

```markdown
## Summary

- Add deterministic validation for the documented workflow.
- Keep runtime behavior dependency-free.

## Why

Contributors need the same safety gates across supported environments.

## Testing

- Unit tests: passed.
- Repository validator: passed.
- Skill discovery: passed.

## Privacy audit

- Profile: community.
- Result: complete and clean.

## Limitations

- No deployment or merge was performed.
```

## Writing checks

- Describe observable behavior, not internal coordination or tool transcripts.
- Use safe commit/path identifiers for findings; never include the matched value.
- Do not link collaboration systems, private hosts, external trackers, or unrelated repositories.
- Use public examples and placeholder identifiers only.
- Keep claims proportional: local tests, draft PR state, checks, merge, and deployment are separate facts.
