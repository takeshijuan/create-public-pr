# Changelog

## [Unreleased]

### Added

- Add a fail-closed user choice when a repository-wide audit proves that sensitive history predates the current pull request boundary.
- Preserve complete current-PR scanning, reject implicit choices and history rewrites, and invalidate prior approval when the base or head changes.
- Add validator, evaluation, policy, documentation, and regression-test coverage for the history decision gate.

### Fixed

- Recognize GitHub Actions workflow command and paired stop/resume markers without masking private IPv6 values at command, property, delimiter, or expression boundaries.
- Keep workflow marker parsing linear for large, malformed, and expression-heavy inputs.
