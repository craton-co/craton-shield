## Summary

<!-- Brief description of what this PR does and why. -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] Test improvement
- [ ] CI/build change

## Domain

- [ ] Core
- [ ] Automotive
- [ ] Embedded IoT
- [ ] Industrial OT/ICS

## Checklist

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo check --target thumbv7em-none-eabihf` passes for affected `no_std` crates
- [ ] New code has `///` doc comments on all `pub` items
- [ ] Tests added for new functionality or bug regression
- [ ] Documentation updated (if behavior changed)
- [ ] CHANGELOG.md updated (if user-facing change)
- [ ] No new `unsafe` code (or safety comments added and maintainer review requested)

## Security Considerations

<!-- Does this change affect security properties? Constant-time operations, key handling, input validation, etc. Write "N/A" if not applicable. -->

## Testing

<!-- How was this tested? Include relevant test commands, hardware targets, or benchmark results. -->

## Related Issues

<!-- Link to related issues: Fixes #123, Relates to #456 -->
