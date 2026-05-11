<!-- Thanks for the PR! Please fill out the sections below. -->

## Summary

<!-- One or two sentences. What changes, and why. -->

## Linked issue

<!-- e.g. Closes #123, Refs #456 -->

## Test plan

<!-- How did you verify this? Did pre_push_gate pass locally? -->

- [ ] `bash scripts/pre_push_gate.sh` PASSED 10/10 locally
- [ ] New tests added / existing tests updated
- [ ] `python3 -m pytest compliance-bundle` PASSED

## Breaking change

- [ ] No breaking change
- [ ] Wire-format or public-API break — requires v0.8 bump + CHANGELOG entry

## Checklist

- [ ] CHANGELOG.md updated if user-visible
- [ ] Spec changes referenced an open issue first (per CONTRIBUTING.md)
- [ ] Did not edit `.github/workflows/` without explicit reviewer ack
