# Contributing to AiEGIS

Thanks for considering contributing. AiEGIS is an open standard for substrate-anchored AI agent identity. Issues, PRs, and design discussion are welcome.

## How to contribute

### Spec changes

Spec changes (anything in `/spec`) require an issue first. Open one describing:

- The motivating use case
- The proposed change
- Backwards-compatibility impact

The maintainers will respond within 7 days with one of: ratify, refine, reject (with reasoning), or defer.

### Reference implementation

PRs against `/substrate-pack`, `/sdk`, `/compliance-bundle` are welcome. Keep them small + focused. Each PR should:

1. Have a clear single-sentence summary
2. Reference the spec section the change implements (or the issue it fixes)
3. Add tests covering the new behavior
4. Pass `python -m pytest` locally
5. Pass `bash scripts/pre_push_gate.sh` — 8 gates: (i) error-codes stability contract, (ii) IdentityError both-worlds contract, (iii) pytest full suite, (iv) JSON-LD @context body verify, (v) VPS reachability, (vi) VPS /api/health 200, (vii) compliance @context byte-stable, (viii) substrate @context byte-stable

### Test discipline

We treat tests as the contract. Some non-obvious patterns:

- **Append-only stability:** error codes are append-only post-v0.8 GA. The regression-lock test refuses removals; PRs adding codes must bump `V08_COUNT` in `test_error_codes.py`.
- **Sanitize-detail:** `IdentityError.detail` strips control chars + caps at 512 chars. Don't bypass.
- **Frozen post-init:** `IdentityError` attributes can't be mutated after construction. If you need to "change" a code, raise a new instance.

### Commit messages

Plain English. Reference issues / PR threads. No emoji unless the user explicitly requests them in a flow.

## Design partner program

Before 2026-05-31, we're accepting design partners. Contact hello@aiegis.ie if you're an operator looking to integrate the substrate-binding pipeline at production scale. Pricing and contract terms are negotiated per partner.

## Code of conduct

Be straight. Disagree with data. Don't be a jerk. The team operates under "professional objectivity" — technical accuracy over agreement, and we expect the same from contributors.

## Reporting issues

- Security issues: see [SECURITY.md](SECURITY.md) — do NOT use the public tracker
- Bugs: GitHub issues
- Spec ambiguity: GitHub issues with `spec` label
- Feature ideas: GitHub issues with `proposal` label

## License

By contributing, you agree your contribution is licensed under Apache 2.0 (matching the repo). See [LICENSE](LICENSE).

## Maintainers

- Travis Gerber — owner, identity architecture
- Velo — Mac mini reference impl + compliance-bundle
- Nel — substrate-pack verifiers + spec stewardship
