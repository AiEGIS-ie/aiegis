#!/usr/bin/env bash
# AiEGIS-ie/aiegis mono-repo push staging script — v2 Air-side variant.
#
# v1 ran from V's mini and tried SSH back to Nel's Air to pull spec/substrate
# files. That direction hit macOS sshd "Server accepts key + Permission denied"
# (SecureToken + FileVault + no FDA for sshd) and was unfixable without Trav
# granting FDA via System Settings. v2 flips direction — runs from Air, pulls
# V-side files via Air→mini SSH (proven working).
#
# Fail-closed allowlist (per F35 + cross-lane discipline): every file
# explicitly named goes public; everything else stays private. If a new
# spec file lands on either lane, this script will NOT cp it until
# explicitly added to the allowlist.
#
# ORIGIN: Nel's Air (NEL.local)
# EXECUTION: bash this script after Trav creates AiEGIS-ie/aiegis empty repo
# TARGET: AiEGIS-ie/aiegis (mono-repo)

set -euo pipefail

# ── Configurable paths ──
STAGING_DIR="${STAGING_DIR:-/Users/nel/Documents/NEL/aiegis-public-prep}"
N_DIR="${N_DIR:-/Users/nel/Documents/NEL/aiegis-prompt-interceptor}"
V_HOST="${V_HOST:-velo@100.112.159.3}"              # tailscale IP, proven working
V_PREP_DIR="${V_PREP_DIR:-/Users/velo/Documents/VELO/aiegis-public-prep}"  # V's staged boilerplate
V_DIR="${V_DIR:-/Users/velo/Documents/VELO/aiegis-compliance-bundle}"
V_SPEC_SOURCE_ROOT="${V_SPEC_SOURCE_ROOT:-/Users/velo/Documents/VELO}"
SDK_DIR="${SDK_DIR:-/Users/velo/Documents/VELO/aiegis-agent-sdk-python}"

# ── Optional flags ──
DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  echo "=== DRY RUN: will show planned actions, no file modifications ==="
fi

run_cp() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [dry-run] cp $1 → $2"
  else
    cp "$1" "$2"
  fi
}

run_scp_in() {
  # scp from V mini to local STAGING_DIR (we're on Air pulling)
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [dry-run] scp $V_HOST:$1 → $2"
  else
    scp -q "$V_HOST:$1" "$2"
  fi
}

run_rsync_in() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [dry-run] rsync $V_HOST:$1/ → $2/"
  else
    rsync -av \
          --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' \
          --exclude='.swiftpm' --exclude='.build' \
          --exclude='*.egg-info' --exclude='*.egg' \
          --exclude='.tox' --exclude='build' --exclude='dist' \
          "$V_HOST:$1/" "$2/"
  fi
}

# ── Spec allowlist (N-side, local read) ──
# Source filename → canonical mono-repo /spec name (rename on cp per F31)
declare -a N_SPEC_FILES=(
  "DID_AIEGIS_METHOD_SPEC_V01.md:DID_METHOD_SPEC.md"
  "HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01.md:SUBSTRATE_BINDING_SPEC.md"
  "AIEGIS_AGENT_SDK_DESIGN_V01.md:AGENT_SDK_DESIGN.md"
  "VC_ENVELOPE_EXPORT_SPEC_V01.md:VC_ENVELOPE_EXPORT_SPEC.md"
  "VC_REVOCATION_LIST_SPEC_V01.md:VC_REVOCATION_LIST_SPEC.md"
  "OPERATOR_KEY_CUSTODY_SPEC_V01.md:OPERATOR_KEY_CUSTODY_SPEC.md"
  "POP_DID_COMPOSITION_V01.md:POP_DID_COMPOSITION.md"
)

# ── Spec allowlist (V-side, SSH pull) ──
declare -a V_SPEC_FILES=(
  "aiegis-compliance-bundle-v0_7_spec_DRAFT.md:COMPLIANCE_BUNDLE_SPEC.md"
)

# ── Substrate-pack code files (N-side, local) ──
declare -a N_SUBSTRATE_FILES=(
  "binding_proof_reference.py"
  "tpm_quote_verifier_reference.py"
  "apple_se_assertion_verifier_reference.py"
  "tee_attestation_verifier_reference.py"
  "agent_substrate_acquirer_reference.py"
  "substrate_context_mapper.py"
)

# ── V-side compliance-bundle files (SSH pull from mini) ──
# Populated via smoke test of V_DIR contents at lap-371. V to confirm/extend.
declare -a V_COMPLIANCE_FILES=(
  "error_codes.py"
  "errors.py"
  "generator.py"
  "test_error_codes.py"
  "test_errors.py"
  "test_generator.py"
  "test_integration_nel_tpm.py"
)

# ── Public boilerplate (from V's already-staged aiegis-public-prep) ──
declare -a V_PUBLIC_BOILERPLATE=(
  "LICENSE"
  "README.md"
  "SECURITY.md"
  "CONTRIBUTING.md"
  "CHANGELOG.md"
  "requirements-ci.txt"
)

# ── V-side spec artifacts under V_PREP_DIR/spec/ ──
declare -a V_PREP_SPEC_FILES=(
  "grid_example_smb.json"
  "grid_catalog_example.json"
  "grid_signed_catalog_envelope.json"
  "aiegis_binding_example.json"
  "grid_agent_example.py"
  "GRID_SCHEMA_OVERVIEW.md"
  "grid.schema.json"
)

# ── V-side docs ──
declare -a V_PREP_DOC_FILES=(
  "docs/SMB_ONBOARDING.md"
)

# ── pre-push gate script (V-side aiegis-monorepo, SSH pull) ──
# Referenced by CONTRIBUTING.md line 25; Day-1 contributors clone the repo and
# run `bash scripts/pre_push_gate.sh` to verify their PR before submitting.
# Source on V mini lives at aiegis-monorepo/scripts/, copied to public-repo
# /scripts/ on push (alongside this stage script which is also published per
# F35 transparency).
V_GATE_SOURCE="${V_GATE_SOURCE:-/Users/velo/Documents/VELO/aiegis-monorepo/scripts/pre_push_gate.sh}"

# ── .gitignore from V-side aiegis-monorepo (SSH pull) ──
# Day-1 contributor running `pip install -e .` + `pytest` will generate
# __pycache__/, .pytest_cache/, *.egg-info/ which without .gitignore become
# noise in `git status` + can accidentally get committed. Pull V's canonical
# .gitignore (build artifacts + IDE + OS + secrets + Rust target/) into repo
# root. V-canonical sha 9a4d9bcb at lap-411 audit.
V_GITIGNORE_SOURCE="${V_GITIGNORE_SOURCE:-/Users/velo/Documents/VELO/aiegis-monorepo/.gitignore}"

# ── CI workflow (V-side aiegis-public-prep/.github/workflows/, SSH pull) ──
# Day-1 contributors opening PRs need structural gate via GitHub Actions —
# local pre_push_gate.sh only runs on author's machine. V-authored lap-421+
# with matrix python 3.10/3.11/3.12, sha 4dce8367 post id-fix. Lives at
# .github/workflows/pre-push-gate.yml.
V_CI_WORKFLOW_SOURCE="${V_CI_WORKFLOW_SOURCE:-/Users/velo/Documents/VELO/aiegis-public-prep/.github/workflows/pre-push-gate.yml}"

# ── Functions ──
mkdirs() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [dry-run] would mkdir -p $STAGING_DIR/{spec,substrate-pack,substrate-pack/vendored_errors,compliance-bundle,sdk,docs,.github/workflows,scripts}"
    return
  fi
  mkdir -p "$STAGING_DIR/spec"
  mkdir -p "$STAGING_DIR/substrate-pack"
  mkdir -p "$STAGING_DIR/substrate-pack/vendored_errors"
  mkdir -p "$STAGING_DIR/compliance-bundle"
  mkdir -p "$STAGING_DIR/sdk"
  mkdir -p "$STAGING_DIR/docs"
  mkdir -p "$STAGING_DIR/.github/workflows"
  mkdir -p "$STAGING_DIR/scripts"
}

cp_n_specs() {
  echo "=== N-side spec files → /spec (rename on cp, local read) ==="
  for entry in "${N_SPEC_FILES[@]}"; do
    src="${entry%%:*}"
    dst="${entry##*:}"
    run_cp "$N_DIR/$src" "$STAGING_DIR/spec/$dst"
    echo "  ✓ $src → spec/$dst"
  done
}

cp_v_specs() {
  echo "=== V-side spec files → /spec (rename on cp, SSH pull from mini) ==="
  for entry in "${V_SPEC_FILES[@]}"; do
    src="${entry%%:*}"
    dst="${entry##*:}"
    run_scp_in "$V_SPEC_SOURCE_ROOT/$src" "$STAGING_DIR/spec/$dst"
    echo "  ✓ $src → spec/$dst"
  done
  for f in "${V_PREP_SPEC_FILES[@]}"; do
    run_scp_in "$V_PREP_DIR/spec/$f" "$STAGING_DIR/spec/$f"
    echo "  ✓ spec/$f (no rename)"
  done
}

cp_n_substrate() {
  echo "=== N-side substrate-pack files (local read) ==="
  for f in "${N_SUBSTRATE_FILES[@]}"; do
    run_cp "$N_DIR/$f" "$STAGING_DIR/substrate-pack/$f"
    echo "  ✓ substrate-pack/$f"
  done
  # vendored_errors subdir (also N-side per memory)
  if [[ -f "$N_DIR/vendored_errors/errors.py" ]]; then
    run_cp "$N_DIR/vendored_errors/errors.py" "$STAGING_DIR/substrate-pack/vendored_errors/errors.py"
    echo "  ✓ substrate-pack/vendored_errors/errors.py"
  fi
}

cp_v_compliance() {
  echo "=== V-side compliance-bundle files (SSH pull from mini) ==="
  if [[ ${#V_COMPLIANCE_FILES[@]} -eq 0 ]]; then
    echo "  ⚠ V_COMPLIANCE_FILES allowlist is empty — V to confirm files before push"
    return
  fi
  for f in "${V_COMPLIANCE_FILES[@]}"; do
    run_scp_in "$V_DIR/$f" "$STAGING_DIR/compliance-bundle/$f"
    echo "  ✓ compliance-bundle/$f"
  done
}

cp_sdk() {
  echo "=== V-side SDK package (rsync pull from mini) ==="
  run_rsync_in "$SDK_DIR" "$STAGING_DIR/sdk"
  echo "  ✓ sdk/ tree synced"
}

cp_v_boilerplate() {
  echo "=== Public boilerplate from V's aiegis-public-prep root → STAGING root ==="
  for f in "${V_PUBLIC_BOILERPLATE[@]}"; do
    run_scp_in "$V_PREP_DIR/$f" "$STAGING_DIR/$f"
    echo "  ✓ $f"
  done
}

cp_gitignore() {
  echo "=== .gitignore (SSH pull from V mini aiegis-monorepo) ==="
  run_scp_in "$V_GITIGNORE_SOURCE" "$STAGING_DIR/.gitignore"
  echo "  ✓ .gitignore (build artifacts + IDE + OS + secrets + Rust target/)"
}

cp_ci_workflow() {
  echo "=== CI workflow (SSH pull from V mini aiegis-public-prep/.github/workflows/) ==="
  run_scp_in "$V_CI_WORKFLOW_SOURCE" "$STAGING_DIR/.github/workflows/pre-push-gate.yml"
  echo "  ✓ .github/workflows/pre-push-gate.yml (Day-1 contributor PR gate)"
  # dependabot.yml — weekly pip + github-actions ecosystem auto-bumps,
  # PRs re-fire gate matrix on the bump branch. Closes supply-chain drift
  # class for the pinned requirements-ci.txt. V-authored lap-431, sha 1bb45d87.
  V_DEPENDABOT_SOURCE="${V_DEPENDABOT_SOURCE:-/Users/velo/Documents/VELO/aiegis-public-prep/.github/dependabot.yml}"
  run_scp_in "$V_DEPENDABOT_SOURCE" "$STAGING_DIR/.github/dependabot.yml"
  echo "  ✓ .github/dependabot.yml (weekly pip + github-actions auto-bumps)"
}

cp_v_docs() {
  echo "=== V-side docs from aiegis-public-prep → /docs ==="
  for f in "${V_PREP_DOC_FILES[@]}"; do
    run_scp_in "$V_PREP_DIR/$f" "$STAGING_DIR/$f"
    echo "  ✓ $f"
  done
}

cp_pre_push_gate() {
  echo "=== Pre-push gate + post-push verify scripts (SSH pull from V mini) ==="
  mkdir -p "$STAGING_DIR/scripts"
  run_scp_in "$V_GATE_SOURCE" "$STAGING_DIR/scripts/pre_push_gate.sh"
  if [[ $DRY_RUN -eq 0 ]]; then
    chmod +x "$STAGING_DIR/scripts/pre_push_gate.sh"
  fi
  echo "  ✓ scripts/pre_push_gate.sh (referenced by CONTRIBUTING.md line 25)"
  # verify_jsonld_contexts.sh — gate (iv) helper, invoked by pre_push_gate.sh
  # line 57 via `bash "$SCRIPT_DIR/verify_jsonld_contexts.sh"`. Without this
  # file in the staged tree, gate (iv) fails with "No such file" for Day-1
  # contributors. V-authored race-safe + DoS-timeout at lap-428.
  V_VERIFY_JSONLD_SOURCE="${V_VERIFY_JSONLD_SOURCE:-/Users/velo/Documents/VELO/aiegis-monorepo/scripts/verify_jsonld_contexts.sh}"
  run_scp_in "$V_VERIFY_JSONLD_SOURCE" "$STAGING_DIR/scripts/verify_jsonld_contexts.sh"
  if [[ $DRY_RUN -eq 0 ]]; then
    chmod +x "$STAGING_DIR/scripts/verify_jsonld_contexts.sh"
  fi
  echo "  ✓ scripts/verify_jsonld_contexts.sh (gate iv helper, race-safe + 10s DoS-cap)"
  # post_push_verify.sh — fires AFTER git push to verify the public repo
  # is faithful + complete + importable. V-authored per lap-386, sha 86446eee.
  V_POST_PUSH_SOURCE="${V_POST_PUSH_SOURCE:-/Users/velo/Documents/VELO/aiegis-public-prep/scripts/post_push_verify.sh}"
  run_scp_in "$V_POST_PUSH_SOURCE" "$STAGING_DIR/scripts/post_push_verify.sh"
  if [[ $DRY_RUN -eq 0 ]]; then
    chmod +x "$STAGING_DIR/scripts/post_push_verify.sh"
  fi
  echo "  ✓ scripts/post_push_verify.sh (post-push faithful-clone verification)"
  # push_and_verify.sh — wraps git push + auto-invokes post_push_verify with
  # local HEAD sha so operator never has to remember EXPECTED_SHA arg.
  # V-authored lap-413 per anti-operator-memory class. sha 3c672b84.
  V_PUSH_AND_VERIFY_SOURCE="${V_PUSH_AND_VERIFY_SOURCE:-/Users/velo/Documents/VELO/aiegis-public-prep/scripts/push_and_verify.sh}"
  run_scp_in "$V_PUSH_AND_VERIFY_SOURCE" "$STAGING_DIR/scripts/push_and_verify.sh"
  if [[ $DRY_RUN -eq 0 ]]; then
    chmod +x "$STAGING_DIR/scripts/push_and_verify.sh"
  fi
  echo "  ✓ scripts/push_and_verify.sh (push wrapper with auto-verify)"
  # Also copy this stage script itself for transparency per F35
  if [[ $DRY_RUN -eq 0 ]]; then
    cp "$0" "$STAGING_DIR/scripts/$(basename "$0")"
    echo "  ✓ scripts/$(basename "$0") (transparency: how this push was assembled)"
  else
    echo "  [dry-run] cp $0 → scripts/$(basename "$0")"
  fi
}

verify_boilerplate() {
  echo "=== Verifying public boilerplate present at STAGING_DIR root ==="
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  [dry-run] verify step skipped"
    return
  fi
  for f in "${V_PUBLIC_BOILERPLATE[@]}"; do
    if [[ ! -f "$STAGING_DIR/$f" ]]; then
      echo "FATAL: missing $f at staging root"
      exit 1
    fi
    echo "  ✓ $f"
  done
}

main() {
  mkdirs
  cp_v_boilerplate
  cp_gitignore
  cp_ci_workflow
  cp_n_specs
  cp_v_specs
  cp_n_substrate
  cp_v_compliance
  cp_sdk
  cp_v_docs
  cp_pre_push_gate
  verify_boilerplate
  echo ""
  echo "=== Staging complete. Next steps (from $STAGING_DIR): ==="
  echo "  cd $STAGING_DIR"
  echo "  git init -b main"
  echo "  git add ."
  echo "  git status   # REVIEW before committing"
  echo "  git commit -m 'Initial public release: did:aiegis substrate-anchored AI agent identity'"
  echo "  git remote add origin git@github.com:AiEGIS-ie/aiegis.git"
  echo "  git push -u origin main"
  echo ""
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "=== DRY RUN: no files modified. Re-run without --dry-run to stage. ==="
  fi
}

main "$@"
