"""
CLI: `python -m aiegis_agent <command>` or via console script `aiegis-agent`.

Subcommands:
  create <name>          — create or load agent identity
  list                   — list known agents
  show <name>            — print agent metadata
  delete <name>          — remove agent (irreversible)
  sign <name> <file>     — sign file bytes, print hex signature
  passport <name>        — emit signed passport JSON to stdout
  doctor                 — health-check compliance-bundle integration
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aiegis_agent import __version__, create_agent
from aiegis_agent import _storage
from aiegis_agent.errors import AiegisError


def _cmd_create(args: argparse.Namespace) -> int:
    agent = create_agent(args.name, operator_id=args.operator_id)
    print(f"name:           {agent.name}")
    print(f"did:            {agent.did}")
    print(f"public_key_hex: {agent.public_key_hex}")
    print(f"operator_id:    {agent.operator_id or '(none)'}")
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    agents = _storage.list_agents()
    if not agents:
        print("no agents")
        return 0
    for a in agents:
        print(f"{a.name}\t{a.did}\t{a.operator_id or '(none)'}")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    a = _storage.load(args.name)
    if a is None:
        print(f"no agent: {args.name}", file=sys.stderr)
        return 1
    out = {
        "name": a.name,
        "did": a.did,
        "public_key_hex": a.public_key_hex,
        "operator_id": a.operator_id,
        "created_at": a.created_at,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def _cmd_delete(args: argparse.Namespace) -> int:
    if not args.yes:
        print(f"refusing to delete {args.name} without --yes", file=sys.stderr)
        return 2
    deleted = _storage.delete(args.name)
    print("deleted" if deleted else "no-op (agent not found)")
    return 0 if deleted else 1


def _cmd_sign(args: argparse.Namespace) -> int:
    payload = Path(args.file).read_bytes()
    agent = create_agent(args.name)  # idempotent load
    print(agent.sign(payload).hex())
    return 0


def _cmd_doctor(_args: argparse.Namespace) -> int:
    """Health-check the compliance-bundle integration. Customer-onboarding
    helper — call BEFORE first build_compliance_bundle to surface missing
    AIEGIS_COMPLIANCE_PATH at deploy-time instead of call-time."""
    from aiegis_agent import compliance
    return compliance._main_doctor()


def _cmd_passport(args: argparse.Namespace) -> int:
    agent = create_agent(args.name)
    print(json.dumps(agent.passport(risk_classification=args.risk), indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aiegis-agent", description=__doc__)
    p.add_argument("--version", action="version", version=f"aiegis-agent {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("create", help="create or load agent identity")
    pc.add_argument("name")
    pc.add_argument("--operator-id", default=None)
    pc.set_defaults(func=_cmd_create)

    pl = sub.add_parser("list", help="list known agents")
    pl.set_defaults(func=_cmd_list)

    psh = sub.add_parser("show", help="print agent metadata")
    psh.add_argument("name")
    psh.set_defaults(func=_cmd_show)

    pd = sub.add_parser("delete", help="remove agent (irreversible)")
    pd.add_argument("name")
    pd.add_argument("--yes", action="store_true", help="confirm deletion")
    pd.set_defaults(func=_cmd_delete)

    ps = sub.add_parser("sign", help="sign file bytes")
    ps.add_argument("name")
    ps.add_argument("file")
    ps.set_defaults(func=_cmd_sign)

    pdoc = sub.add_parser("doctor", help="health-check compliance-bundle integration")
    pdoc.set_defaults(func=_cmd_doctor)

    pp = sub.add_parser("passport", help="emit signed passport JSON")
    pp.add_argument("name")
    pp.add_argument("--risk", default="minimal", choices=["minimal", "limited", "high", "critical"])
    pp.set_defaults(func=_cmd_passport)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except AiegisError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except ImportError as e:
        # Compliance integration mis-configured (e.g. AIEGIS_COMPLIANCE_PATH).
        # Surface as a friendly one-liner instead of a traceback; exit 1 so
        # CI catches deploy-time mis-config. (Nel regression-catch.)
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
