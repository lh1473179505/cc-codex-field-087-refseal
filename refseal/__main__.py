"""CLI. inspect already works; admit is the piece to implement."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from refseal.load import LoadError, load_json
def build_parser():
    p=argparse.ArgumentParser(prog="refseal")
    sub=p.add_subparsers(dest="cmd", required=True)
    ins=sub.add_parser("inspect"); ins.add_argument("--update", required=True)
    adm=sub.add_parser("admit")
    adm.add_argument("--update", required=True); adm.add_argument("--policy", required=True)
    adm.add_argument("--keys", required=True); adm.add_argument("--report", required=True)
    return p
def main(argv=None)->int:
    args=build_parser().parse_args(argv)
    try: update=load_json(args.update)
    except (LoadError, OSError) as exc:
        print(f"failed to load update: {exc}", file=sys.stderr); return 2
    if args.cmd=="inspect":
        print(json.dumps({"ref":update.get("ref"),"old_oid":update.get("old_oid"),"new_oid":update.get("new_oid"),
                          "object_count":len(update.get("objects") or {})}, indent=2)); return 0
    try:
        policy=load_json(args.policy); keys=load_json(args.keys)
    except (LoadError, OSError) as exc:
        print(f"failed to load policy or keys: {exc}", file=sys.stderr); return 2
    from refseal.engine import admit
    try: report=admit(update, policy, keys)
    except NotImplementedError as exc:
        print(str(exc), file=sys.stderr); return 2
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    d=str(report.get("decision","")).lower()
    if d=="allow": return 0
    if d=="deny": return 1
    print("report is missing a decision of allow or deny", file=sys.stderr); return 2
if __name__=="__main__":
    raise SystemExit(main())
