"""Build an immutable toy trace and generate a counterfactual replay report."""
import argparse
import json
from pathlib import Path
from .engine import build_trace, compare_traces, fork_trace, replay
from .report import render


def main() -> None:
    p=argparse.ArgumentParser(description="Offline agent time-machine demo")
    p.add_argument("command",choices=["demo"])
    p.add_argument("--scenario",type=Path,default=Path(__file__).resolve().parents[1]/"fixtures"/"incident.json")
    p.add_argument("--out",type=Path,default=Path("examples/replay_report.html"))
    p.add_argument("--trace-out",type=Path,default=Path("examples/trace.json"))
    a=p.parse_args()
    cfg=json.loads(a.scenario.read_text(encoding="utf-8"))
    original=build_trace(cfg['actions'])
    branch=fork_trace(original,cfg['fork_event_id'],severity=cfg['alternate_severity'],summary=cfg['alternate_summary'])
    diff=compare_traces(original,branch['events'])
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(render(original,branch,diff),encoding="utf-8")
    a.trace_out.parent.mkdir(parents=True,exist_ok=True)
    a.trace_out.write_text(json.dumps({"events":original,"branch":branch,"comparison":diff},indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"report":str(a.out),"before":replay(original)["decision"],"after":replay(branch['events'])["decision"],"semantic_changes":diff['semantic_changes'],"head":branch['head']},indent=2))


if __name__=="__main__":main()
