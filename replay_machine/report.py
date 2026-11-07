"""Offline trace comparison in a readable self-contained HTML timeline."""
from html import escape


def render(original: list[dict], fork: dict, comparison: dict) -> str:
    before_changes = set(comparison["semantic_changes"])
    rows = []
    for a,b in zip(original,fork['events']):
        changed = a['id'] in before_changes
        action = escape(a['kind'].replace('_',' '))
        old = escape(str(a['payload'].get('severity','—')))
        new = escape(str(b['payload'].get('severity','—')))
        old_summary = escape(str(a['payload'].get('summary','')))
        new_summary = escape(str(b['payload'].get('summary','')))
        rows.append(f'<tr class="{"changed" if changed else ""}"><td>{escape(a["id"])}</td><td>{action}</td><td>{old}<small>{old_summary}</small></td><td>{new}<small>{new_summary}</small></td><td>{"Forked" if changed else "Same payload"}</td></tr>')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent Replay Time Machine · Incident fork</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{background:#081e23;color:#eaf9f6;margin:0;font:16px/1.55 system-ui,sans-serif}}main{{max-width:1090px;margin:auto;padding:clamp(20px,5vw,60px)}}.eyebrow{{color:#94f0d7;letter-spacing:.17em;font-weight:750;text-transform:uppercase;font-size:.77rem}}h1{{font-size:clamp(2rem,5vw,3.7rem);line-height:1.1;margin:14px 0}}p{{color:#b0d2d0;max-width:80ch}}.branches{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin:32px 0}}.branch,.panel{{background:#102f35;border:1px solid #326469;border-radius:16px;padding:22px}}.result{{font-size:2rem;font-weight:750}}.sub{{color:#a3c5c2}}.arrow{{color:#94f0d7}}.changed{{background:#273e3a}}table{{width:100%;border-collapse:collapse;text-align:left}}td,th{{padding:12px;border-bottom:1px solid #365e61;vertical-align:top}}td small{{display:block;color:#b9cfcd;font-size:.83rem;margin-top:5px;max-width:35ch}}.scroll{{overflow:auto}}.panel{{margin:22px 0}}code{{overflow-wrap:anywhere;color:#b0f7e4}}footer{{font-size:.85rem;color:#acc8c6;margin:32px 0}}</style></head><body><main>
<div class="eyebrow">Deterministic incident replay / counterfactual branch</div><h1>Agent Replay Time Machine</h1><p>What if one tool response had been different? Replay the same synthetic incident with a substituted recorded result; compare evidence, outcome and the SHA-256 checksum chain. No agents or external tools are executed.</p>
<div class="branches"><section class="branch"><span class="sub">Original incident</span><div class="result">{escape(str(comparison['before']))}</div><p>Cited results: {escape(', '.join(comparison['before_citations']))}</p></section><section class="branch"><span class="sub">Counterfactual fork</span><div class="result arrow">{escape(str(comparison['after']))}</div><p>Cited results: {escape(', '.join(comparison['after_citations']))}</p></section></div>
<section class="panel"><h2>Event-by-event comparison</h2><p>Only one event payload was substituted; downstream checksum changes are expected because the chain is linked.</p><div class="scroll"><table><thead><tr><th>Event</th><th>Type</th><th>Original</th><th>Fork</th><th>Payload diff</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>
<section class="panel"><h2>Reproducibility markers</h2><p>Original head: <code>{escape(fork['parent_head'])}</code></p><p>Fork head: <code>{escape(fork['head'])}</code></p><p>Rehashed suffix length: <strong>{len(comparison['hash_changes'])}</strong> · Semantic changes: <strong>{len(comparison['semantic_changes'])}</strong></p></section>
<footer>Checksum chaining is not authentication: an attacker who can rewrite the trace can also recompute every hash. This is a deterministic rule-based simulator, not an LLM or a record of actual customer incidents. Counterfactual branch outcomes do not establish real-world causality.</footer></main></body></html>'''
