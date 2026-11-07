# Counterfactual replay design

The log schema is intentionally small: `start`, `tool_call`, `tool_result`, and `finalize`. Each record stores a sequence number, stable ID, JSON payload, prior hash, and SHA-256 checksum. Canonical JSON is necessary for stable checksums across runs. All content remains local and synthetic.

`replay(trace, up_to)` validates the full checksum chain and then reconstructs the state through the chosen prefix; it never sends a request to the tool named in the trace. The decision reducer considers **structured severity fields** from correlated tool responses. Untrusted summary text is not evaluated as executable instructions.

`fork_trace` creates new records with the exact same calls and identifiers, changing one result, then recomputes checksums. `compare_traces` distinguishes (a) semantically changed payloads from (b) subsequent records whose checksum changed only because their predecessor changed.

## Future production extensions

Instrument actual agent runtime spans and tool responses, implement schema versioning and PII minimization, store append-only audit envelopes with cryptographic provenance, support sandboxed replay of selected pure tools, and evaluate counterfactual behavior with recorded fixtures under consent.
