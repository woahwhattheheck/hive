# Context packets

Context packets are an opt-in worker-context dispatch primitive for graph runs that have more shared state than any one worker should read.

They are deliberately **non-generative**. The dispatcher does not ask an LLM to summarize global state. Instead, a node explicitly declares shared-buffer keys it is already allowed to read; Hive admits those values whole under hard worker-facing and complete-packet character bounds, binds them to the worker and goal with SHA-256 digests, and records what was omitted.

## Node contract

`NodeSpec` allows extra fields, so a worker can opt in without changing existing graph definitions:

```json
{
  "id": "proposal_writer",
  "name": "Proposal writer",
  "input_keys": ["work_order", "buyer_requirements", "source_ledger", "pricing_constraints"],
  "context_keys": ["work_order", "buyer_requirements", "source_ledger", "pricing_constraints"],
  "context_required_keys": ["work_order", "buyer_requirements"],
  "context_char_budget": 12000,
  "context_packet_max_chars": 16384
}
```

`context_keys` is ordered: required keys are admitted first, then optional keys retain declaration order as their priority. With no `context_keys`, packet dispatch is disabled and behavior is unchanged.

For a node with explicit `input_keys`, every `context_key` must already be in that exact allow-set. Packet selection cannot be used as a second path around scoped-buffer permissions, and naming a key with a leading underscore does not create framework provenance or read authority. A framework metadata key remains available only when it is explicitly present in `input_keys`. Nodes whose existing DataBuffer contract has an empty read allow-set keep that existing unrestricted-read behavior; context packets do not silently change DataBuffer semantics.

Two independent size controls apply:

- `context_char_budget` (default 12,000) is a **worker-facing rendered-prompt bound**, not merely a sum of value sizes. Packet framing, integrity fields, entry labels, and values must all fit.
- `context_packet_max_chars` (default 16,384, framework hard maximum 32,768) bounds both the rendered packet and the canonical structured `_context_packet` JSON. Requested/required key lists and omission metadata therefore cannot grow without bound while the visible payload remains tiny.

Required context that cannot fit either applicable bound fails closed. Optional entries are admitted whole only when both packet forms remain within their configured bounds.

When enabled, the orchestrator:

1. checks declared packet keys against the node's existing effective shared-buffer read authority;
2. reads only authorized values from the shared buffer;
3. recursively screens mapping keys for credential-like names before any value can be emitted;
4. canonicalizes JSON with sorted object keys and rejects non-finite numbers;
5. hashes every admitted value and every serializable budget-omitted value;
6. admits required entries before optional entries;
7. admits optional values whole or omits them whole — never truncates a fact;
8. binds packet identity to the target worker and current goal;
9. renders admitted entries as canonical JSON so key/value control characters cannot create new prompt frames;
10. checks both worker render size and complete structured packet size; and
11. injects the bounded packet block into the worker narrative while exposing the same structured packet at `input_data["_context_packet"]`.

## Failure semantics

Required context fails closed. Execution does not proceed when a required key is missing, cannot be represented as canonical JSON, contains a credential-like mapping key at any nested depth, is outside an explicitly scoped node's read authority, or cannot fit inside the configured packet bounds.

Optional context is recorded in the structured packet's `omissions` with a reason:

- `missing` — the key was not present;
- `budget` — admitting the whole entry would make a packet representation exceed an applicable bound;
- `non_json` — the value could not be represented as canonical JSON;
- `sensitive_key` — either the selected key or a nested mapping key looks like credential material, so the whole entry is fenced.

A `budget` omission carries the value SHA-256 and character count. The digest is an integrity identifier only; workers are explicitly told not to infer omitted content from it.

Detailed omission records remain available to programmatic consumers in `_context_packet`. The worker-facing prompt renders only a compact omission count/reason summary. This prevents long or control-bearing omitted key names from consuming the prompt budget or manufacturing prompt sections. Complete structured-packet sizing separately prevents those same metadata fields from becoming an unbounded programmatic handoff.

Context-key declarations are also bounded before packet metadata is constructed: at most 128 distinct requested keys are accepted, and the combined requested/required key text cannot exceed the framework's 32,768-character hard packet ceiling. Individual long-key prompt hostiles remain representable when the caller explicitly chooses a complete-packet ceiling large enough for their duplicated structured metadata.

## Credential boundary

Context packets are not a credential transport. Key names associated with passwords, API keys, access/refresh/auth tokens, private keys, cookies, authorization headers, secrets, or credentials are fenced before values are serialized or rendered. Screening is recursive across nested dictionaries and list/tuple containers and normalizes snake-case, kebab-case, camelCase, and PascalCase names (for example `access_token`, `accessToken`, and `ClientSecret`). If such material appears in a required entry, packet construction fails rather than leaking it.

This is intentionally a key-name boundary, not heuristic secret-value scanning: generic prose is not classified by guessing whether a string "looks secret." Use Hive's existing credential/account path for authenticated integrations.

## Prompt-boundary model

The worker narrative receives one packet block whose exact rendered length is checked against `context_char_budget` and `context_packet_max_chars`. Admitted entries are serialized as canonical JSON inside that block. Context key names and string values therefore cannot introduce literal newline-delimited headings or closing/opening packet markers through embedded control characters.

The structured `_context_packet` representation is for programmatic consumers and retains exact requested/required keys plus omission metadata. Its canonical JSON length is independently checked against `context_packet_max_chars`; a small rendered prompt cannot hide an unbounded structured handoff.

## Integrity model

Each admitted entry has a SHA-256 of its canonical JSON. The packet has its own SHA-256 over the complete logical body (worker identity, goal digest, both configured bounds, requested/required keys, budget accounting, entries, and omission metadata).

This provides deterministic replay checks and makes accidental mutation detectable without pretending that a hash grants authority or proves source truth.

## What this does not do

Context packets do not provide cross-run persistence, remote transport, retrieval/ranking, source verification, semantic summarization, or credential transport. Those can sit upstream of this primitive. The packet's job is narrower: **take an already authorized task slice and hand it to one worker with hard worker-facing and complete-packet size boundaries plus an auditable identity**.
