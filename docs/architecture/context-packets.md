# Context packets

Context packets are an opt-in worker-context dispatch primitive for graph runs that have more shared state than any one worker should read.

They are deliberately **non-generative**. The dispatcher does not ask an LLM to summarize global state. Instead, a node explicitly declares the shared-buffer keys it needs; Hive admits those values whole under a hard worker-facing character budget, binds them to the worker and goal with SHA-256 digests, and records what was omitted.

## Node contract

`NodeSpec` allows extra fields, so a worker can opt in without changing existing graph definitions:

```json
{
  "id": "proposal_writer",
  "name": "Proposal writer",
  "input_keys": ["work_order"],
  "context_keys": ["work_order", "buyer_requirements", "source_ledger", "pricing_constraints"],
  "context_required_keys": ["work_order", "buyer_requirements"],
  "context_char_budget": 12000
}
```

`context_keys` is ordered: required keys are admitted first, then optional keys retain declaration order as their priority. With no `context_keys`, packet dispatch is disabled and behavior is unchanged.

`context_char_budget` is a **worker-facing rendered-prompt bound**, not merely a sum of value sizes. Packet framing, integrity fields, entry labels, and values must all fit. Required context that cannot fit with the packet envelope fails closed; optional entries are admitted whole only when the complete rendered packet remains within the bound.

When enabled, the orchestrator:

1. reads the declared values from the shared buffer;
2. recursively screens mapping keys for credential-like names before any value can be emitted;
3. canonicalizes JSON with sorted object keys and rejects non-finite numbers;
4. hashes every admitted value and every serializable budget-omitted value;
5. admits required entries before optional entries;
6. admits optional values whole or omits them whole — never truncates a fact;
7. binds packet identity to the target worker and current goal;
8. renders admitted entries as canonical JSON so key/value control characters cannot create new prompt frames;
9. injects the bounded packet block into the worker narrative; and
10. exposes the same structured packet at `input_data["_context_packet"]`.

## Failure semantics

Required context fails closed. Execution does not proceed when a required key is missing, cannot be represented as canonical JSON, contains a credential-like mapping key at any nested depth, or cannot fit inside the complete rendered packet budget.

Optional context is recorded in the structured packet's `omissions` with a reason:

- `missing` — the key was not present;
- `budget` — admitting the whole entry would make the rendered worker packet exceed the configured budget;
- `non_json` — the value could not be represented as canonical JSON;
- `sensitive_key` — either the selected key or a nested mapping key looks like credential material, so the whole entry is fenced.

A `budget` omission carries the value SHA-256 and character count. The digest is an integrity identifier only; workers are explicitly told not to infer omitted content from it.

Detailed omission records remain available to programmatic consumers in `_context_packet`. The worker-facing prompt renders only a compact omission count/reason summary. This prevents long or control-bearing omitted key names from consuming the prompt budget or manufacturing prompt sections.

## Credential boundary

Context packets are not a credential transport. Key names associated with passwords, API keys, access/refresh/auth tokens, private keys, cookies, authorization headers, secrets, or credentials are fenced before values are rendered. Screening is recursive across nested dictionaries and list/tuple containers and normalizes snake-case, kebab-case, camelCase, and PascalCase names (for example `access_token`, `accessToken`, and `ClientSecret`). If such material appears in a required entry, packet construction fails rather than leaking it.

This is intentionally a key-name boundary, not heuristic secret-value scanning: generic prose is not classified by guessing whether a string "looks secret." Use Hive's existing credential/account path for authenticated integrations.

## Prompt-boundary model

The worker narrative receives one packet block whose exact rendered length is checked against `context_char_budget`. Admitted entries are serialized as canonical JSON inside that block. Context key names and string values therefore cannot introduce literal newline-delimited headings or closing/opening packet markers through embedded control characters.

The structured `_context_packet` representation is for programmatic consumers and retains exact requested/required keys plus omission metadata. The hard character bound applies to the worker-facing rendered packet, which is the context-window and prompt-injection boundary this feature controls.

## Integrity model

Each admitted entry has a SHA-256 of its canonical JSON. The packet has its own SHA-256 over the complete logical body (worker identity, goal digest, requested/required keys, budget accounting, entries, and omission metadata).

This provides deterministic replay checks and makes accidental mutation detectable without pretending that a hash grants authority or proves source truth.

## What this does not do

Context packets do not provide cross-run persistence, remote transport, retrieval/ranking, source verification, semantic summarization, or credential transport. Those can sit upstream of this primitive. The packet's job is narrower: **take an already selected task slice and hand it to one worker with a hard worker-facing size boundary and an auditable identity**.
