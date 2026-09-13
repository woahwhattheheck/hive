# Context packets

Context packets are an opt-in worker-context dispatch primitive for graph runs that have more shared state than any one worker should read.

They are deliberately **non-generative**. The dispatcher does not ask an LLM to summarize global state. Instead, a node explicitly declares the shared-buffer keys it needs; Hive admits those values whole under a fixed character budget, binds them to the worker and goal with SHA-256 digests, and records what was omitted.

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

When enabled, the orchestrator:

1. reads the declared values from the shared buffer;
2. canonicalizes JSON with sorted object keys and rejects non-finite numbers;
3. hashes every admitted value and every serializable budget-omitted value;
4. admits required entries before optional entries;
5. admits optional values whole or omits them whole — never truncates a fact;
6. binds packet identity to the target worker and current goal;
7. injects a compact packet block into the worker narrative; and
8. exposes the same structured packet at `input_data["_context_packet"]`.

## Failure semantics

Required context fails closed. Execution does not proceed when a required key is missing, cannot be represented as canonical JSON, is credential-like, or cannot fit inside the configured budget.

Optional context is recorded in `omissions` with a reason:

- `missing` — the key was not present;
- `budget` — the whole canonical value would exceed the remaining budget;
- `non_json` — the value could not be represented as canonical JSON;
- `sensitive_key` — the key looks like credential material and is never emitted.

A `budget` omission carries the value SHA-256 and character count. The digest is an integrity identifier only; workers are explicitly told not to infer omitted content from it.

## Credential boundary

Context packets are not a credential transport. Key names associated with passwords, API keys, access/refresh/auth tokens, private keys, cookies, authorization headers, secrets, or credentials are fenced before values are rendered. If such a key is marked required, packet construction fails rather than leaking it.

Use Hive's existing credential/account path for authenticated integrations.

## Integrity model

Each admitted entry has a SHA-256 of its canonical JSON. The packet has its own SHA-256 over the complete logical body (worker identity, goal digest, requested/required keys, budget accounting, entries, and omission metadata).

This provides deterministic replay checks and makes accidental mutation detectable without pretending that a hash grants authority or proves source truth.

## What this does not do

Context packets do not provide cross-run persistence, remote transport, retrieval/ranking, source verification, or semantic summarization. Those can sit upstream of this primitive. The packet's job is narrower: **take an already selected task slice and hand it to one worker with a hard size boundary and an auditable identity**.
