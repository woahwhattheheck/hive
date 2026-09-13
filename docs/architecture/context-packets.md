# Context packets

Context packets are an opt-in worker-context dispatch primitive for graph runs that have more shared state than any one worker should read.

They are deliberately **non-generative**. The dispatcher does not ask an LLM to summarize global state. Instead, a node explicitly declares a subset of the shared-buffer keys it is already authorized to read; Hive admits those values whole under a payload budget, binds them to the worker and goal with SHA-256 digests, and records what was omitted.

## Node contract

`NodeSpec` allows extra fields, so an existing graph can opt in without changing legacy node definitions:

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

**Context selection is not a new read capability.** When a node has a scoped shared-buffer boundary, every `context_keys` entry must already be inside that effective read boundary. A context-packet declaration that attempts to name another global key fails closed before node dispatch. Existing framework-managed `_` keys retain the same effective scoping rule as the normal node buffer.

When enabled, the orchestrator:

1. checks the requested packet keys against the node's existing buffer-read authority;
2. reads only an authorized task slice from the shared buffer;
3. recursively fences credential-shaped object fields before a value can be rendered;
4. canonicalizes JSON with sorted object keys and rejects non-finite numbers;
5. hashes every admitted value and every serializable budget-omitted value;
6. admits required entries before optional entries;
7. admits optional values whole or omits them whole — never truncates a fact;
8. binds packet identity to the target worker and current goal;
9. enforces a hard maximum over both the structured packet and worker narrative representation;
10. injects a compact packet block into the worker narrative; and
11. exposes the same structured packet at `input_data["_context_packet"]`.

## Two size boundaries

`context_char_budget` is the **payload admission budget**. It counts canonical characters of admitted values and preserves the original whole-value admission behavior.

`context_packet_max_chars` is the **complete representation ceiling**. Hive verifies both:

- canonical JSON for the structured packet stored at `input_data["_context_packet"]`; and
- the rendered worker narrative block.

Neither representation may exceed the configured ceiling. The configured ceiling itself is capped by a framework hard maximum of 32,768 characters, and packet key count/key length are bounded before metadata construction. This prevents a large requested/required/omission list from exhausting prompt context even when `payload_chars` is zero.

The default complete representation ceiling is 16,384 characters.

## Failure semantics

Required context fails closed. Execution does not proceed when a required key is missing, outside the node's read authority, cannot be represented as canonical JSON, contains credential-shaped material, or cannot fit inside the configured payload/representation bounds.

A context-packet configuration that names any key outside a scoped node's read authority also fails closed; optional context cannot be used to smuggle a wider read capability.

Optional context is recorded in `omissions` with a reason:

- `missing` — the authorized key was not present;
- `budget` — the whole canonical value would exceed the remaining payload budget;
- `non_json` — the value could not be represented as canonical JSON;
- `sensitive_key` — the selected top-level key looks like credential material;
- `sensitive_value` — a nested JSON object key looks like credential material, so the whole optional value is omitted.

A `budget` omission carries the value SHA-256 and character count. The digest is an integrity identifier only; workers are explicitly told not to infer omitted content from it. Sensitive omissions deliberately do not carry a digest of secret-bearing content.

## Credential boundary

Context packets are not a credential transport. Key names associated with passwords, API keys, access/refresh/auth tokens, private keys, cookies, authorization headers, secrets, or credentials are fenced before values are rendered.

The same test is applied recursively inside nested objects and arrays. For example, a safe-looking outer key such as `integration_config` is still fenced when it contains `{"auth": {"api_key": "..."}}`.

If credential-shaped material is required, packet construction fails rather than leaking it. If it is optional, the entire value is omitted without rendering the nested secret.

Use Hive's existing credential/account path for authenticated integrations.

## Integrity model

Each admitted entry has a SHA-256 of its canonical JSON. The packet has its own SHA-256 over the complete logical body (worker identity, goal digest, requested/required keys, payload budget, complete packet ceiling, entries, and omission metadata).

This provides deterministic replay checks and makes accidental mutation detectable without pretending that a hash grants authority or proves source truth.

## What this does not do

Context packets do not provide cross-run persistence, remote transport, retrieval/ranking, source verification, semantic summarization, or additional buffer-read authority. Those can sit upstream of this primitive.

The packet's job is narrower: **take an already authorized task slice and hand it to one worker with auditable identity and hard worker-facing size bounds**.
