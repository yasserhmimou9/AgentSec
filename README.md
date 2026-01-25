## Deterministic Dataset Generator (Schema 1.1)

This generator produces JSON session files that **conform to** the frozen schema in `schema/session_schema.json` (schema_version = 1.1). The pipeline is deterministic, auditable, and oriented toward reproducibility.

### Determinism and auditability
- **Random seed**: Explicitly supplied; defaults to `1234`. Stored in `session_metadata.determinism.random_seed`. Same seed ⇒ identical dataset.
- **Deterministic UUIDs**: UUIDv5 derived from a namespace based on `(seed, scenario_id)` plus a monotonic counter; identical `(seed, scenario_id)` ⇒ identical IDs.
- **Timestamps**: Derived from a fixed base UTC time plus fixed offsets per event (no wall-clock dependence).
- **Hashes**: SHA256 over canonical JSON (sorted keys, compact separators) for all memory/state/provenance SHA256 fields.

### Validation contract
Validation is defined **operationally** using AJV with a deterministic preprocessing step:
- **Validator**: `ajv@8.x`
- **Options**: `strict: false`, `allErrors: true`
- **Preprocessing**: `tools/validate_with_ajv.mjs` reads the frozen schema and:
  - Resolves local `#/...` `$ref` targets.
  - For object schemas that use `allOf` to compose a shared `trace_context` with additional fields, it merges the object subschemas into a single object schema (union of `properties` and `required`, preserving `additionalProperties`).
- The on-disk schema in `schema/session_schema.json` is **never modified**; preprocessing is applied in-memory at validation time and is part of the formal dataset pipeline.

Each generated session file is validated by invoking:
- `node tools/validate_with_ajv.mjs schema/session_schema.json <session.json>`

## Dataset composition

The published dataset contains **30** scenario session files under `examples/`, indexed by `dataset_manifest.json`.

Note: `python dataset_generator.py` deterministically regenerates the repository’s baseline scenario subset (seed default `1234`). The published dataset includes additional schema-valid scenarios under `examples/` that are referenced in `dataset_manifest.json`.

### Core scenarios (4)

- **`examples/scenario-success-tool-success.json`**
  - **Scenario type**: successful decision + successful tool call.
  - **Highlights**: alternative decisions (including unselected options), successful `tool_call_event`, memory and state traces, and a provenance chain from the initial user request through decision, tool call, and final summary.

- **`examples/scenario-rejected-decision.json`**
  - **Scenario type**: rejected decision (refusal) without tool invocation.
  - **Highlights**: explicit refusal decision (`intent` = safety-oriented), unselected alternatives (e.g., “comply”), and provenance links from unsafe user request to the rejection decision and refusal response.

- **`examples/scenario-tool-failure.json`**
  - **Scenario type**: tool failure with `error` object.
  - **Highlights**: decision to run a dependency scanner, a `tool_call_event` with `status: "failed"` and a populated `error.message`, and provenance linking the failure to the assistant’s explanation of why the request could not be fully satisfied.

- **`examples/scenario-memory-noop.json`**
  - **Scenario type**: memory noop (no change).
  - **Highlights**: `memory_traces` entry with `change_type: "noop"` where `memory_before` and `memory_after` are identical and share the same `memory_hash_*`, plus provenance showing how this noop trace supports an explicit statement about memory not changing.

### Extended scenarios (6)

- **`examples/scenario-multi-tool-success.json`**
  - **Scenario type**: multi-tool-success.
  - **Highlights**: one decision triggers two sequential tool calls (structure analyzer, security scanner), both results stored in memory and synthesized in final response. Non-linear provenance with branching and convergence (≥6 entities, ≥6 links).

- **`examples/scenario-tool-success-decision-reverted.json`**
  - **Scenario type**: tool-success-but-decision-reverted.
  - **Highlights**: tool succeeds, but agent rejects its own decision after reflection (privacy concerns). Multiple `decision_traces`, explicit `rejected_by` provenance link.

- **`examples/scenario-memory-conflict.json`**
  - **Scenario type**: memory-conflict.
  - **Highlights**: `memory_before` contradicts tool output; agent detects conflict, resolves it explicitly via second decision, updates memory. Demonstrates conflict detection and resolution.

- **`examples/scenario-hallucination-detected.json`**
  - **Scenario type**: hallucination-detected.
  - **Highlights**: agent initially produces incorrect estimate, then corrects after tool verification. Multiple `decision_traces` and `interactions`, explicit error acknowledgment via `rejected_by` link.

- **`examples/scenario-partial-failure-recovery.json`**
  - **Scenario type**: partial-failure-recovery.
  - **Highlights**: first tool fails, second fallback tool succeeds. Multiple `decision_traces` and `tool_calls`, provenance shows failure-to-recovery path.

- **`examples/scenario-provenance-branching.json`**
  - **Scenario type**: provenance-branching.
  - **Highlights**: two parallel decision paths (quality analysis, security analysis) converge into one final response. Non-linear provenance structure with branching and convergence (≥7 entities, ≥9 links).

An index file, `dataset_manifest.json`, summarizes the dataset:
- `entries[]` (one per scenario), each with:
  - **`scenario_id`**: matches `session_metadata.scenario_id`.
  - **`scenario_version`**: matches `session_metadata.scenario_version`.
  - **`number_of_turns`**: mirrors `session_metadata.total_turns`.
  - **`description`**: short natural-language description of the scenario.
  - **`scientific_intent`**: research purpose and evaluation target for the scenario.

## Intended Research Uses

This dataset is designed to support research in agentic AI systems with a focus on traceability, determinism, and auditability. Primary research applications include:

- **Agent auditability**: Evaluating how well agent systems can be audited through decision traces, memory changes, and tool usage. The dataset provides ground-truth provenance graphs linking all events, enabling research on automated audit trail analysis and compliance verification.

- **Decision faithfulness**: Assessing whether agents' stated decisions (in `decision_traces`) align with their actual behavior (tool calls, memory updates, responses). Scenarios include cases where decisions are revised, rejected, or corrected, enabling research on decision-behavior consistency.

- **Tool reliance analysis**: Understanding how agents depend on tool outputs, handle tool failures, and recover from partial failures. The dataset includes successful tool chains, failure scenarios, and fallback strategies with explicit provenance linking tool results to agent responses.

- **Provenance graph reasoning**: Research on reasoning over complex causal structures in agent behavior. The dataset includes non-linear provenance graphs (branching, convergence, rejection paths) with explicit relationships (`used_by`, `triggered`, `derived_from`, `caused`), enabling research on graph-based explanation generation and causal inference.

## Derived Evaluation Metrics

The dataset enables computation of the following metrics from the session JSON files without requiring human interpretation:

### Decision Faithfulness

**Definition**: The consistency between stated decisions (`decision_traces`) and actual agent behavior (`interactions`, `tool_calls`, `memory_traces`).

**Computation**: For each `decision_trace` with `resulting_actions`, verify that:
- If `resulting_actions` includes a tool call intent, a corresponding `tool_call_event` exists with a provenance link `triggered` from the decision.
- If `resulting_actions` includes a memory update intent, a corresponding `memory_trace_event` exists with a provenance link from the decision or tool output.
- The `selected_option` in the decision aligns with the actual behavior (e.g., if `selected_option == "reject"`, no tool calls should occur).

**Formula**: `faithfulness = (decisions_with_consistent_behavior / total_decisions) * 100%`

### Tool Reliance Ratio

**Definition**: The ratio of tool calls to decisions, indicating how frequently agents depend on external tools.

**Computation**: `tool_reliance_ratio = tool_calls.length / decision_traces.length`

**Interpretation**: Values > 1 indicate multiple tools per decision (orchestration); values < 1 indicate some decisions do not trigger tools; values = 1 indicate one-to-one mapping.

### Recovery Rate After Failure

**Definition**: The proportion of failed tool calls that are followed by successful recovery (fallback tool or alternative strategy).

**Computation**: For each `tool_call` with `status == "failed"`:
- Check if a subsequent `tool_call` with `status == "succeeded"` exists in the same session.
- Verify via provenance that the failure `triggered` a decision that led to the recovery.

**Formula**: `recovery_rate = (failed_tools_with_recovery / total_failed_tools) * 100%`

### Hallucination Correction Rate

**Definition**: The proportion of incorrect initial responses that are subsequently corrected.

**Computation**: Identify sequences where:
- An `interaction_event` with `role == "assistant"` is followed by a `decision_trace` with `intent` containing "correction" or "verify".
- The correction decision `triggered` a `tool_call_event` for verification.
- A subsequent `interaction_event` explicitly acknowledges the prior error (content includes "correction", "correct", "apologize", or similar).

**Formula**: `correction_rate = (corrected_hallucinations / total_hallucinations) * 100%`

### Provenance Graph Depth and Branching Factor

**Definition**: Structural metrics of the provenance graph indicating complexity and causal depth.

**Computation**:
- **Depth**: Maximum path length from any root entity (typically user `interaction_event`) to any leaf entity (typically final assistant `interaction_event`), following `provenance.links` relationships.
- **Branching Factor**: Average number of outgoing links per entity. Compute as `total_links / unique_source_entities`.

**Algorithm for Depth**:
1. Build a directed graph from `provenance.links` (source → target).
2. Identify root nodes (entities with no incoming links from other entities in the session).
3. Perform BFS/DFS from roots to compute maximum depth to any leaf node.

**Interpretation**: Higher depth indicates longer causal chains; higher branching factor indicates more parallel decision-making or tool orchestration.

## Threats to Validity & Limitations

This section explicitly discusses limitations of the dataset that researchers should consider when interpreting results.

### Synthetic Nature of Scenarios

The dataset consists of **synthetically generated** scenarios rather than real-world agent interactions. While scenarios are designed to reflect realistic patterns (tool failures, decision revisions, memory conflicts), they may not capture the full complexity, ambiguity, or edge cases present in production agent systems. Researchers should validate findings on real-world data when possible.

### Deterministic Behavior vs. Stochastic Real-World Agents

The dataset is **fully deterministic** (same seed produces identical outputs), whereas real-world agents exhibit stochastic behavior due to:
- Non-deterministic model sampling
- Environmental variability
- User behavior unpredictability
- Network latency and timing effects

This determinism is intentional for reproducibility, but may limit generalizability to stochastic systems. Researchers should consider whether their evaluation metrics account for expected variance in real deployments.

### Schema-Driven Bias

The dataset structure is **constrained by the frozen JSON schema** (`schema/session_schema.json`). This schema:
- Requires explicit `decision_traces` for all decisions (agents may make implicit decisions).
- Enforces specific provenance relationship types (`used_by`, `triggered`, `derived_from`, `caused`, etc.).
- Mandates memory/state traces even when agents may not explicitly track these.

Agents that do not conform to this schema structure cannot be evaluated using this dataset without adaptation. The schema reflects an **idealized auditability model** that may not match all agent architectures.

### Absence of Latent/Internal (Non-Logged) Cognition

The dataset captures only **explicitly logged events** (interactions, decisions, tool calls, memory changes). It does not include:
- Internal reasoning steps not logged as `decision_traces`.
- Implicit assumptions or heuristics.
- Cognitive load or attention mechanisms.
- Partial or aborted decision processes.

Agents that rely heavily on implicit reasoning may appear less auditable under this dataset's evaluation framework, even if their behavior is correct. This limitation reflects the challenge of evaluating "black-box" cognitive processes.

### Temporal Ordering Assumptions

The dataset assumes **strict temporal ordering** via `timestamp_utc` and `turn_id`. Real-world agents may:
- Process multiple requests concurrently.
- Have non-linear execution flows.
- Experience race conditions or timing-dependent behavior.

The dataset's sequential model may not capture these complexities.

## Reproducibility Statement

This dataset is designed for **bit-identical reproducibility** to enable controlled experiments and peer review validation.

### Determinism Guarantees

**Seed-based determinism**: The dataset generator uses a fixed random seed (default: `1234`, stored in `session_metadata.determinism.random_seed`). Given the same seed:
- All UUIDs are identical (UUIDv5 derived from `(seed, scenario_id, counter)`).
- All timestamps are identical (fixed base time `2026-01-20T15:00:00Z` plus deterministic offsets).
- All SHA256 hashes are identical (canonical JSON serialization with sorted keys).
- All session structures are identical (same number of events, same field values).

**Verification**:
- The published dataset is verified by schema validation (AJV) and cross-file consistency checks (`tools/audit_consistency.py`).
- Re-running `python dataset_generator.py` with `seed=1234` deterministically reproduces the generator-defined baseline subset.

### Exact Validation Authority

**Validator specification**:
- **Tool**: AJV (Another JSON Validator) v8.x
- **Configuration**: `strict: false`, `allErrors: true`
- **Preprocessing**: Deterministic schema preprocessing in `tools/validate_with_ajv.mjs`:
  - Resolves local `#/...` `$ref` references.
  - Merges `allOf` object subschemas (for `trace_context` composition).
  - Applied in-memory; schema file remains unchanged.

**Validation command**: `node tools/validate_with_ajv.mjs schema/session_schema.json <session.json>`

**Reproducibility**: The same validator configuration and preprocessing logic must be used to validate generated sessions. Deviations (e.g., different AJV versions, different preprocessing) may yield different validation results.

### Steps to Regenerate Bit-Identical JSON Outputs

1. **Environment setup**:
   ```bash
   pip install -r requirements.txt
   npm install
   ```

2. **Generation**:
   ```bash
   python dataset_generator.py
   ```
   This uses the default seed `1234`. To use a different seed, modify `main()` in `dataset_generator.py`.

3. **Verification**:
   - Compare SHA256 hashes of generated files against published hashes (if provided).
   - Validate each generated file: `node tools/validate_with_ajv.mjs schema/session_schema.json examples/<scenario>.json`
   - Compare `dataset_manifest.json` structure and content.

4. **Expected output**: All files should be byte-identical to the published dataset when using `seed=1234`.

**Note**: Minor differences may occur due to:
- Operating system differences in file encoding (should not affect JSON content).
- Node.js version differences (AJV behavior should be consistent across v8.x).
- Python version differences (should not affect deterministic UUID/hash generation).

If bit-identical reproduction fails, report the environment details (OS, Python version, Node.js version) for investigation.

## Quickstart
```bash
pip install -r requirements.txt
npm install

# Validate all published scenarios
# On Linux/Mac:
for file in examples/*.json; do
  node tools/validate_with_ajv.mjs schema/session_schema.json "$file"
done

# Cross-file consistency (manifest ↔ scenarios, provenance IDs)
python tools/audit_consistency.py
```

Outputs:
- 30 scenario JSON files under `examples/`
- `dataset_manifest.json`

## Files
- `schema/session_schema.json` — frozen schema (do not modify).
- `dataset_generator.py` — deterministic generator and scenario definitions.
- `tools/validate_with_ajv.mjs` — AJV v8 validator plus deterministic `allOf` + local `$ref` preprocessing.
- `examples/*.json` — generated sessions (reproducible given the same seed).
- `dataset_manifest.json` — dataset index summarizing scenarios.
- `requirements.txt` — Python runtime dependencies.
- `package.json` / `package-lock.json` — Node/AJV dependencies.

## Regenerating the dataset
```bash
python dataset_generator.py
```
Re-running with the same seed yields identical content for the generator-defined subset (IDs, timestamps, hashes, and manifest entries for that subset).

## Dataset Freeze and Versioning Policy

**Dataset Version**: 1.0.0  
**Schema Version**: 1.1 (FROZEN)  
**Scenario Version**: 1.0 (FROZEN)

### Frozen Components

The following components are **frozen** and must not be modified without a major dataset version bump (2.0.0):

1. **`schema/session_schema.json`**: Frozen at version 1.1. No modifications allowed. Any schema changes require a new major dataset version.

2. **All scenario JSON files in `examples/`**: Frozen at version 1.0. These files represent the ground-truth dataset and must remain unchanged. Adding, removing, or modifying scenarios requires a new major dataset version.

3. **Deterministic generation logic**: The UUID generation algorithm, timestamp derivation, and hash computation methods are frozen. Changes to these would break reproducibility guarantees.

### Versioning Rules

- **Major version (X.0.0)**: Required for schema changes, breaking changes to scenario structure, or addition/removal of scenarios.
- **Minor version (x.Y.0)**: For non-breaking additions (new scenarios), non-breaking schema extensions, or significant metadata updates.
- **Patch version (x.y.Z)**: For bug fixes, documentation updates, or manifest corrections that do not affect scenario files or schema.

### Future Changes

Any future changes to frozen components require:
1. Incrementing the major dataset version (e.g., 1.0.0 → 2.0.0)
2. Documenting the changes in a CHANGELOG
3. Updating the schema version if schema changes are made
4. Maintaining backward compatibility documentation if possible

**Current Status**: Dataset is frozen and ready for publication. All components are locked at their current versions.
