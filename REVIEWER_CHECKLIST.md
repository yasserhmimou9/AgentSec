# Reviewer Sanity Checklist

This document provides step-by-step instructions for reviewers to verify the AgentSec dataset's reproducibility, validity, and evaluation procedures.

## Prerequisites

- Python 3.8+ (tested with Python 3.12)
- Node.js 16+ (for AJV validation)
- npm (for installing AJV)

## 1. Regenerate the Dataset

**Objective**: Verify that the **published dataset (30 scenarios)** is internally consistent and schema-valid.

**Steps**:
```bash
# Install dependencies
pip install -r requirements.txt
npm install

# Validate all scenarios with AJV (recommended)
# On Linux/Mac:
for file in examples/*.json; do
  node tools/validate_with_ajv.mjs schema/session_schema.json "$file"
done

# On Windows (PowerShell):
# Get-ChildItem examples\*.json | ForEach-Object { node tools/validate_with_ajv.mjs schema/session_schema.json $_.FullName }

# Cross-file consistency (manifest ↔ scenarios, provenance IDs)
python tools/audit_consistency.py
```

**Expected Output**:
- 30 JSON files in `examples/` directory
- `dataset_manifest.json` contains 30 entries
- AJV validation passes for all scenario files (exit code 0)
- `tools/audit_consistency.py` prints: "All consistency checks passed" (exit code 0)

**Verification**:
- Validate all scenario files with AJV (no schema errors)
- Run `tools/audit_consistency.py` (no manifest/provenance mismatches)

**Failure Indicators**:
- Missing files
- AJV validation errors
- Consistency issues reported by `tools/audit_consistency.py`

## 1b. (Optional) Regenerate the baseline generator subset

**Objective**: Verify that the repository’s generator reproduces its **baseline subset** deterministically (seed=1234).

**Steps**:
```bash
# WARNING: This will overwrite dataset_manifest.json with the generator-produced manifest.
python dataset_generator.py
```

**Expected Output**:
- The generator rewrites its baseline scenario files under `examples/`
- Console message: "Wrote sessions to examples/ and manifest to dataset_manifest.json"

## 2. Validate a Scenario File

**Objective**: Verify that scenario files conform to the frozen schema.

**Steps**:
```bash
# Validate a single scenario file
node tools/validate_with_ajv.mjs schema/session_schema.json examples/scenario-success-tool-success.json
```

**Expected Output**:
- Exit code: 0
- No error messages

**Alternative (validate all)**:
```bash
# Validate all scenario files
for file in examples/*.json; do
  node tools/validate_with_ajv.mjs schema/session_schema.json "$file"
done
```

**Failure Indicators**:
- Exit code: 1
- JSON validation errors in stderr
- Schema violation messages

## 3. Verify Determinism

**Objective**: Confirm that the same seed produces identical outputs.

**Steps**:
```bash
# Validate published dataset twice (hashes should match)

# Compare outputs (example using checksums)
# On Linux/Mac:
sha256sum examples/*.json dataset_manifest.json > checksums1.txt
sha256sum examples/*.json dataset_manifest.json > checksums2.txt
diff checksums1.txt checksums2.txt

# On Windows (PowerShell):
Get-FileHash examples/*.json, dataset_manifest.json | Format-Table
# Run again and compare hashes
```

**Expected Output**:
- All file hashes are identical between runs
- `diff` shows no differences (or PowerShell comparison shows identical hashes)

**Failure Indicators**:
- Different hashes between runs
- Non-deterministic UUIDs, timestamps, or content

## 4. Evaluate One Scenario Using Success Criteria

**Objective**: Demonstrate how to evaluate a scenario using the machine-checkable criteria in the manifest.

**Example Scenario**: `scenario-success-tool-success`

**Steps**:

1. **Load the scenario and manifest**:
```python
import json

# Load scenario
with open('examples/scenario-success-tool-success.json') as f:
    session = json.load(f)

# Load manifest
with open('dataset_manifest.json') as f:
    manifest = json.load(f)

# Find scenario entry
entry = next(e for e in manifest['entries'] 
             if e['scenario_id'] == 'scenario-success-tool-success')
```

2. **Evaluate success criteria** (example checks):
```python
# Check: decision_traces.length >= 1
assert len(session['decision_traces']) >= 1, "Missing decision traces"

# Check: tool_calls.length >= 1
assert len(session['tool_calls']) >= 1, "Missing tool calls"

# Check: tool_calls[0].status == 'succeeded'
assert session['tool_calls'][0]['status'] == 'succeeded', "Tool call failed"

# Check: memory_traces.length >= 1
assert len(session['memory_traces']) >= 1, "Missing memory traces"

# Check: state_traces.length >= 1
assert len(session['state_traces']) >= 1, "Missing state traces"

# Check: provenance.entities.length >= 4
assert len(session['provenance']['entities']) >= 4, "Insufficient provenance entities"

# Check: provenance.links.length >= 4
assert len(session['provenance']['links']) >= 4, "Insufficient provenance links"

# Check: interactions.filter(i => i.role == 'assistant').length >= 2
assistant_interactions = [i for i in session['interactions'] 
                          if i['role'] == 'assistant']
assert len(assistant_interactions) >= 2, "Insufficient assistant interactions"
```

3. **Evaluate failure conditions** (should all be false):
```python
# Check: tool_calls[0].status != 'succeeded' (should be False)
assert session['tool_calls'][0]['status'] == 'succeeded', "Failure condition met: tool failed"

# Check: decision_traces.length == 0 (should be False)
assert len(session['decision_traces']) > 0, "Failure condition met: no decisions"

# Check provenance link (should exist)
decision_id = session['decision_traces'][0]['event_id']
tool_id = session['tool_calls'][0]['event_id']
triggered_links = [l for l in session['provenance']['links']
                   if l['relationship'] == 'triggered' 
                   and l['source_entity_id'] == decision_id
                   and l['target_entity_id'] == tool_id]
assert len(triggered_links) > 0, "Failure condition met: missing provenance link"
```

**Expected Output**:
- All assertions pass
- All success criteria evaluate to True
- All failure conditions evaluate to False

**Failure Indicators**:
- Assertion failures
- Success criteria evaluate to False
- Failure conditions evaluate to True

## 5. Cross-File Consistency Check

**Objective**: Verify that scenario files match manifest metadata.

**Steps**:
```bash
# Run the provided audit script
python tools/audit_consistency.py
```

**Expected Output**:
- "All consistency checks passed"
- Exit code: 0

**Failure Indicators**:
- Consistency issues reported
- Exit code: 1

## Quick Verification Summary

| Check | Command | Expected Result |
|-------|---------|----------------|
| Validate (published) | AJV loop over `examples/*.json` | Exit code 0 |
| Validate | `node tools/validate_with_ajv.mjs schema/session_schema.json examples/scenario-success-tool-success.json` | Exit code 0 |
| Determinism | Hash twice, compare | Identical hashes |
| Evaluate | Run Python evaluation script | All criteria pass |
| Consistency | `python tools/audit_consistency.py` | All checks passed |

## Troubleshooting

**Issue**: Validation fails with "additionalProperties" errors
- **Solution**: Ensure you're using AJV v8.x with the provided preprocessing (`tools/validate_with_ajv.mjs`)

**Issue**: Generated files differ from published dataset
- **Solution**: Verify Python version, Node.js version, and that seed=1234 is used

**Issue**: Evaluation criteria fail
- **Solution**: Check that you're evaluating the correct scenario file and using the correct manifest entry
