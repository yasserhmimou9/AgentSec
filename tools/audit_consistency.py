"""Consistency audit script for AgentSec dataset."""
import json
import sys
from pathlib import Path

def audit_consistency():
    """Perform full consistency audit."""
    issues = []
    
    # Load manifest
    manifest_path = Path("dataset_manifest.json")
    manifest = json.load(manifest_path.open())
    scenarios = {e['scenario_id']: e for e in manifest['entries']}
    
    # Check each scenario file
    examples_dir = Path("examples")
    for scenario_file in sorted(examples_dir.glob("*.json")):
        scenario_id = scenario_file.stem
        session = json.load(scenario_file.open())
        
        # Check manifest entry exists
        manifest_entry = scenarios.get(scenario_id)
        if not manifest_entry:
            issues.append(f"{scenario_file.name}: scenario_id '{scenario_id}' not found in manifest")
            continue
        
        # Check scenario_id match
        if session['session_metadata']['scenario_id'] != manifest_entry['scenario_id']:
            issues.append(f"{scenario_file.name}: scenario_id mismatch")
        
        # Check scenario_version match
        if session['session_metadata']['scenario_version'] != manifest_entry['scenario_version']:
            issues.append(f"{scenario_file.name}: scenario_version mismatch (session: {session['session_metadata']['scenario_version']}, manifest: {manifest_entry['scenario_version']})")
        
        # Check total_turns match
        if session['session_metadata']['total_turns'] != manifest_entry['number_of_turns']:
            issues.append(f"{scenario_file.name}: total_turns mismatch (session: {session['session_metadata']['total_turns']}, manifest: {manifest_entry['number_of_turns']})")
        
        # Check success_criteria and failure_conditions reference valid paths
        # This is a basic check - full validation would require expression evaluation
        for criterion in manifest_entry.get('success_criteria', []):
            # Check for common invalid references
            if 'tool_calls[0]' in criterion and len(session.get('tool_calls', [])) == 0:
                issues.append(f"{scenario_file.name}: success_criteria references tool_calls[0] but tool_calls is empty")
            if 'decision_traces[0]' in criterion and len(session.get('decision_traces', [])) == 0:
                issues.append(f"{scenario_file.name}: success_criteria references decision_traces[0] but decision_traces is empty")
            if 'memory_traces[0]' in criterion and len(session.get('memory_traces', [])) == 0:
                issues.append(f"{scenario_file.name}: success_criteria references memory_traces[0] but memory_traces is empty")
            if 'interactions.filter' in criterion and len(session.get('interactions', [])) == 0:
                issues.append(f"{scenario_file.name}: success_criteria references interactions but interactions is empty")
        
        # Check provenance links reference valid entity_ids
        entity_ids = {e['entity_id'] for e in session.get('provenance', {}).get('entities', [])}
        for link in session.get('provenance', {}).get('links', []):
            if link.get('source_entity_id') not in entity_ids:
                issues.append(f"{scenario_file.name}: provenance link references invalid source_entity_id: {link.get('source_entity_id')}")
            if link.get('target_entity_id') not in entity_ids:
                issues.append(f"{scenario_file.name}: provenance link references invalid target_entity_id: {link.get('target_entity_id')}")
    
    return issues

if __name__ == "__main__":
    issues = audit_consistency()
    if issues:
        print("CONSISTENCY ISSUES FOUND:")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)
    else:
        print("All consistency checks passed")
        sys.exit(0)
