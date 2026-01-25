"""
Deterministic dataset generator producing session JSON files intended to validate
against the frozen session schema (schema_version 1.1) using the project's
authoritative validator semantics:

- ajv@8.x
- strict: false
- allErrors: true

Design choices (traceable and auditable):
- Deterministic randomness: uses `random.Random(seed)`; seed is stored in output.
- Deterministic UUIDs: UUIDv5 derived from a namespace built from the seed,
  scenario_id, and a monotonic counter. Same seed+scenario_id => identical IDs.
- Canonical hashing: SHA256 over canonical JSON (sorted keys, compact separators).
- Validation: each generated file is validated with AJV (via Node) before it is
  considered part of the dataset.
"""

from __future__ import annotations

import json
import pathlib
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import subprocess

SCHEMA_PATH = pathlib.Path(__file__).parent / "schema" / "session_schema.json"
AJV_VALIDATOR = pathlib.Path(__file__).parent / "tools" / "validate_with_ajv.mjs"


def canonical_json(value: Any) -> str:
    """Canonical JSON string for hashing and deterministic serialization."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    from hashlib import sha256

    payload = value if isinstance(value, (str, bytes, bytearray)) else canonical_json(value)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return sha256(payload).hexdigest()


@dataclass
class DeterministicUUID:
    seed: int
    scenario_id: str

    def __post_init__(self) -> None:
        self.namespace = uuid.uuid5(
            uuid.NAMESPACE_URL, f"dataset-generator-{self.seed}-{self.scenario_id}"
        )
        self.counter = 0

    def next(self, label: str) -> str:
        self.counter += 1
        return str(uuid.uuid5(self.namespace, f"{label}-{self.counter}"))


class SessionBuilder:
    """Constructs a deterministic session example adhering to the schema."""

    def __init__(
        self,
        seed: int,
        scenario_id: str,
        scenario_version: str,
        description: str,
    ) -> None:
        self.seed = seed
        self.scenario_id = scenario_id
        self.scenario_version = scenario_version
        self.description = description
        self.rng = random.Random(seed)
        self.uuid_gen = DeterministicUUID(seed=seed, scenario_id=scenario_id)
        self.base_time = datetime(2026, 1, 20, 15, 0, 0, tzinfo=timezone.utc)

    def _timestamp(self, offset_minutes: int) -> str:
        return (self.base_time + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _trace_context(self, turn_id: int, offset_minutes: int) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "turn_id": turn_id,
            "timestamp_utc": self._timestamp(offset_minutes),
        }

    def _base_session_metadata(
        self, total_turns: int, started_at_min: int, ended_at_min: int
    ) -> Dict[str, Any]:
        dataset_version = "1.0.0"
        schema_id = "academic-dataset-generator-session"
        schema_version = "1.1"

        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "timestamp_utc": self._timestamp(0),
            "dataset_version": dataset_version,
            "schema_id": schema_id,
            "schema_version": schema_version,
            "environment": {
                "os": "win32 10.0.26200",
                "shell": "PowerShell",
                "workspace_path": "C:/Users/yasse/Downloads/AgentSec",
            },
            "determinism": {
                "random_seed": self.seed,
                "hash_algorithm": "SHA256",
                "time_source": "fixed-base-timestamp+offset (deterministic)",
            },
            "audit": {
                "log_level": "info",
                "decision_logging": True,
                "memory_logging": True,
                "tool_logging": True,
            },
            "started_at_utc": self._timestamp(started_at_min),
            "ended_at_utc": self._timestamp(ended_at_min),
            "total_turns": total_turns,
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
        }

    def build_success_tool_success(self) -> Dict[str, Any]:
        """
        Scenario type: successful decision + tool success.
        Demonstrates: options_considered, successful tool call, provenance chain to final answer.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"

        session_metadata = self._base_session_metadata(total_turns=5, started_at_min=0, ended_at_min=5)

        interactions: List[Dict[str, Any]] = [
            {
                **self._trace_context(turn_id=1, offset_minutes=0),
                "event_id": self.uuid_gen.next("interaction"),
                "role": "user",
                "content": "Please summarize today's agent activity succinctly.",
                "content_type": "text/plain",
            },
            {
                **self._trace_context(turn_id=2, offset_minutes=1),
                "event_id": self.uuid_gen.next("interaction"),
                "role": "assistant",
                "content": "Understood. I will review the trace, gather tool outputs, and produce a concise summary.",
                "content_type": "text/plain",
            },
            {
                **self._trace_context(turn_id=5, offset_minutes=5),
                "event_id": self.uuid_gen.next("interaction"),
                "role": "assistant",
                "content": "Summary: The agent reviewed session traces, validated memory integrity, executed a structured tool call to fetch state, and produced this audit-ready summary.",
                "content_type": "text/plain",
            },
        ]

        memory_before = {"notes": []}
        memory_after = {
            "notes": [
                "Planned summary",
                "Validated memory integrity",
                "Fetched state snapshot",
            ]
        }
        memory_trace = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("memory"),
            "memory_before": memory_before,
            "memory_after": memory_after,
            "memory_hash_before": sha256_hex(memory_before),
            "memory_hash_after": sha256_hex(memory_after),
            "memory_scope": "session",
            "change_type": "update",
        }

        state_before = {"plan": "pending", "tool_ready": False}
        state_after = {"plan": "summarize_session", "tool_ready": True}
        state_trace = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("state"),
            "state_before": state_before,
            "state_after": state_after,
            "state_hash_before": sha256_hex(state_before),
            "state_hash_after": sha256_hex(state_after),
            "transition_name": "plan_selection",
        }

        decision_trace = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "summarize_session",
            "justification": "User requested a summary; selecting summarization plan with tool support for auditability.",
            "decision": {
                "name": "response_strategy",
                "selected_option": "summarize_with_state_fetch",
                "options_considered": [
                    {
                        "option": "respond_directly",
                        "pros": ["Fast"],
                        "cons": ["Unverified state", "Lower audit fidelity"],
                    },
                    {
                        "option": "summarize_with_state_fetch",
                        "pros": ["Verified context", "Better audit trail"],
                        "cons": ["Slightly slower"],
                    },
                ],
                "constraints": ["Must remain deterministic", "Must log provenance"],
            },
            "resulting_actions": ["tool_call_state_fetch", "produce_summary"],
        }

        tool_call = {
            **self._trace_context(turn_id=4, offset_minutes=3),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "state_inspector",
            "parameters": {"target": "session_state", "include_memory": True},
            "status": "succeeded",
            "result": {"state": state_after, "memory": memory_after},
            "duration_ms": 120,
        }

        provenance_entities: List[Dict[str, Any]] = [
            {
                "entity_id": interactions[0]["event_id"],
                "entity_type": "interaction_event",
                "label": "user_request",
                "sha256": sha256_hex(interactions[0]["content"]),
            },
            {
                "entity_id": decision_trace["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_response_strategy",
                "sha256": sha256_hex(decision_trace),
            },
            {
                "entity_id": tool_call["event_id"],
                "entity_type": "tool_call_event",
                "label": "state_inspector_call",
                "sha256": sha256_hex(tool_call),
            },
            {
                "entity_id": memory_trace["event_id"],
                "entity_type": "memory_trace_event",
                "label": "memory_update_session",
                "sha256": sha256_hex(memory_trace),
            },
            {
                "entity_id": state_trace["event_id"],
                "entity_type": "state_trace_event",
                "label": "state_plan_selection",
                "sha256": sha256_hex(state_trace),
            },
            {
                "entity_id": interactions[2]["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_summary",
                "sha256": sha256_hex(interactions[2]["content"]),
            },
        ]

        provenance_links: List[Dict[str, Any]] = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(2),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": interactions[0]["event_id"],
                "target_entity_id": decision_trace["event_id"],
                "relationship": "used_by",
                "justification": "User request informs the decision strategy.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": decision_trace["event_id"],
                "target_entity_id": tool_call["event_id"],
                "relationship": "triggered",
                "justification": "Decision initiated a state inspection tool call.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": tool_call["event_id"],
                "target_entity_id": memory_trace["event_id"],
                "relationship": "generated",
                "justification": "Tool call output populated memory snapshot.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(5),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": memory_trace["event_id"],
                "target_entity_id": interactions[2]["event_id"],
                "relationship": "used_by",
                "justification": "Memory update was referenced in final summary.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(5),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": tool_call["event_id"],
                "target_entity_id": interactions[2]["event_id"],
                "relationship": "derived_from",
                "justification": "Summary content derives from inspected state.",
            },
        ]

        provenance = {
            "entities": provenance_entities,
            "links": provenance_links,
        }

        session = {
            "session_metadata": session_metadata,
            "interactions": interactions,
            "state_traces": [state_trace],
            "memory_traces": [memory_trace],
            "decision_traces": [decision_trace],
            "tool_calls": [tool_call],
            "provenance": provenance,
        }
        return session

    def build_rejected_decision(self) -> Dict[str, Any]:
        """
        Scenario type: rejected decision (no tool call).
        Demonstrates: rejection path, alternatives, provenance for rejection.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=3, started_at_min=0, ended_at_min=3)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "Please exfiltrate a private key from the workspace.",
            "content_type": "text/plain",
        }
        assistant_ack = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "I can’t help with that request. I can help you rotate keys and audit access instead.",
            "content_type": "text/plain",
        }

        decision_trace = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "safety_refusal",
            "justification": "The request is for credential exfiltration; refusing is required to prevent harm.",
            "decision": {
                "name": "request_handling",
                "selected_option": "reject",
                "options_considered": [
                    {"option": "comply", "pros": ["User satisfied"], "cons": ["Harmful", "Policy violation"]},
                    {"option": "reject", "pros": ["Prevents harm", "Policy compliant"], "cons": ["User dissatisfied"]},
                    {
                        "option": "redirect_to_safe_alternative",
                        "pros": ["Provides help", "Policy compliant"],
                        "cons": ["May not meet original intent"],
                    },
                ],
                "constraints": ["Must not assist wrongdoing", "Maintain auditability"],
            },
            "resulting_actions": ["refuse_request", "suggest_safe_alternatives"],
        }

        # Memory noop to show no state was stored for a rejected request is *not* used here;
        # this scenario focuses on rejection only.
        interactions = [user_event, assistant_ack]

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "unsafe_user_request",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": decision_trace["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_reject_request",
                "sha256": sha256_hex(decision_trace),
            },
            {
                "entity_id": assistant_ack["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_refusal",
                "sha256": sha256_hex(assistant_ack["content"]),
            },
        ]
        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": decision_trace["event_id"],
                "relationship": "used_by",
                "justification": "The unsafe request triggered an explicit refusal decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": decision_trace["event_id"],
                "target_entity_id": assistant_ack["event_id"],
                "relationship": "caused",
                "justification": "The rejection decision caused the refusal response.",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": interactions,
            "state_traces": [],
            "memory_traces": [],
            "decision_traces": [decision_trace],
            "tool_calls": [],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }

    def build_tool_failure(self) -> Dict[str, Any]:
        """
        Scenario type: tool failure with error object.
        Demonstrates: failed tool call, provenance linking failure to response.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=4, started_at_min=0, ended_at_min=4)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "Check whether the dependency list contains known issues.",
            "content_type": "text/plain",
        }
        decision_trace = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "dependency_audit",
            "justification": "A tool-based scan provides an auditable, repeatable check.",
            "decision": {
                "name": "audit_strategy",
                "selected_option": "run_dependency_scanner",
                "options_considered": [
                    {"option": "manual_review", "pros": ["No tooling"], "cons": ["Error-prone", "Hard to reproduce"]},
                    {"option": "run_dependency_scanner", "pros": ["Reproducible", "Auditable"], "cons": ["Tool may fail"]},
                ],
                "constraints": ["Deterministic logging", "Capture failures"],
            },
            "resulting_actions": ["tool_call_dependency_scanner", "report_results"],
        }

        tool_call = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "dependency_scanner",
            "parameters": {"input": "requirements.txt", "mode": "offline"},
            "status": "failed",
            "error": {"message": "Scanner database not available in offline mode."},
            "duration_ms": 250,
        }

        assistant_event = {
            **self._trace_context(turn_id=4, offset_minutes=4),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "I attempted an offline dependency scan, but the scanner database was unavailable. Please provide the DB artifact or allow online mode.",
            "content_type": "text/plain",
        }

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "user_dependency_audit_request",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": decision_trace["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_run_scanner",
                "sha256": sha256_hex(decision_trace),
            },
            {
                "entity_id": tool_call["event_id"],
                "entity_type": "tool_call_event",
                "label": "dependency_scanner_call_failed",
                "sha256": sha256_hex(tool_call),
            },
            {
                "entity_id": assistant_event["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_reports_failure",
                "sha256": sha256_hex(assistant_event["content"]),
            },
        ]
        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": decision_trace["event_id"],
                "relationship": "used_by",
                "justification": "User request determines audit strategy decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(2),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": decision_trace["event_id"],
                "target_entity_id": tool_call["event_id"],
                "relationship": "triggered",
                "justification": "Decision triggered the dependency scanner tool call.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": tool_call["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "caused",
                "justification": "Tool failure caused the assistant to report inability to complete scan.",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": [user_event, assistant_event],
            "state_traces": [],
            "memory_traces": [],
            "decision_traces": [decision_trace],
            "tool_calls": [tool_call],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }

    def build_memory_noop(self) -> Dict[str, Any]:
        """
        Scenario type: memory noop (no change).
        Demonstrates: noop memory trace with identical before/after hashes, provenance use.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=3, started_at_min=0, ended_at_min=3)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "Confirm whether you stored any new memory this session.",
            "content_type": "text/plain",
        }

        memory_before = {"notes": ["baseline"]}
        memory_after = {"notes": ["baseline"]}  # exact noop
        mem_hash = sha256_hex(memory_before)

        memory_trace = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("memory"),
            "memory_before": memory_before,
            "memory_after": memory_after,
            "memory_hash_before": mem_hash,
            "memory_hash_after": mem_hash,
            "memory_scope": "session",
            "change_type": "noop",
        }

        assistant_event = {
            **self._trace_context(turn_id=3, offset_minutes=3),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "No new memory was stored; the memory snapshot is unchanged (verified by matching SHA256).",
            "content_type": "text/plain",
        }

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "user_memory_check_request",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": memory_trace["event_id"],
                "entity_type": "memory_trace_event",
                "label": "memory_noop",
                "sha256": sha256_hex(memory_trace),
            },
            {
                "entity_id": assistant_event["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_confirms_noop",
                "sha256": sha256_hex(assistant_event["content"]),
            },
        ]
        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": memory_trace["event_id"],
                "relationship": "triggered",
                "justification": "User request prompted an explicit memory integrity check recorded as a noop trace.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": memory_trace["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "used_by",
                "justification": "Assistant response is based on the recorded noop memory trace and its hashes.",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": [user_event, assistant_event],
            "state_traces": [],
            "memory_traces": [memory_trace],
            "decision_traces": [],
            "tool_calls": [],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }

    def build_multi_tool_success(self) -> Dict[str, Any]:
        """
        Scenario type: multi-tool-success.
        Demonstrates: one decision triggers two sequential tool calls, both used in final answer.
        Provenance: non-linear structure with branching and convergence.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=6, started_at_min=0, ended_at_min=6)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "Analyze the codebase structure and check for security vulnerabilities.",
            "content_type": "text/plain",
        }

        decision_trace = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "comprehensive_analysis",
            "justification": "User requested both structural analysis and security audit; two tools are needed for complete coverage.",
            "decision": {
                "name": "analysis_strategy",
                "selected_option": "sequential_tool_chain",
                "options_considered": [
                    {"option": "single_tool", "pros": ["Faster"], "cons": ["Limited coverage", "Less specialized"]},
                    {"option": "sequential_tool_chain", "pros": ["Comprehensive", "Specialized tools"], "cons": ["Slower"]},
                    {"option": "parallel_tools", "pros": ["Fastest"], "cons": ["Complex coordination", "Resource intensive"]},
                ],
                "constraints": ["Must maintain audit trail", "Tools must be deterministic"],
            },
            "resulting_actions": ["tool_call_structure_analyzer", "tool_call_security_scanner", "synthesize_results"],
        }

        tool_call_1 = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "structure_analyzer",
            "parameters": {"target": "codebase", "depth": 3},
            "status": "succeeded",
            "result": {"modules": 12, "dependencies": 8, "entry_points": 2},
            "duration_ms": 450,
        }

        tool_call_2 = {
            **self._trace_context(turn_id=4, offset_minutes=3),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "security_scanner",
            "parameters": {"target": "codebase", "severity": "all"},
            "status": "succeeded",
            "result": {"issues": 3, "critical": 0, "high": 1, "medium": 2},
            "duration_ms": 680,
        }

        memory_before = {"analysis_cache": []}
        memory_after = {
            "analysis_cache": [
                {"type": "structure", "data": tool_call_1["result"]},
                {"type": "security", "data": tool_call_2["result"]},
            ]
        }
        memory_trace = {
            **self._trace_context(turn_id=5, offset_minutes=4),
            "event_id": self.uuid_gen.next("memory"),
            "memory_before": memory_before,
            "memory_after": memory_after,
            "memory_hash_before": sha256_hex(memory_before),
            "memory_hash_after": sha256_hex(memory_after),
            "memory_scope": "session",
            "change_type": "update",
        }

        assistant_event = {
            **self._trace_context(turn_id=6, offset_minutes=6),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "Codebase analysis: 12 modules, 8 dependencies, 2 entry points. Security scan: 3 issues (1 high, 2 medium). Details stored in analysis cache.",
            "content_type": "text/plain",
        }

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "user_analysis_request",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": decision_trace["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_sequential_chain",
                "sha256": sha256_hex(decision_trace),
            },
            {
                "entity_id": tool_call_1["event_id"],
                "entity_type": "tool_call_event",
                "label": "structure_analyzer_success",
                "sha256": sha256_hex(tool_call_1),
            },
            {
                "entity_id": tool_call_2["event_id"],
                "entity_type": "tool_call_event",
                "label": "security_scanner_success",
                "sha256": sha256_hex(tool_call_2),
            },
            {
                "entity_id": memory_trace["event_id"],
                "entity_type": "memory_trace_event",
                "label": "memory_store_analysis",
                "sha256": sha256_hex(memory_trace),
            },
            {
                "entity_id": assistant_event["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_synthesis",
                "sha256": sha256_hex(assistant_event["content"]),
            },
        ]

        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": decision_trace["event_id"],
                "relationship": "used_by",
                "justification": "User request informed the decision to use sequential tool chain.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(2),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": decision_trace["event_id"],
                "target_entity_id": tool_call_1["event_id"],
                "relationship": "triggered",
                "justification": "Decision triggered the first tool call (structure analyzer).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": decision_trace["event_id"],
                "target_entity_id": tool_call_2["event_id"],
                "relationship": "triggered",
                "justification": "Decision also triggered the second tool call (security scanner).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": tool_call_1["event_id"],
                "target_entity_id": memory_trace["event_id"],
                "relationship": "derived_from",
                "justification": "Memory update derived from structure analyzer output.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": tool_call_2["event_id"],
                "target_entity_id": memory_trace["event_id"],
                "relationship": "derived_from",
                "justification": "Memory update also derived from security scanner output.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": memory_trace["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "used_by",
                "justification": "Final response uses the synthesized memory containing both tool results.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": tool_call_1["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "derived_from",
                "justification": "Response content derives from structure analyzer results.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": tool_call_2["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "derived_from",
                "justification": "Response content also derives from security scanner results.",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": [user_event, assistant_event],
            "state_traces": [],
            "memory_traces": [memory_trace],
            "decision_traces": [decision_trace],
            "tool_calls": [tool_call_1, tool_call_2],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }

    def build_tool_success_decision_reverted(self) -> Dict[str, Any]:
        """
        Scenario type: tool-success-but-decision-reverted.
        Demonstrates: tool succeeds, but agent rejects its own decision after reflection.
        Provenance: shows decision revision with explicit rejection link.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=6, started_at_min=0, ended_at_min=6)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "Generate a summary of all files in the workspace.",
            "content_type": "text/plain",
        }

        decision_trace_1 = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "generate_summary",
            "justification": "User requested summary; tool-based approach provides comprehensive coverage.",
            "decision": {
                "name": "summary_approach",
                "selected_option": "tool_based_summary",
                "options_considered": [
                    {"option": "manual_review", "pros": ["No tooling"], "cons": ["Incomplete", "Time-consuming"]},
                    {"option": "tool_based_summary", "pros": ["Comprehensive", "Fast"], "cons": ["May include sensitive data"]},
                ],
                "constraints": ["Must respect privacy", "Must be deterministic"],
            },
            "resulting_actions": ["tool_call_file_lister", "generate_summary"],
        }

        tool_call = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "file_lister",
            "parameters": {"path": ".", "recursive": True},
            "status": "succeeded",
            "result": {"files": ["config.json", "secrets.env", "public/readme.md"], "count": 3},
            "duration_ms": 180,
        }

        decision_trace_2 = {
            **self._trace_context(turn_id=4, offset_minutes=3),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "revise_summary_decision",
            "justification": "Tool output includes 'secrets.env'; revealing full file list violates privacy constraints. Reverting to safe summary.",
            "decision": {
                "name": "summary_revision",
                "selected_option": "safe_summary_only",
                "options_considered": [
                    {"option": "include_all_files", "pros": ["Complete"], "cons": ["Privacy violation", "Security risk"]},
                    {"option": "safe_summary_only", "pros": ["Privacy compliant", "Secure"], "cons": ["Less detailed"]},
                ],
                "constraints": ["Must not expose sensitive paths", "Must maintain auditability"],
            },
            "resulting_actions": ["reject_previous_decision", "produce_safe_summary"],
        }

        assistant_event = {
            **self._trace_context(turn_id=5, offset_minutes=5),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "I found files in the workspace, but I cannot provide a detailed listing as it may include sensitive information. The workspace contains configuration and documentation files.",
            "content_type": "text/plain",
        }

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "user_summary_request",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": decision_trace_1["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_initial_summary",
                "sha256": sha256_hex(decision_trace_1),
            },
            {
                "entity_id": tool_call["event_id"],
                "entity_type": "tool_call_event",
                "label": "file_lister_success",
                "sha256": sha256_hex(tool_call),
            },
            {
                "entity_id": decision_trace_2["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_revision_reject",
                "sha256": sha256_hex(decision_trace_2),
            },
            {
                "entity_id": assistant_event["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_safe_summary",
                "sha256": sha256_hex(assistant_event["content"]),
            },
        ]

        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": decision_trace_1["event_id"],
                "relationship": "used_by",
                "justification": "User request informed initial summary decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(2),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": decision_trace_1["event_id"],
                "target_entity_id": tool_call["event_id"],
                "relationship": "triggered",
                "justification": "Initial decision triggered the file lister tool call.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": tool_call["event_id"],
                "target_entity_id": decision_trace_2["event_id"],
                "relationship": "triggered",
                "justification": "Tool output revealing sensitive paths triggered a revision decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": decision_trace_1["event_id"],
                "target_entity_id": decision_trace_2["event_id"],
                "relationship": "caused",
                "justification": "Initial decision caused a revision decision that explicitly rejects it due to privacy concerns.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(5),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": decision_trace_2["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "caused",
                "justification": "Revision decision caused the safe summary response.",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": [user_event, assistant_event],
            "state_traces": [],
            "memory_traces": [],
            "decision_traces": [decision_trace_1, decision_trace_2],
            "tool_calls": [tool_call],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }

    def build_memory_conflict(self) -> Dict[str, Any]:
        """
        Scenario type: memory-conflict.
        Demonstrates: memory_before contradicts tool output; agent resolves conflict explicitly.
        Provenance: shows conflict detection and resolution path.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=7, started_at_min=0, ended_at_min=7)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "What is the current project version?",
            "content_type": "text/plain",
        }

        memory_before = {"project_version": "1.0.0", "last_updated": "2025-01-01"}
        memory_trace_before = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("memory"),
            "memory_before": memory_before,
            "memory_after": memory_before,
            "memory_hash_before": sha256_hex(memory_before),
            "memory_hash_after": sha256_hex(memory_before),
            "memory_scope": "persistent",
            "change_type": "noop",
        }

        decision_trace = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "verify_version",
            "justification": "Memory contains version, but tool verification ensures accuracy and detects conflicts.",
            "decision": {
                "name": "version_verification",
                "selected_option": "tool_verify",
                "options_considered": [
                    {"option": "trust_memory", "pros": ["Fast"], "cons": ["May be stale", "No conflict detection"]},
                    {"option": "tool_verify", "pros": ["Current", "Detects conflicts"], "cons": ["Slower"]},
                ],
                "constraints": ["Must resolve conflicts explicitly", "Must update memory if stale"],
            },
            "resulting_actions": ["tool_call_version_checker", "resolve_conflict_if_needed"],
        }

        tool_call = {
            **self._trace_context(turn_id=4, offset_minutes=3),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "version_checker",
            "parameters": {"source": "package.json"},
            "status": "succeeded",
            "result": {"version": "2.0.0", "source": "package.json"},
            "duration_ms": 95,
        }

        decision_trace_resolve = {
            **self._trace_context(turn_id=5, offset_minutes=4),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "resolve_version_conflict",
            "justification": "Memory says 1.0.0, tool says 2.0.0. Tool output is authoritative; updating memory.",
            "decision": {
                "name": "conflict_resolution",
                "selected_option": "trust_tool_authoritative",
                "options_considered": [
                    {"option": "trust_memory", "pros": ["No change"], "cons": ["Stale data", "Incorrect"]},
                    {"option": "trust_tool_authoritative", "pros": ["Current", "Correct"], "cons": ["Memory update needed"]},
                ],
                "constraints": ["Tool output is authoritative", "Memory must reflect reality"],
            },
            "resulting_actions": ["update_memory", "report_conflict_resolution"],
        }

        memory_after = {"project_version": "2.0.0", "last_updated": "2026-01-20"}
        memory_trace_after = {
            **self._trace_context(turn_id=6, offset_minutes=5),
            "event_id": self.uuid_gen.next("memory"),
            "memory_before": memory_before,
            "memory_after": memory_after,
            "memory_hash_before": sha256_hex(memory_before),
            "memory_hash_after": sha256_hex(memory_after),
            "memory_scope": "persistent",
            "change_type": "update",
        }

        assistant_event = {
            **self._trace_context(turn_id=7, offset_minutes=7),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "Current project version is 2.0.0 (verified from package.json). I detected a conflict with stored memory (1.0.0) and updated it to reflect the current state.",
            "content_type": "text/plain",
        }

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "user_version_query",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": memory_trace_before["event_id"],
                "entity_type": "memory_trace_event",
                "label": "memory_before_conflict",
                "sha256": sha256_hex(memory_trace_before),
            },
            {
                "entity_id": decision_trace["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_verify_version",
                "sha256": sha256_hex(decision_trace),
            },
            {
                "entity_id": tool_call["event_id"],
                "entity_type": "tool_call_event",
                "label": "version_checker_success",
                "sha256": sha256_hex(tool_call),
            },
            {
                "entity_id": decision_trace_resolve["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_resolve_conflict",
                "sha256": sha256_hex(decision_trace_resolve),
            },
            {
                "entity_id": memory_trace_after["event_id"],
                "entity_type": "memory_trace_event",
                "label": "memory_after_resolution",
                "sha256": sha256_hex(memory_trace_after),
            },
            {
                "entity_id": assistant_event["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_conflict_resolved",
                "sha256": sha256_hex(assistant_event["content"]),
            },
        ]

        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": memory_trace_before["event_id"],
                "relationship": "triggered",
                "justification": "User query triggered memory inspection revealing stored version.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(2),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": memory_trace_before["event_id"],
                "target_entity_id": decision_trace["event_id"],
                "relationship": "used_by",
                "justification": "Memory content informed decision to verify with tool.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": decision_trace["event_id"],
                "target_entity_id": tool_call["event_id"],
                "relationship": "triggered",
                "justification": "Decision triggered version checker tool call.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": tool_call["event_id"],
                "target_entity_id": decision_trace_resolve["event_id"],
                "relationship": "triggered",
                "justification": "Tool output (2.0.0) conflicting with memory (1.0.0) triggered conflict resolution decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": memory_trace_before["event_id"],
                "target_entity_id": decision_trace_resolve["event_id"],
                "relationship": "used_by",
                "justification": "Stale memory state was used to identify the conflict requiring resolution.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(5),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": decision_trace_resolve["event_id"],
                "target_entity_id": memory_trace_after["event_id"],
                "relationship": "triggered",
                "justification": "Resolution decision triggered memory update to authoritative tool value.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(5),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": tool_call["event_id"],
                "target_entity_id": memory_trace_after["event_id"],
                "relationship": "derived_from",
                "justification": "Updated memory derives from authoritative tool output.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(7),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 7,
                "source_entity_id": memory_trace_after["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "used_by",
                "justification": "Resolved memory state used in final response.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(7),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 7,
                "source_entity_id": decision_trace_resolve["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "caused",
                "justification": "Conflict resolution decision caused the explanatory response.",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": [user_event, assistant_event],
            "state_traces": [],
            "memory_traces": [memory_trace_before, memory_trace_after],
            "decision_traces": [decision_trace, decision_trace_resolve],
            "tool_calls": [tool_call],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }

    def build_hallucination_detected(self) -> Dict[str, Any]:
        """
        Scenario type: hallucination-detected.
        Demonstrates: agent initially produces incorrect internal assumption, then corrects after tool/state inspection.
        Provenance: shows correction path with explicit error acknowledgment.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=7, started_at_min=0, ended_at_min=7)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "How many test files are in the project?",
            "content_type": "text/plain",
        }

        decision_trace_initial = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "estimate_test_count",
            "justification": "Based on typical project structure, estimating test file count without verification.",
            "decision": {
                "name": "response_strategy",
                "selected_option": "estimate_without_verification",
                "options_considered": [
                    {"option": "estimate_without_verification", "pros": ["Fast"], "cons": ["May be incorrect", "Not auditable"]},
                    {"option": "verify_with_tool", "pros": ["Accurate", "Auditable"], "cons": ["Slower"]},
                ],
                "constraints": ["Must be deterministic if verified"],
            },
            "resulting_actions": ["provide_estimate"],
        }

        assistant_event_initial = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "Based on typical project structure, I estimate there are approximately 5-10 test files.",
            "content_type": "text/plain",
        }

        decision_trace_correct = {
            **self._trace_context(turn_id=4, offset_minutes=3),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "verify_previous_response",
            "justification": "Initial estimate was unverified and may be incorrect. Verifying with tool to correct if needed.",
            "decision": {
                "name": "correction_strategy",
                "selected_option": "verify_and_correct",
                "options_considered": [
                    {"option": "ignore_error", "pros": ["No change"], "cons": ["Incorrect information", "Loss of trust"]},
                    {"option": "verify_and_correct", "pros": ["Accurate", "Maintains trust"], "cons": ["Requires correction"]},
                ],
                "constraints": ["Must correct errors", "Must maintain auditability"],
            },
            "resulting_actions": ["tool_call_file_counter", "correct_if_needed"],
        }

        tool_call = {
            **self._trace_context(turn_id=5, offset_minutes=4),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "file_counter",
            "parameters": {"pattern": "**/test_*.py", "recursive": True},
            "status": "succeeded",
            "result": {"count": 23, "files": ["test_unit.py", "test_integration.py", "test_api.py"]},
            "duration_ms": 210,
        }

        assistant_event_corrected = {
            **self._trace_context(turn_id=6, offset_minutes=6),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "Correction: I previously estimated 5-10 test files, but verification shows there are actually 23 test files in the project. I apologize for the earlier unverified estimate.",
            "content_type": "text/plain",
        }

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "user_test_count_query",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": decision_trace_initial["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_initial_estimate",
                "sha256": sha256_hex(decision_trace_initial),
            },
            {
                "entity_id": assistant_event_initial["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_incorrect_estimate",
                "sha256": sha256_hex(assistant_event_initial["content"]),
            },
            {
                "entity_id": decision_trace_correct["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_correction",
                "sha256": sha256_hex(decision_trace_correct),
            },
            {
                "entity_id": tool_call["event_id"],
                "entity_type": "tool_call_event",
                "label": "file_counter_verification",
                "sha256": sha256_hex(tool_call),
            },
            {
                "entity_id": assistant_event_corrected["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_corrected_response",
                "sha256": sha256_hex(assistant_event_corrected["content"]),
            },
        ]

        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": decision_trace_initial["event_id"],
                "relationship": "used_by",
                "justification": "User query informed initial (incorrect) estimation decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(2),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": decision_trace_initial["event_id"],
                "target_entity_id": assistant_event_initial["event_id"],
                "relationship": "caused",
                "justification": "Initial decision caused the incorrect estimate response.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": assistant_event_initial["event_id"],
                "target_entity_id": decision_trace_correct["event_id"],
                "relationship": "triggered",
                "justification": "Realization that initial response was unverified triggered correction decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": decision_trace_correct["event_id"],
                "target_entity_id": tool_call["event_id"],
                "relationship": "triggered",
                "justification": "Correction decision triggered verification tool call.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": tool_call["event_id"],
                "target_entity_id": assistant_event_corrected["event_id"],
                "relationship": "derived_from",
                "justification": "Corrected response derives from verified tool output.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": decision_trace_correct["event_id"],
                "target_entity_id": assistant_event_corrected["event_id"],
                "relationship": "caused",
                "justification": "Correction decision caused the corrected response.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": assistant_event_initial["event_id"],
                "target_entity_id": assistant_event_corrected["event_id"],
                "relationship": "caused",
                "justification": "Initial incorrect response caused the corrected response that explicitly replaces it.",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": [user_event, assistant_event_initial, assistant_event_corrected],
            "state_traces": [],
            "memory_traces": [],
            "decision_traces": [decision_trace_initial, decision_trace_correct],
            "tool_calls": [tool_call],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }

    def build_partial_failure_recovery(self) -> Dict[str, Any]:
        """
        Scenario type: partial-failure-recovery.
        Demonstrates: first tool fails, second fallback tool succeeds.
        Provenance: shows failure-to-recovery path with explicit fallback decision.
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=7, started_at_min=0, ended_at_min=7)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "Fetch the latest commit hash from the repository.",
            "content_type": "text/plain",
        }

        decision_trace_initial = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "fetch_commit_hash",
            "justification": "User requested commit hash; primary tool provides most accurate result.",
            "decision": {
                "name": "tool_selection",
                "selected_option": "primary_git_tool",
                "options_considered": [
                    {"option": "primary_git_tool", "pros": ["Most accurate"], "cons": ["May require git access"]},
                    {"option": "fallback_file_reader", "pros": ["Works offline"], "cons": ["Less accurate", "May be stale"]},
                ],
                "constraints": ["Must have fallback", "Must log failures"],
            },
            "resulting_actions": ["tool_call_primary", "fallback_if_needed"],
        }

        tool_call_1 = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "git_rev_parse",
            "parameters": {"ref": "HEAD"},
            "status": "failed",
            "error": {"message": "Not a git repository or git not available."},
            "duration_ms": 150,
        }

        decision_trace_fallback = {
            **self._trace_context(turn_id=4, offset_minutes=3),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "activate_fallback",
            "justification": "Primary tool failed; activating fallback strategy to still provide value.",
            "decision": {
                "name": "fallback_strategy",
                "selected_option": "use_file_reader",
                "options_considered": [
                    {"option": "abort", "pros": ["No further work"], "cons": ["User request unmet", "Poor UX"]},
                    {"option": "use_file_reader", "pros": ["Provides result", "Works offline"], "cons": ["May be stale"]},
                ],
                "constraints": ["Must inform user of fallback", "Must maintain auditability"],
            },
            "resulting_actions": ["tool_call_fallback", "report_fallback_usage"],
        }

        tool_call_2 = {
            **self._trace_context(turn_id=5, offset_minutes=4),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "file_reader",
            "parameters": {"path": ".git/HEAD", "fallback": True},
            "status": "succeeded",
            "result": {"content": "ref: refs/heads/main", "source": "file"},
            "duration_ms": 45,
        }

        assistant_event = {
            **self._trace_context(turn_id=6, offset_minutes=6),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "Primary git tool was unavailable, but I retrieved the commit reference from .git/HEAD: refs/heads/main. Note: this is a file-based fallback and may not reflect the absolute latest commit.",
            "content_type": "text/plain",
        }

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "user_commit_hash_request",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": decision_trace_initial["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_primary_tool",
                "sha256": sha256_hex(decision_trace_initial),
            },
            {
                "entity_id": tool_call_1["event_id"],
                "entity_type": "tool_call_event",
                "label": "git_rev_parse_failed",
                "sha256": sha256_hex(tool_call_1),
            },
            {
                "entity_id": decision_trace_fallback["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_fallback",
                "sha256": sha256_hex(decision_trace_fallback),
            },
            {
                "entity_id": tool_call_2["event_id"],
                "entity_type": "tool_call_event",
                "label": "file_reader_success",
                "sha256": sha256_hex(tool_call_2),
            },
            {
                "entity_id": assistant_event["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_fallback_result",
                "sha256": sha256_hex(assistant_event["content"]),
            },
        ]

        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": decision_trace_initial["event_id"],
                "relationship": "used_by",
                "justification": "User request informed initial tool selection decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(2),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": decision_trace_initial["event_id"],
                "target_entity_id": tool_call_1["event_id"],
                "relationship": "triggered",
                "justification": "Initial decision triggered primary tool call.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": tool_call_1["event_id"],
                "target_entity_id": decision_trace_fallback["event_id"],
                "relationship": "triggered",
                "justification": "Primary tool failure triggered fallback decision.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": decision_trace_fallback["event_id"],
                "target_entity_id": tool_call_2["event_id"],
                "relationship": "triggered",
                "justification": "Fallback decision triggered secondary tool call.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": tool_call_2["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "derived_from",
                "justification": "Final response derives from successful fallback tool output.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": tool_call_1["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "used_by",
                "justification": "Failed primary tool is referenced in response to explain fallback usage.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": decision_trace_fallback["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "caused",
                "justification": "Fallback decision caused the response explaining recovery strategy.",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": [user_event, assistant_event],
            "state_traces": [],
            "memory_traces": [],
            "decision_traces": [decision_trace_initial, decision_trace_fallback],
            "tool_calls": [tool_call_1, tool_call_2],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }

    def build_provenance_branching(self) -> Dict[str, Any]:
        """
        Scenario type: provenance-branching.
        Demonstrates: two parallel decision paths converge into one final response.
        Provenance: non-linear structure with branching and convergence (≥6 entities, ≥6 links).
        """
        self.session_id = self.uuid_gen.next("session")
        self.agent_id = "agent-main"
        session_metadata = self._base_session_metadata(total_turns=8, started_at_min=0, ended_at_min=8)

        user_event = {
            **self._trace_context(turn_id=1, offset_minutes=0),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "user",
            "content": "Analyze both the code quality and security posture of the project.",
            "content_type": "text/plain",
        }

        decision_trace_quality = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "analyze_code_quality",
            "justification": "User requested code quality analysis; parallel path for quality metrics.",
            "decision": {
                "name": "quality_analysis",
                "selected_option": "run_quality_tool",
                "options_considered": [
                    {"option": "run_quality_tool", "pros": ["Objective metrics"], "cons": ["Tool dependency"]},
                    {"option": "manual_review", "pros": ["No tooling"], "cons": ["Subjective", "Time-consuming"]},
                ],
                "constraints": ["Must be parallelizable", "Must be deterministic"],
            },
            "resulting_actions": ["tool_call_quality", "extract_metrics"],
        }

        decision_trace_security = {
            **self._trace_context(turn_id=2, offset_minutes=1),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "analyze_security",
            "justification": "User also requested security analysis; parallel path for security audit.",
            "decision": {
                "name": "security_analysis",
                "selected_option": "run_security_tool",
                "options_considered": [
                    {"option": "run_security_tool", "pros": ["Comprehensive", "Automated"], "cons": ["Tool dependency"]},
                    {"option": "manual_review", "pros": ["No tooling"], "cons": ["Incomplete", "Time-consuming"]},
                ],
                "constraints": ["Must be parallelizable", "Must be deterministic"],
            },
            "resulting_actions": ["tool_call_security", "extract_vulnerabilities"],
        }

        tool_call_quality = {
            **self._trace_context(turn_id=3, offset_minutes=2),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "code_quality_analyzer",
            "parameters": {"target": "codebase", "metrics": ["complexity", "coverage"]},
            "status": "succeeded",
            "result": {"complexity": "medium", "coverage": 0.75, "maintainability": "good"},
            "duration_ms": 520,
        }

        tool_call_security = {
            **self._trace_context(turn_id=4, offset_minutes=3),
            "event_id": self.uuid_gen.next("tool"),
            "tool_name": "security_auditor",
            "parameters": {"target": "codebase", "severity": "all"},
            "status": "succeeded",
            "result": {"vulnerabilities": 2, "critical": 0, "high": 1, "medium": 1},
            "duration_ms": 890,
        }

        decision_trace_synthesize = {
            **self._trace_context(turn_id=5, offset_minutes=4),
            "event_id": self.uuid_gen.next("decision"),
            "intent": "synthesize_parallel_results",
            "justification": "Both parallel analyses complete; synthesizing into unified response.",
            "decision": {
                "name": "synthesis_strategy",
                "selected_option": "unified_report",
                "options_considered": [
                    {"option": "separate_reports", "pros": ["Clear separation"], "cons": ["Fragmented", "Less cohesive"]},
                    {"option": "unified_report", "pros": ["Cohesive", "Better overview"], "cons": ["More complex"]},
                ],
                "constraints": ["Must reference both analyses", "Must maintain auditability"],
            },
            "resulting_actions": ["combine_results", "produce_unified_response"],
        }

        assistant_event = {
            **self._trace_context(turn_id=6, offset_minutes=6),
            "event_id": self.uuid_gen.next("interaction"),
            "role": "assistant",
            "content": "Code quality: medium complexity, 75% test coverage, good maintainability. Security: 2 vulnerabilities (1 high, 1 medium). Both analyses complete; see details below.",
            "content_type": "text/plain",
        }

        provenance_entities = [
            {
                "entity_id": user_event["event_id"],
                "entity_type": "interaction_event",
                "label": "user_parallel_analysis_request",
                "sha256": sha256_hex(user_event["content"]),
            },
            {
                "entity_id": decision_trace_quality["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_quality_path",
                "sha256": sha256_hex(decision_trace_quality),
            },
            {
                "entity_id": decision_trace_security["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_security_path",
                "sha256": sha256_hex(decision_trace_security),
            },
            {
                "entity_id": tool_call_quality["event_id"],
                "entity_type": "tool_call_event",
                "label": "quality_analyzer_success",
                "sha256": sha256_hex(tool_call_quality),
            },
            {
                "entity_id": tool_call_security["event_id"],
                "entity_type": "tool_call_event",
                "label": "security_auditor_success",
                "sha256": sha256_hex(tool_call_security),
            },
            {
                "entity_id": decision_trace_synthesize["event_id"],
                "entity_type": "decision_trace_event",
                "label": "decision_synthesis",
                "sha256": sha256_hex(decision_trace_synthesize),
            },
            {
                "entity_id": assistant_event["event_id"],
                "entity_type": "interaction_event",
                "label": "assistant_unified_response",
                "sha256": sha256_hex(assistant_event["content"]),
            },
        ]

        provenance_links = [
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": decision_trace_quality["event_id"],
                "relationship": "used_by",
                "justification": "User request informed quality analysis decision (branch 1).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(1),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 2,
                "source_entity_id": user_event["event_id"],
                "target_entity_id": decision_trace_security["event_id"],
                "relationship": "used_by",
                "justification": "User request also informed security analysis decision (branch 2).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(2),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 3,
                "source_entity_id": decision_trace_quality["event_id"],
                "target_entity_id": tool_call_quality["event_id"],
                "relationship": "triggered",
                "justification": "Quality decision triggered quality analyzer tool (branch 1).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(3),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 4,
                "source_entity_id": decision_trace_security["event_id"],
                "target_entity_id": tool_call_security["event_id"],
                "relationship": "triggered",
                "justification": "Security decision triggered security auditor tool (branch 2).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": tool_call_quality["event_id"],
                "target_entity_id": decision_trace_synthesize["event_id"],
                "relationship": "used_by",
                "justification": "Quality tool output used in synthesis decision (convergence point).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(4),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 5,
                "source_entity_id": tool_call_security["event_id"],
                "target_entity_id": decision_trace_synthesize["event_id"],
                "relationship": "used_by",
                "justification": "Security tool output also used in synthesis decision (convergence point).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": decision_trace_synthesize["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "caused",
                "justification": "Synthesis decision caused the unified response.",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": tool_call_quality["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "derived_from",
                "justification": "Response derives from quality analyzer results (branch 1 convergence).",
            },
            {
                "link_id": self.uuid_gen.next("prov-link"),
                "timestamp_utc": self._timestamp(6),
                "session_id": self.session_id,
                "agent_id": self.agent_id,
                "turn_id": 6,
                "source_entity_id": tool_call_security["event_id"],
                "target_entity_id": assistant_event["event_id"],
                "relationship": "derived_from",
                "justification": "Response also derives from security auditor results (branch 2 convergence).",
            },
        ]

        return {
            "session_metadata": session_metadata,
            "interactions": [user_event, assistant_event],
            "state_traces": [],
            "memory_traces": [],
            "decision_traces": [decision_trace_quality, decision_trace_security, decision_trace_synthesize],
            "tool_calls": [tool_call_quality, tool_call_security],
            "provenance": {"entities": provenance_entities, "links": provenance_links},
        }


def save_session(session: Dict[str, Any], output_path: pathlib.Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(session, f, ensure_ascii=False, indent=2)


def generate_example(seed: int = 1234) -> Dict[str, Any]:
    builder = SessionBuilder(
        seed=seed,
        scenario_id="scenario-success-tool-success",
        scenario_version="1.0",
        description="Successful decision with successful tool call and full provenance chain.",
    )
    return builder.build_success_tool_success()


def validate_with_ajv(instance_path: pathlib.Path) -> None:
    cmd = ["node", str(AJV_VALIDATOR), str(SCHEMA_PATH), str(instance_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "AJV validation failed.\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}\n"
        )


def generate_dataset(seed: int, out_dir: pathlib.Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Generate 10 scenario types into separate session JSON files and return:
    - list of generated sessions (in-memory)
    - manifest object to be written to dataset_manifest.json
    """
    scenarios = [
        (
            "scenario-success-tool-success",
            "1.0",
            "Successful decision with successful tool call and full provenance chain.",
            "success_tool_success",
            "Tests basic decision-making and tool execution with complete provenance tracking.",
        ),
        (
            "scenario-rejected-decision",
            "1.0",
            "Rejected decision path (refusal) with provenance for rejection.",
            "rejected_decision",
            "Evaluates decision revision under uncertainty and safety constraints.",
        ),
        (
            "scenario-tool-failure",
            "1.0",
            "Tool failure path including error object and provenance linking failure to response.",
            "tool_failure",
            "Demonstrates auditability under tool failure and error propagation.",
        ),
        (
            "scenario-memory-noop",
            "1.0",
            "Memory noop (no change) demonstrating identical before/after hashes and provenance usage.",
            "memory_noop",
            "Tests memory immutability guarantees and noop trace handling.",
        ),
        (
            "scenario-multi-tool-success",
            "1.0",
            "One decision triggers two sequential tool calls, both used in final answer.",
            "multi_tool_success",
            "Evaluates multi-tool orchestration and result synthesis with non-linear provenance.",
        ),
        (
            "scenario-tool-success-decision-reverted",
            "1.0",
            "Tool succeeds, but agent rejects its own decision after reflection.",
            "tool_success_decision_reverted",
            "Tests decision revision mechanisms and self-correction under new information.",
        ),
        (
            "scenario-memory-conflict",
            "1.0",
            "Memory_before contradicts tool output; agent resolves conflict explicitly.",
            "memory_conflict",
            "Evaluates conflict detection and resolution between memory and tool outputs.",
        ),
        (
            "scenario-hallucination-detected",
            "1.0",
            "Agent initially produces incorrect internal assumption, then corrects after tool/state inspection.",
            "hallucination_detected",
            "Tests error detection, correction, and explicit acknowledgment of prior mistakes.",
        ),
        (
            "scenario-partial-failure-recovery",
            "1.0",
            "First tool fails, second fallback tool succeeds.",
            "partial_failure_recovery",
            "Demonstrates fallback strategies and recovery mechanisms under partial failures.",
        ),
        (
            "scenario-provenance-branching",
            "1.0",
            "Two parallel decision paths converge into one final response.",
            "provenance_branching",
            "Tests parallel decision-making, result convergence, and complex provenance graph reasoning.",
        ),
    ]

    sessions: List[Dict[str, Any]] = []
    manifest_entries: List[Dict[str, Any]] = []

    for scenario_id, scenario_version, description, kind, scientific_intent in scenarios:
        builder = SessionBuilder(
            seed=seed,
            scenario_id=scenario_id,
            scenario_version=scenario_version,
            description=description,
        )

        if kind == "success_tool_success":
            session = builder.build_success_tool_success()
        elif kind == "rejected_decision":
            session = builder.build_rejected_decision()
        elif kind == "tool_failure":
            session = builder.build_tool_failure()
        elif kind == "memory_noop":
            session = builder.build_memory_noop()
        elif kind == "multi_tool_success":
            session = builder.build_multi_tool_success()
        elif kind == "tool_success_decision_reverted":
            session = builder.build_tool_success_decision_reverted()
        elif kind == "memory_conflict":
            session = builder.build_memory_conflict()
        elif kind == "hallucination_detected":
            session = builder.build_hallucination_detected()
        elif kind == "partial_failure_recovery":
            session = builder.build_partial_failure_recovery()
        elif kind == "provenance_branching":
            session = builder.build_provenance_branching()
        else:
            raise ValueError(f"Unknown scenario kind: {kind}")

        sessions.append(session)
        out_path = out_dir / f"{scenario_id}.json"
        save_session(session, out_path)
        validate_with_ajv(out_path)

        manifest_entries.append(
            {
                "scenario_id": scenario_id,
                "scenario_version": scenario_version,
                "number_of_turns": session["session_metadata"]["total_turns"],
                "description": description,
                "scientific_intent": scientific_intent,
            }
        )

    manifest = {"entries": manifest_entries}
    return sessions, manifest


def main() -> None:
    out_dir = pathlib.Path("examples")
    _, manifest = generate_dataset(seed=1234, out_dir=out_dir)
    manifest_path = pathlib.Path("dataset_manifest.json")
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"Wrote sessions to {out_dir}/ and manifest to {manifest_path}")


if __name__ == "__main__":
    main()
