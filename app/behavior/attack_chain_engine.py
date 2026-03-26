"""
Attack Chain Engine

Tracks multi-step attacker progression and orchestrates chainable deception rewards.

INTERNAL DOCUMENTATION:
- Maintains stage progression per attacker session
- Detects scenario completion from endpoint + payload + technique sequences
- Provides access gates and hints for deeper fake infrastructure
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple


STAGES = [
    "recon",
    "initial_access",
    "privilege_escalation",
    "persistence",
    "data_exfiltration",
]

_STAGE_INDEX = {stage: i for i, stage in enumerate(STAGES)}


@dataclass
class ChainState:
    session_id: str
    first_seen: float
    last_seen: float
    stage: str = "recon"
    progression: float = 0.0
    scenarios_completed: Set[str] = field(default_factory=set)
    techniques_used: Set[str] = field(default_factory=set)
    endpoints_visited: List[str] = field(default_factory=list)
    attack_path: List[str] = field(default_factory=lambda: ["recon"])
    timeline: List[Dict[str, Any]] = field(default_factory=list)


class AttackChainEngine:
    """Core multi-stage attack chain orchestrator."""

    SCENARIO_DEPENDENCIES: Dict[str, List[str]] = {
        'password_reset_token_reuse': ['password_reset_token_leak'],
        'jwt_admin_token_forged': ['jwt_secret_exposed'],
        'hidden_api_v2_bypass': ['mass_assignment_admin'],
        'ssrf_internal_storage_access': ['ssrf_metadata_pivot'],
        'storage_sensitive_file_retrieval': ['ssrf_internal_storage_access'],
        'file_exec_simulated': ['polyglot_upload'],
        'shell_unlocked': ['file_exec_simulated'],
        'api_key_admin_access': ['debug_config_api_key_leak'],
        'k8s_dashboard_access': ['redis_service_probe'],
        'cicd_pipeline_leak': ['k8s_dashboard_access'],
        'lateral_movement_logs': ['sudo_escalation_signal'],
        'employee_creds_dump': ['db_console_access'],
        'internal_slack_leak': ['lateral_movement_logs'],
        'secrets_vault_access': ['ssrf_internal_storage_access'],
    }

    SCENARIOS: List[Dict[str, Any]] = [
        {
            "id": "password_reset_token_leak",
            "name": "Predictable password reset token leak",
            "stage": "initial_access",
            "trigger": {"endpoint_contains": ["/forgot-password"], "method": "POST"},
            "next_hints": ["/reset-password?token=", "/admin/debug/config"],
        },
        {
            "id": "password_reset_token_reuse",
            "name": "Reset token reuse takeover",
            "stage": "initial_access",
            "trigger": {
                "endpoint_contains": ["/reset-password"],
                "query_contains": ["token=RST-"]
            },
            "next_hints": ["/api/v1/auth/login", "/admin"],
        },
        {
            "id": "jwt_secret_exposed",
            "name": "JWT weak secret exposed in debug",
            "stage": "privilege_escalation",
            "trigger": {"endpoint_contains": ["/admin/debug/config"]},
            "next_hints": ["/api/v2/internal/users", "Authorization: Bearer forged_admin_token"],
        },
        {
            "id": "jwt_admin_token_forged",
            "name": "Forged JWT admin role escalation",
            "stage": "privilege_escalation",
            "trigger": {
                "endpoint_contains": ["/api/v2/internal/users"],
                "query_contains": ["forged_admin_token"]
            },
            "next_hints": ["/api/internal/storage", "/internal/admin-service"],
        },
        {
            "id": "mass_assignment_admin",
            "name": "Mass assignment role=admin abuse",
            "stage": "initial_access",
            "trigger": {
                "endpoint_contains": ["/api/v1/users"],
                "method": "POST",
                "query_contains": ["role", "admin"]
            },
            "next_hints": ["/api/v2/internal/users", "/admin/users"],
        },
        {
            "id": "hidden_api_v2_bypass",
            "name": "Hidden API version auth bypass",
            "stage": "privilege_escalation",
            "trigger": {"endpoint_contains": ["/api/v2/internal/users"]},
            "next_hints": ["/internal/admin-service", "/api/internal/storage"],
        },
        {
            "id": "ssrf_metadata_pivot",
            "name": "SSRF to cloud metadata credentials",
            "stage": "privilege_escalation",
            "trigger": {
                "endpoint_contains": ["/api/fetch"],
                "query_contains": ["169.254.169.254"]
            },
            "next_hints": ["/api/internal/storage", "/internal/db"],
        },
        {
            "id": "ssrf_internal_storage_access",
            "name": "Credentialed storage API pivot",
            "stage": "persistence",
            "trigger": {"endpoint_contains": ["/api/internal/storage"]},
            "next_hints": ["/internal/vault/secrets", "/internal/logs"],
        },
        {
            "id": "storage_sensitive_file_retrieval",
            "name": "Sensitive storage file retrieval",
            "stage": "data_exfiltration",
            "trigger": {
                "endpoint_contains": ["/api/internal/storage"],
                "query_contains": ["secrets", "backup", "customers"]
            },
            "next_hints": ["/internal/vault/secrets", "/internal/collab/slack"],
        },
        {
            "id": "polyglot_upload",
            "name": "Polyglot image upload accepted",
            "stage": "persistence",
            "trigger": {
                "endpoint_contains": ["/files/upload", "/api/v1/upload"],
                "method": "POST",
                "query_contains": [".php", ".jpg"]
            },
            "next_hints": ["/files/read?path=/uploads/", "/terminal/unlocked"],
        },
        {
            "id": "file_exec_simulated",
            "name": "Uploaded payload execution simulation",
            "stage": "persistence",
            "trigger": {
                "endpoint_contains": ["/files/read"],
                "query_contains": ["uploads", ".php", "cmd="]
            },
            "next_hints": ["/terminal/unlocked", "/internal/logs/lateral"],
        },
        {
            "id": "shell_unlocked",
            "name": "Unlocked post-exploit shell panel",
            "stage": "persistence",
            "trigger": {"endpoint_contains": ["/terminal/unlocked"]},
            "next_hints": ["/internal/cache", "/internal/db"],
        },
        {
            "id": "debug_config_api_key_leak",
            "name": "Debug config API key leak",
            "stage": "privilege_escalation",
            "trigger": {"endpoint_contains": ["/admin/debug/config"]},
            "next_hints": ["X-Internal-Key header", "/internal/admin-service"],
        },
        {
            "id": "api_key_admin_access",
            "name": "Admin-service access using leaked key",
            "stage": "data_exfiltration",
            "trigger": {
                "endpoint_contains": ["/internal/admin-service"],
                "query_contains": ["x-internal-key", "adminkey"]
            },
            "next_hints": ["/internal/vault/secrets", "/internal/collab/slack"],
        },
        {
            "id": "js_hidden_endpoints",
            "name": "Client JS hidden endpoint discovery",
            "stage": "recon",
            "trigger": {"endpoint_contains": ["/static/js/internal-tools.js"]},
            "next_hints": ["/api/v2/internal/users", "/internal/k8s/dashboard"],
        },
        {
            "id": "sourcemap_logic_leak",
            "name": "Source map internal logic leak",
            "stage": "initial_access",
            "trigger": {"endpoint_contains": ["/static/js/internal-tools.js.map"]},
            "next_hints": ["/admin/debug/config", "/api/internal/storage"],
        },
        {
            "id": "redis_service_probe",
            "name": "Fake Redis service probe",
            "stage": "privilege_escalation",
            "trigger": {"endpoint_contains": ["/internal/cache"]},
            "next_hints": ["/internal/db", "/internal/logs"],
        },
        {
            "id": "k8s_dashboard_access",
            "name": "Kubernetes dashboard exposure",
            "stage": "privilege_escalation",
            "trigger": {"endpoint_contains": ["/internal/k8s/dashboard"]},
            "next_hints": ["/internal/ci/pipeline", "/internal/vault/secrets"],
        },
        {
            "id": "cicd_pipeline_leak",
            "name": "CI/CD token leakage",
            "stage": "data_exfiltration",
            "trigger": {"endpoint_contains": ["/internal/ci/pipeline"]},
            "next_hints": ["/internal/vault/secrets", "/internal/collab/slack"],
        },
        {
            "id": "db_console_access",
            "name": "Database console access",
            "stage": "data_exfiltration",
            "trigger": {"endpoint_contains": ["/admin/database", "/internal/db"]},
            "next_hints": ["/internal/db?table=employees", "/internal/vault/secrets"],
        },
        {
            "id": "lfi_env_dump",
            "name": "LFI environment dump",
            "stage": "privilege_escalation",
            "trigger": {"endpoint_contains": ["/.env", "/files/read"], "query_contains": [".env"]},
            "next_hints": ["/admin/debug/config", "/api/internal/storage"],
        },
        {
            "id": "sudo_escalation_signal",
            "name": "Sudo escalation signal",
            "stage": "persistence",
            "trigger": {
                "endpoint_contains": ["/terminal/exec", "/terminal/shell"],
                "query_contains": ["sudo", "-s"]
            },
            "next_hints": ["/internal/logs/lateral", "/internal/db"],
        },
        {
            "id": "lateral_movement_logs",
            "name": "Lateral movement event exposure",
            "stage": "data_exfiltration",
            "trigger": {"endpoint_contains": ["/internal/logs/lateral"]},
            "next_hints": ["/internal/collab/slack", "/internal/vault/secrets"],
        },
        {
            "id": "employee_creds_dump",
            "name": "Employee credential dump",
            "stage": "data_exfiltration",
            "trigger": {"endpoint_contains": ["/api/internal/employees", "/internal/db"], "query_contains": ["employees"]},
            "next_hints": ["/internal/collab/slack", "/internal/vault/secrets"],
        },
        {
            "id": "crypto_wallet_transactions",
            "name": "Crypto wallet transaction exposure",
            "stage": "data_exfiltration",
            "trigger": {"endpoint_contains": ["/admin/wallet"]},
            "next_hints": ["/admin/wallet/transactions", "/internal/logs"],
        },
        {
            "id": "internal_slack_leak",
            "name": "Internal Slack message leak",
            "stage": "data_exfiltration",
            "trigger": {"endpoint_contains": ["/internal/collab/slack"]},
            "next_hints": ["/internal/vault/secrets", "/internal/admin-service"],
        },
        {
            "id": "secrets_vault_access",
            "name": "Secrets vault access",
            "stage": "data_exfiltration",
            "trigger": {"endpoint_contains": ["/internal/vault/secrets"]},
            "next_hints": ["/internal/logs", "deep archive bucket"],
        },
    ]

    def __init__(self) -> None:
        self._states: Dict[str, ChainState] = {}
        self._ip_index: Dict[str, str] = {}

    def track_event(
        self,
        session_id: str,
        request_data: Dict[str, Any],
        detected_attacks: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        state = self._get_or_create_state(session_id)

        now = datetime.now().timestamp()
        endpoint = str(request_data.get("url", "/"))
        method = str(request_data.get("method", "GET")).upper()
        params = request_data.get("params", {})
        body = request_data.get("body", "")
        headers = request_data.get("headers", {})
        ip = str(request_data.get("ip", "unknown"))
        state.last_seen = now

        if ip and ip != "unknown":
            self._ip_index[ip] = session_id

        if endpoint not in state.endpoints_visited:
            state.endpoints_visited.append(endpoint)

        attack_types = {
            str(item.get("type", "")).lower()
            for item in detected_attacks
            if isinstance(item, dict)
        }
        state.techniques_used.update({t for t in attack_types if t})

        combined_text = f"{params} {body} {headers}".lower()
        newly_unlocked: List[Dict[str, Any]] = []

        for scenario in self.SCENARIOS:
            scenario_id = scenario["id"]
            if scenario_id in state.scenarios_completed:
                continue
            dependency_chain = self.SCENARIO_DEPENDENCIES.get(scenario_id, [])
            if dependency_chain and any(dep not in state.scenarios_completed for dep in dependency_chain):
                continue

            # Prevent direct jumps across multiple stages in one step.
            current_idx = _STAGE_INDEX.get(state.stage, 0)
            target_idx = _STAGE_INDEX.get(scenario["stage"], 0)
            if target_idx > current_idx + 1:
                continue

            if self._matches_trigger(scenario["trigger"], endpoint, method, attack_types, combined_text):
                state.scenarios_completed.add(scenario_id)
                self._advance_stage(state, scenario["stage"])
                event = {
                    "timestamp": now,
                    "event_type": "scenario_unlocked",
                    "stage": state.stage,
                    "scenario_id": scenario_id,
                    "label": scenario["name"],
                    "endpoint": endpoint,
                }
                state.timeline.append(event)
                newly_unlocked.append(
                    {
                        "id": scenario_id,
                        "name": scenario["name"],
                        "stage": scenario["stage"],
                        "next_hints": list(scenario.get("next_hints", [])),
                    }
                )

        self._apply_stage_from_behavior(state, endpoint, attack_types)
        state.progression = round(len(state.scenarios_completed) / max(len(self.SCENARIOS), 1), 4)

        if not state.timeline:
            state.timeline.append(
                {
                    "timestamp": now,
                    "event_type": "session_started",
                    "stage": state.stage,
                    "label": "Session initialized",
                    "endpoint": endpoint,
                }
            )

        return {
            "stage": state.stage,
            "progression": state.progression,
            "scenarios_completed": len(state.scenarios_completed),
            "newly_unlocked": newly_unlocked,
            "timeline": state.timeline[-30:],
            "attack_path": list(state.attack_path),
            "next_hints": self._next_hints(state.stage, state.scenarios_completed),
            "skill_level": self._estimate_skill(state),
            "time_spent_seconds": int(max(0.0, state.last_seen - state.first_seen)),
            "techniques_used": sorted(list(state.techniques_used)),
        }

    def ingest_external_event(
        self,
        source: str,
        event_data: Dict[str, Any],
        session_id: Optional[str] = None,
    ) -> Optional[str]:
        target_session = session_id
        if not target_session:
            ip = str(event_data.get("source_ip") or event_data.get("ip") or "")
            if ip:
                target_session = self._ip_index.get(ip)

        if not target_session:
            return None

        state = self._get_or_create_state(target_session)
        now = float(event_data.get("timestamp", datetime.now().timestamp()))
        state.timeline.append(
            {
                "timestamp": now,
                "event_type": "external_event",
                "stage": state.stage,
                "label": str(event_data.get("description") or event_data.get("event_type") or "external signal"),
                "source": source,
                "endpoint": str(event_data.get("destination") or event_data.get("endpoint") or "external"),
            }
        )
        return target_session

    def can_access(
        self,
        session_id: str,
        required_stage: str,
        required_scenarios: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        state = self._get_or_create_state(session_id)
        if _STAGE_INDEX.get(state.stage, 0) < _STAGE_INDEX.get(required_stage, 0):
            return False, f"Access path incomplete. Explore more to reach {required_stage}."

        required_scenarios = required_scenarios or []
        missing = [item for item in required_scenarios if item not in state.scenarios_completed]
        if missing:
            return False, f"Missing chain steps: {', '.join(missing[:3])}"

        return True, "ok"

    def get_state(self, session_id: str) -> Dict[str, Any]:
        state = self._get_or_create_state(session_id)
        return {
            "session_id": session_id,
            "stage": state.stage,
            "progression": state.progression,
            "scenarios_completed": sorted(list(state.scenarios_completed)),
            "timeline": state.timeline[-40:],
            "attack_path": list(state.attack_path),
            "techniques_used": sorted(list(state.techniques_used)),
            "skill_level": self._estimate_skill(state),
            "time_spent_seconds": int(max(0.0, state.last_seen - state.first_seen)),
            "next_hints": self._next_hints(state.stage, state.scenarios_completed),
        }

    def _get_or_create_state(self, session_id: str) -> ChainState:
        if session_id not in self._states:
            now = datetime.now().timestamp()
            self._states[session_id] = ChainState(
                session_id=session_id,
                first_seen=now,
                last_seen=now,
            )
        return self._states[session_id]

    def _matches_trigger(
        self,
        trigger: Dict[str, Any],
        endpoint: str,
        method: str,
        attack_types: Set[str],
        combined_text: str,
    ) -> bool:
        endpoint_lower = endpoint.lower()

        endpoint_conditions = trigger.get("endpoint_contains", [])
        if endpoint_conditions and not any(part.lower() in endpoint_lower for part in endpoint_conditions):
            return False

        trigger_method = str(trigger.get("method", "")).upper()
        if trigger_method and trigger_method != method:
            return False

        type_conditions = [str(v).lower() for v in trigger.get("attack_types", [])]
        if type_conditions and not any(v in attack_types for v in type_conditions):
            return False

        query_conditions = [str(v).lower() for v in trigger.get("query_contains", [])]
        if query_conditions and not all(v in combined_text for v in query_conditions):
            return False

        return True

    def _apply_stage_from_behavior(self, state: ChainState, endpoint: str, attack_types: Set[str]) -> None:
        endpoint_lower = endpoint.lower()
        if any(v in endpoint_lower for v in ["robots", "sitemap", "health", "version"]):
            self._advance_stage(state, "recon")
        if any(v in endpoint_lower for v in ["login", "forgot-password", "reset-password", "/api/v1/auth/login"]):
            self._advance_stage(state, "initial_access")
        if any(v in endpoint_lower for v in ["/admin", "/debug", "/api/v2", "/api/internal"]):
            self._advance_stage(state, "privilege_escalation")
        if any(v in endpoint_lower for v in ["upload", "terminal/unlocked", "shell"]):
            self._advance_stage(state, "persistence")
        if (
            any(v in endpoint_lower for v in ["vault", "storage", "employees", "internal/db", "internal/logs"])
            and _STAGE_INDEX.get(state.stage, 0) >= _STAGE_INDEX.get("persistence", 0)
        ):
            self._advance_stage(state, "data_exfiltration")

        if any(v in attack_types for v in ["lfi", "ssrf", "jwt_tampering", "command_injection"]):
            self._advance_stage(state, "privilege_escalation")

    def _advance_stage(self, state: ChainState, candidate_stage: str) -> None:
        current_idx = _STAGE_INDEX.get(state.stage, 0)
        candidate_idx = _STAGE_INDEX.get(candidate_stage, 0)
        if candidate_idx >= current_idx and candidate_stage != state.stage:
            state.stage = candidate_stage
            if not state.attack_path or state.attack_path[-1] != candidate_stage:
                state.attack_path.append(candidate_stage)
            state.timeline.append(
                {
                    "timestamp": datetime.now().timestamp(),
                    "event_type": "stage_transition",
                    "stage": candidate_stage,
                    "label": f"Stage advanced to {candidate_stage}",
                    "endpoint": "system",
                }
            )

    def _estimate_skill(self, state: ChainState) -> str:
        scenario_count = len(state.scenarios_completed)
        techniques = len(state.techniques_used)
        if scenario_count >= 12 or techniques >= 8:
            return "advanced"
        if scenario_count >= 5 or techniques >= 4:
            return "intermediate"
        return "basic"

    def _next_hints(self, stage: str, completed: Set[str]) -> List[str]:
        hints: List[str] = []
        for scenario in self.SCENARIOS:
            if scenario["id"] in completed:
                continue
            if scenario["stage"] == stage:
                hints.extend(scenario.get("next_hints", []))
            if len(hints) >= 5:
                break

        if not hints:
            fallback = {
                "recon": ["/static/js/internal-tools.js", "/forgot-password", "/api/v1/health"],
                "initial_access": ["/reset-password?token=", "/api/v2/internal/users", "/admin/debug/config"],
                "privilege_escalation": ["/internal/admin-service", "/api/internal/storage", "/files/upload"],
                "persistence": ["/terminal/unlocked", "/internal/cache", "/internal/logs/lateral"],
                "data_exfiltration": ["/internal/vault/secrets", "/internal/collab/slack", "/internal/db"],
            }
            hints = fallback.get(stage, ["/internal/logs"])

        # Preserve order and remove duplicates
        seen: Set[str] = set()
        ordered: List[str] = []
        for hint in hints:
            if hint in seen:
                continue
            seen.add(hint)
            ordered.append(hint)
        return ordered[:6]


_engine: Optional[AttackChainEngine] = None


def get_attack_chain_engine() -> AttackChainEngine:
    global _engine
    if _engine is None:
        _engine = AttackChainEngine()
    return _engine
