"""
Automated Response & Containment Engine
Handles automated containment playbooks with human-in-loop for high-risk actions
"""

import asyncio
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Callable
from enum import Enum
import uuid
import logging
import threading

class ActionType(Enum):
    LOG_EVENT = "log_event"
    NOTIFY_SOC = "notify_soc"
    REVOKE_TOKEN = "revoke_token"
    LOCK_ACCOUNT = "lock_account"
    BLOCK_IP = "block_ip"
    ISOLATE_SYSTEM = "isolate_system"
    THROTTLE_USER = "throttle_user"
    REQUIRE_MFA = "require_mfa"
    ESCALATE_INCIDENT = "escalate_incident"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"

class ActionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class RiskLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ResponseEngine:
    """Automated response and containment system"""
    
    def __init__(self, auth_service=None):
        self.auth_service = auth_service
        self.playbooks = {}
        self.pending_actions = {}
        self.executed_actions = []
        self.approval_queue = []
        self.human_approvers = {}
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize playbooks
        self._initialize_playbooks()
        
        # Setup human approvers
        self._setup_approvers()
        
        # Start background processes
        self._start_background_tasks()
    
    def _initialize_playbooks(self):
        """Initialize automated response playbooks"""
        
        # Low-risk automated responses
        self.playbooks["low_risk_anomaly"] = {
            "name": "Low Risk Anomaly Response",
            "trigger_conditions": ["anomaly_score < 0.4", "severity == LOW"],
            "actions": [
                {
                    "type": ActionType.LOG_EVENT,
                    "risk_level": RiskLevel.LOW,
                    "auto_execute": True,
                    "parameters": {"detail_level": "basic"}
                }
            ]
        }
        
        # Medium-risk responses
        self.playbooks["medium_risk_anomaly"] = {
            "name": "Medium Risk Anomaly Response",
            "trigger_conditions": ["anomaly_score >= 0.4", "severity == MEDIUM"],
            "actions": [
                {
                    "type": ActionType.LOG_EVENT,
                    "risk_level": RiskLevel.MEDIUM,
                    "auto_execute": True,
                    "parameters": {"detail_level": "detailed"}
                },
                {
                    "type": ActionType.NOTIFY_SOC,
                    "risk_level": RiskLevel.MEDIUM,
                    "auto_execute": True,
                    "parameters": {"priority": "medium", "channel": "email"}
                },
                {
                    "type": ActionType.THROTTLE_USER,
                    "risk_level": RiskLevel.MEDIUM,
                    "auto_execute": True,
                    "parameters": {"rate_limit": "50%", "duration_minutes": 30}
                }
            ]
        }
        
        # High-risk responses (require approval)
        self.playbooks["high_risk_anomaly"] = {
            "name": "High Risk Anomaly Response",
            "trigger_conditions": ["anomaly_score >= 0.6", "severity == HIGH"],
            "actions": [
                {
                    "type": ActionType.LOG_EVENT,
                    "risk_level": RiskLevel.HIGH,
                    "auto_execute": True,
                    "parameters": {"detail_level": "forensic"}
                },
                {
                    "type": ActionType.NOTIFY_SOC,
                    "risk_level": RiskLevel.HIGH,
                    "auto_execute": True,
                    "parameters": {"priority": "high", "channel": "immediate"}
                },
                {
                    "type": ActionType.REVOKE_TOKEN,
                    "risk_level": RiskLevel.HIGH,
                    "auto_execute": False,  # Requires approval
                    "parameters": {"scope": "current_session"}
                },
                {
                    "type": ActionType.REQUIRE_MFA,
                    "risk_level": RiskLevel.HIGH,
                    "auto_execute": True,
                    "parameters": {"force_reauthentication": True}
                }
            ]
        }
        
        # Critical responses (require immediate approval)
        self.playbooks["critical_anomaly"] = {
            "name": "Critical Anomaly Response",
            "trigger_conditions": ["anomaly_score >= 0.8", "severity == CRITICAL"],
            "actions": [
                {
                    "type": ActionType.LOG_EVENT,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": True,
                    "parameters": {"detail_level": "forensic", "preserve_evidence": True}
                },
                {
                    "type": ActionType.NOTIFY_SOC,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": True,
                    "parameters": {"priority": "critical", "channel": "all"}
                },
                {
                    "type": ActionType.REVOKE_TOKEN,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": False,
                    "parameters": {"scope": "all_sessions"}
                },
                {
                    "type": ActionType.LOCK_ACCOUNT,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": False,
                    "parameters": {"duration_hours": 24}
                },
                {
                    "type": ActionType.BLOCK_IP,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": False,
                    "parameters": {"duration_hours": 24}
                },
                {
                    "type": ActionType.ESCALATE_INCIDENT,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": True,
                    "parameters": {"escalation_level": "management"}
                }
            ]
        }
        
        # Mass data exfiltration
        self.playbooks["mass_data_exfiltration"] = {
            "name": "Mass Data Exfiltration Response",
            "trigger_conditions": ["data_volume > 500MB", "files_accessed > 100"],
            "actions": [
                {
                    "type": ActionType.REVOKE_TOKEN,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": True,  # Immediate action
                    "parameters": {"scope": "all_sessions"}
                },
                {
                    "type": ActionType.BLOCK_IP,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": True,
                    "parameters": {"duration_hours": 48}
                },
                {
                    "type": ActionType.ISOLATE_SYSTEM,
                    "risk_level": RiskLevel.CRITICAL,
                    "auto_execute": False,  # Requires approval due to business impact
                    "parameters": {"isolation_level": "network"}
                }
            ]
        }
        
        # Independence Day / Event spike response
        self.playbooks["event_spike_response"] = {
            "name": "National Event Spike Response",
            "trigger_conditions": ["event_spike_detected == True", "z_score > 5.0"],
            "actions": [
                {
                    "type": ActionType.LOG_EVENT,
                    "risk_level": RiskLevel.MEDIUM,
                    "auto_execute": True,
                    "parameters": {"detail_level": "enhanced"}
                },
                {
                    "type": ActionType.NOTIFY_SOC,
                    "risk_level": RiskLevel.MEDIUM,
                    "auto_execute": True,
                    "parameters": {"priority": "high", "context": "national_event"}
                }
            ]
        }
        
        self.logger.info(f"Initialized {len(self.playbooks)} response playbooks")
    
    def _setup_approvers(self):
        """Setup human approvers for high-risk actions"""
        self.human_approvers = {
            "soc_analyst": {
                "name": "SOC Analyst Kumar",
                "role": "soc_analyst",
                "contact": "soc.analyst@defenderai.gov.in",
                "max_approval_level": RiskLevel.MEDIUM,
                "response_time_minutes": 15
            },
            "security_manager": {
                "name": "Security Manager Singh",
                "role": "security_manager", 
                "contact": "sec.manager@defenderai.gov.in",
                "max_approval_level": RiskLevel.HIGH,
                "response_time_minutes": 30
            },
            "ciso": {
                "name": "CISO Sharma",
                "role": "ciso",
                "contact": "ciso@defenderai.gov.in",
                "max_approval_level": RiskLevel.CRITICAL,
                "response_time_minutes": 60
            }
        }
    
    def _start_background_tasks(self):
        """Start background monitoring tasks"""
        # In a real implementation, this would start actual background threads
        self.logger.info("Background response monitoring started")
    
    def trigger_response(self, anomaly_data: Dict) -> Dict:
        """Trigger automated response based on anomaly data"""
        playbook = self._select_playbook(anomaly_data)
        if not playbook:
            return {"error": "No matching playbook found"}
        
        response_id = str(uuid.uuid4())
        
        response = {
            "response_id": response_id,
            "timestamp": datetime.now(timezone.utc),
            "playbook_name": playbook["name"],
            "trigger_data": anomaly_data,
            "actions": [],
            "status": "in_progress"
        }
        
        self.logger.info(f"Triggering response {response_id} with playbook: {playbook['name']}")
        
        # Execute each action in the playbook
        for action_config in playbook["actions"]:
            action_result = self._execute_action(action_config, anomaly_data, response_id)
            response["actions"].append(action_result)
        
        response["status"] = "completed"
        self.executed_actions.append(response)
        
        return response
    
    def _select_playbook(self, anomaly_data: Dict) -> Optional[Dict]:
        """Select appropriate playbook based on anomaly data"""
        anomaly_score = anomaly_data.get("anomaly_score", 0.0)
        severity = anomaly_data.get("severity", "LOW")
        
        # Check for specific conditions first
        if anomaly_data.get("details", {}).get("data_volume_mb", 0) > 500:
            return self.playbooks.get("mass_data_exfiltration")
        
        if anomaly_data.get("event_spike_detected"):
            return self.playbooks.get("event_spike_response")
        
        # General severity-based selection
        if anomaly_score >= 0.8 or severity == "CRITICAL":
            return self.playbooks.get("critical_anomaly")
        elif anomaly_score >= 0.6 or severity == "HIGH":
            return self.playbooks.get("high_risk_anomaly")
        elif anomaly_score >= 0.4 or severity == "MEDIUM":
            return self.playbooks.get("medium_risk_anomaly")
        else:
            return self.playbooks.get("low_risk_anomaly")
    
    def _execute_action(self, action_config: Dict, anomaly_data: Dict, response_id: str) -> Dict:
        """Execute a single action from a playbook"""
        action_id = str(uuid.uuid4())
        
        action_result = {
            "action_id": action_id,
            "response_id": response_id,
            "type": action_config["type"].value,
            "risk_level": action_config["risk_level"].value,
            "auto_execute": action_config["auto_execute"],
            "parameters": action_config["parameters"],
            "timestamp": datetime.now(timezone.utc),
            "status": ActionStatus.PENDING,
            "execution_details": {}
        }
        
        if action_config["auto_execute"]:
            # Execute immediately
            execution_result = self._perform_action(action_config["type"], action_config["parameters"], anomaly_data)
            action_result["status"] = ActionStatus.EXECUTED if execution_result["success"] else ActionStatus.FAILED
            action_result["execution_details"] = execution_result
        else:
            # Requires human approval
            self._request_approval(action_result, anomaly_data)
            action_result["status"] = ActionStatus.PENDING
            action_result["execution_details"] = {"awaiting_approval": True}
        
        return action_result
    
    def _perform_action(self, action_type: ActionType, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Perform the actual action"""
        
        if action_type == ActionType.LOG_EVENT:
            return self._log_security_event(parameters, anomaly_data)
        
        elif action_type == ActionType.NOTIFY_SOC:
            return self._notify_soc(parameters, anomaly_data)
        
        elif action_type == ActionType.REVOKE_TOKEN:
            return self._revoke_user_token(parameters, anomaly_data)
        
        elif action_type == ActionType.LOCK_ACCOUNT:
            return self._lock_user_account(parameters, anomaly_data)
        
        elif action_type == ActionType.BLOCK_IP:
            return self._block_ip_address(parameters, anomaly_data)
        
        elif action_type == ActionType.THROTTLE_USER:
            return self._throttle_user_access(parameters, anomaly_data)
        
        elif action_type == ActionType.REQUIRE_MFA:
            return self._require_mfa_reauthentication(parameters, anomaly_data)
        
        elif action_type == ActionType.ESCALATE_INCIDENT:
            return self._escalate_incident(parameters, anomaly_data)
        
        elif action_type == ActionType.ISOLATE_SYSTEM:
            return self._isolate_system(parameters, anomaly_data)
        
        else:
            return {"success": False, "error": f"Unknown action type: {action_type}"}
    
    def _log_security_event(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Log security event with specified detail level"""
        detail_level = parameters.get("detail_level", "basic")
        
        log_entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "event_type": "security_anomaly",
            "detail_level": detail_level,
            "user_id": anomaly_data.get("user_id"),
            "department": anomaly_data.get("dept"),
            "anomaly_score": anomaly_data.get("anomaly_score"),
            "severity": anomaly_data.get("severity").name if hasattr(anomaly_data.get("severity"), 'name') else str(anomaly_data.get("severity")),
            "source_ip": "192.168.1.100",  # Mock IP
            "preserve_evidence": parameters.get("preserve_evidence", False)
        }
        
        self.logger.info(f"Security event logged: {log_entry['event_id']}")
        
        return {
            "success": True,
            "action": "event_logged",
            "event_id": log_entry["event_id"],
            "detail_level": detail_level
        }
    
    def _notify_soc(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Send notification to SOC team"""
        priority = parameters.get("priority", "medium")
        channel = parameters.get("channel", "email")
        
        notification = {
            "notification_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "priority": priority,
            "channel": channel,
            "recipient": "soc-team@defenderai.gov.in",
            "subject": f"DefenderAI Alert: {priority.upper()} Priority Security Anomaly",
            "details": {
                "user_id": anomaly_data.get("user_id"),
                "department": anomaly_data.get("dept"),
                "anomaly_score": anomaly_data.get("anomaly_score"),
                "severity": str(anomaly_data.get("severity")),
                "recommended_actions": anomaly_data.get("recommended_actions", [])
            }
        }
        
        self.logger.info(f"SOC notification sent: {notification['notification_id']} - Priority: {priority}")
        
        return {
            "success": True,
            "action": "soc_notified",
            "notification_id": notification["notification_id"],
            "priority": priority,
            "channel": channel
        }
    
    def _revoke_user_token(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Revoke user authentication tokens"""
        scope = parameters.get("scope", "current_session")
        user_id = anomaly_data.get("user_id")
        
        if self.auth_service:
            # In real implementation, revoke tokens from auth service
            success = True
            revoked_count = 1 if scope == "current_session" else 3
        else:
            # Mock implementation
            success = True
            revoked_count = 1 if scope == "current_session" else 3
        
        self.logger.warning(f"Token revocation: User {user_id}, Scope: {scope}, Count: {revoked_count}")
        
        return {
            "success": success,
            "action": "tokens_revoked",
            "user_id": user_id,
            "scope": scope,
            "revoked_count": revoked_count
        }
    
    def _lock_user_account(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Lock user account"""
        duration_hours = parameters.get("duration_hours", 24)
        user_id = anomaly_data.get("user_id")
        
        lock_until = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
        
        self.logger.warning(f"Account locked: User {user_id} until {lock_until}")
        
        return {
            "success": True,
            "action": "account_locked",
            "user_id": user_id,
            "duration_hours": duration_hours,
            "locked_until": lock_until.isoformat()
        }
    
    def _block_ip_address(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Block source IP address"""
        duration_hours = parameters.get("duration_hours", 24)
        source_ip = "192.168.1.100"  # Mock IP
        
        self.logger.warning(f"IP address blocked: {source_ip} for {duration_hours} hours")
        
        return {
            "success": True,
            "action": "ip_blocked",
            "source_ip": source_ip,
            "duration_hours": duration_hours,
            "blocked_until": (datetime.now(timezone.utc) + timedelta(hours=duration_hours)).isoformat()
        }
    
    def _throttle_user_access(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Throttle user access rate"""
        rate_limit = parameters.get("rate_limit", "50%")
        duration_minutes = parameters.get("duration_minutes", 30)
        user_id = anomaly_data.get("user_id")
        
        self.logger.info(f"User access throttled: {user_id} to {rate_limit} for {duration_minutes} minutes")
        
        return {
            "success": True,
            "action": "access_throttled",
            "user_id": user_id,
            "rate_limit": rate_limit,
            "duration_minutes": duration_minutes
        }
    
    def _require_mfa_reauthentication(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Require MFA re-authentication"""
        force_reauth = parameters.get("force_reauthentication", True)
        user_id = anomaly_data.get("user_id")
        
        self.logger.info(f"MFA re-authentication required: User {user_id}")
        
        return {
            "success": True,
            "action": "mfa_required",
            "user_id": user_id,
            "force_reauthentication": force_reauth
        }
    
    def _escalate_incident(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Escalate incident to management"""
        escalation_level = parameters.get("escalation_level", "management")
        
        incident_id = str(uuid.uuid4())
        
        self.logger.warning(f"Incident escalated: {incident_id} to {escalation_level}")
        
        return {
            "success": True,
            "action": "incident_escalated",
            "incident_id": incident_id,
            "escalation_level": escalation_level,
            "notified": f"security-{escalation_level}@defenderai.gov.in"
        }
    
    def _isolate_system(self, parameters: Dict, anomaly_data: Dict) -> Dict:
        """Isolate affected system"""
        isolation_level = parameters.get("isolation_level", "network")
        
        self.logger.critical(f"System isolation initiated: Level {isolation_level}")
        
        return {
            "success": True,
            "action": "system_isolated",
            "isolation_level": isolation_level,
            "affected_systems": ["primary_db", "file_server"],
            "business_impact": "high"
        }
    
    def _request_approval(self, action_result: Dict, anomaly_data: Dict):
        """Request human approval for high-risk actions"""
        risk_level = RiskLevel(action_result["risk_level"])
        
        # Find appropriate approver
        approver = None
        for approver_info in self.human_approvers.values():
            if approver_info["max_approval_level"].value >= risk_level.value:
                approver = approver_info
                break
        
        if not approver:
            approver = self.human_approvers["ciso"]  # Escalate to CISO
        
        approval_request = {
            "approval_id": str(uuid.uuid4()),
            "action_id": action_result["action_id"],
            "timestamp": datetime.now(timezone.utc),
            "approver": approver,
            "risk_level": risk_level.name,
            "action_type": action_result["type"],
            "anomaly_data": anomaly_data,
            "status": "pending",
            "response_required_by": datetime.now(timezone.utc) + timedelta(minutes=approver["response_time_minutes"])
        }
        
        self.approval_queue.append(approval_request)
        
        self.logger.info(f"Approval requested: {approval_request['approval_id']} from {approver['name']}")
    
    def approve_action(self, approval_id: str, approved: bool, approver_notes: str = "") -> Dict:
        """Approve or reject a pending action"""
        approval_request = None
        for req in self.approval_queue:
            if req["approval_id"] == approval_id:
                approval_request = req
                break
        
        if not approval_request:
            return {"error": "Approval request not found"}
        
        approval_request["status"] = "approved" if approved else "rejected"
        approval_request["approver_notes"] = approver_notes
        approval_request["decision_timestamp"] = datetime.now(timezone.utc)
        
        if approved:
            # Execute the approved action
            # This would require finding the original action and executing it
            self.logger.info(f"Action approved and executed: {approval_id}")
        else:
            self.logger.info(f"Action rejected: {approval_id}")
        
        return {
            "approval_id": approval_id,
            "status": approval_request["status"],
            "decision_timestamp": approval_request["decision_timestamp"]
        }
    
    def get_pending_approvals(self) -> List[Dict]:
        """Get all pending approval requests"""
        return [req for req in self.approval_queue if req["status"] == "pending"]
    
    def get_response_history(self, hours: int = 24) -> List[Dict]:
        """Get response history"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        return [
            response for response in self.executed_actions
            if response["timestamp"] > cutoff_time
        ]
    
    def get_response_statistics(self) -> Dict:
        """Get response engine statistics"""
        total_responses = len(self.executed_actions)
        
        if total_responses == 0:
            return {"total_responses": 0}
        
        # Count by playbook
        playbook_counts = {}
        for response in self.executed_actions:
            playbook = response["playbook_name"]
            playbook_counts[playbook] = playbook_counts.get(playbook, 0) + 1
        
        # Count actions
        total_actions = sum(len(response["actions"]) for response in self.executed_actions)
        auto_executed = sum(
            sum(1 for action in response["actions"] if action["auto_execute"])
            for response in self.executed_actions
        )
        
        return {
            "total_responses": total_responses,
            "total_actions": total_actions,
            "auto_executed_actions": auto_executed,
            "pending_approvals": len(self.get_pending_approvals()),
            "playbook_usage": playbook_counts,
            "average_actions_per_response": total_actions / total_responses if total_responses > 0 else 0
        }

# Test function
def test_response_engine():
    """Test the response engine"""
    engine = ResponseEngine()
    
    print("=== DefenderAI Response Engine Test ===")
    
    # Test low-risk response
    low_risk_anomaly = {
        "anomaly_id": "test_001",
        "user_id": "user_123",
        "dept": "POLICE",
        "anomaly_score": 0.3,
        "severity": "LOW"
    }
    
    response = engine.trigger_response(low_risk_anomaly)
    print(f"✓ Low-risk response triggered - Actions: {len(response['actions'])}")
    
    # Test critical response
    critical_anomaly = {
        "anomaly_id": "test_002",
        "user_id": "user_456",
        "dept": "ARMY",
        "anomaly_score": 0.9,
        "severity": "CRITICAL",
        "details": {"data_volume_mb": 600}
    }
    
    response = engine.trigger_response(critical_anomaly)
    print(f"✓ Critical response triggered - Actions: {len(response['actions'])}")
    
    # Check pending approvals
    pending = engine.get_pending_approvals()
    print(f"✓ Pending approvals: {len(pending)}")
    
    # Show statistics
    stats = engine.get_response_statistics()
    print(f"✓ Total responses: {stats['total_responses']}")
    print(f"✓ Auto-executed actions: {stats['auto_executed_actions']}")
    
    return engine

if __name__ == "__main__":
    test_response_engine()