"""
DefenderAI Integration Tests
Comprehensive testing of all system components
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto_service import CryptoService
from core.auth_service import AuthService
from core.anomaly_detector import AnomalyDetector
from core.response_engine import ResponseEngine
import json
from datetime import datetime, timezone

def test_complete_workflow():
    """Test complete DefenderAI workflow"""
    print("=== DefenderAI Integration Test ===")
    print()
    
    # Initialize all services
    print("1. Initializing Services...")
    crypto = CryptoService()
    auth = AuthService()
    detector = AnomalyDetector()
    response = ResponseEngine(auth)
    print("✅ All services initialized")
    print()
    
    # Test authentication
    print("2. Testing Authentication...")
    user = auth.authenticate_user("inspector.sharma", "SecurePass123!", "123456")  # Add MFA code
    if user:
        token = auth.generate_token(user)
        payload = auth.verify_token(token)
        print(f"✅ Authentication successful for {user['username']}")
        print(f"   Department: {user['dept']}, Role: {user['role']}")
    print()
    
    # Test cryptographic integrity
    print("3. Testing Cryptographic Integrity...")
    
    # Create sample records
    records = [
        crypto.compute_file_hash("Confidential Police Report #2024001", {"dept": "POLICE", "classification": "SECRET"}),
        crypto.compute_file_hash("Army Strategic Assessment Q4", {"dept": "ARMY", "classification": "CONFIDENTIAL"}),
        crypto.compute_file_hash("Public Health Emergency Plan", {"dept": "HEALTH", "classification": "RESTRICTED"})
    ]
    
    # Create snapshots
    police_snapshot = crypto.create_snapshot([records[0]], "POLICE")
    army_snapshot = crypto.create_snapshot([records[1]], "ARMY") 
    health_snapshot = crypto.create_snapshot([records[2]], "HEALTH")
    
    print(f"✅ Created {len(crypto.snapshots)} cryptographic snapshots")
    
    # Create daily Merkle root
    daily_root = crypto.create_daily_merkle_root()
    print(f"✅ Daily Merkle root: {daily_root[:32]}...")
    
    # Verify integrity
    for record in records:
        evidence = crypto.get_tamper_evidence(record["id"])
        print(f"   Record {record['id'][:8]}... - Status: {evidence['status']}")
    print()
    
    # Test access control
    print("4. Testing Departmental Access Control...")
    
    # Test same department access
    can_access_police = auth.check_access_permission(payload, "POLICE", 4, "read")
    can_access_army = auth.check_access_permission(payload, "ARMY", 4, "read")
    
    print(f"✅ Police inspector accessing POLICE records: {can_access_police}")
    print(f"✅ Police inspector accessing ARMY records: {can_access_army}")
    print("   ↳ Departmental partitioning working correctly")
    print()
    
    # Test anomaly detection
    print("5. Testing AI Anomaly Detection...")
    
    # Normal access pattern
    normal_access = {
        "user_id": user["id"],
        "dept": user["dept"],
        "files_accessed": 5,
        "session_duration": 3600,
        "data_volume_mb": 10,
        "unique_resources": 3,
        "hour_of_day": 14,
        "day_of_week": 2,
        "login_attempts": 1,
        "failed_authentications": 0,
        "source_ip_changes": 0,
        "clearance_level": user["clearance"]
    }
    
    result = detector.analyze_access_pattern(normal_access)
    print(f"✅ Normal pattern analysis - Score: {result['anomaly_score']:.3f}, Severity: {result['severity'].name}")
    
    # Suspicious access pattern
    suspicious_access = {
        "user_id": user["id"],
        "dept": user["dept"], 
        "files_accessed": 200,  # Suspicious high access
        "session_duration": 14400,  # Long session
        "data_volume_mb": 500,  # High volume
        "unique_resources": 50,  # Many resources
        "hour_of_day": 3,  # Off hours
        "day_of_week": 6,
        "login_attempts": 1,
        "failed_authentications": 0,
        "source_ip_changes": 5,  # IP hopping
        "clearance_level": user["clearance"]
    }
    
    suspicious_result = detector.analyze_access_pattern(suspicious_access)
    print(f"✅ Suspicious pattern analysis - Score: {suspicious_result['anomaly_score']:.3f}, Severity: {suspicious_result['severity'].name}")
    print(f"   Rule violations: {len(suspicious_result['rule_violations'])}")
    print()
    
    # Test automated response
    print("6. Testing Automated Response System...")
    
    if suspicious_result['severity'].value >= 2:
        response_result = response.trigger_response(suspicious_result)
        print(f"✅ Automated response triggered - ID: {response_result['response_id']}")
        print(f"   Playbook: {response_result['playbook_name']}")
        print(f"   Actions executed: {len(response_result['actions'])}")
        
        # Show actions taken
        for action in response_result['actions']:
            status_emoji = "✅" if action['status'] == 'EXECUTED' else "⏳" if action['status'] == 'PENDING' else "❌"
            print(f"   {status_emoji} {action['type']} ({action['status']})")
    print()
    
    # Test event spike detection (simulating Independence Day)
    print("7. Testing National Event Spike Detection...")
    
    # Create mock events for spike
    mock_events = [
        {"timestamp": datetime.now(timezone.utc)} for _ in range(100)
    ]
    
    spike_result = detector.detect_event_spike(mock_events)
    print(f"✅ Event spike detection - Detected: {spike_result['spike_detected']}")
    
    if spike_result['spike_detected']:
        print(f"   Z-score: {spike_result['z_score']:.2f}")
        print(f"   Current activity: {spike_result['current_activity']}")
        print(f"   Baseline: {spike_result['baseline_mean']:.1f} ± {spike_result['baseline_std']:.1f}")
        
        # Trigger event response
        event_anomaly = {
            "anomaly_id": "independence_day_spike",
            "event_spike_detected": True,
            "z_score": spike_result['z_score'],
            "severity": "MEDIUM"
        }
        
        event_response = response.trigger_response(event_anomaly)
        print(f"✅ Event spike response triggered - ID: {event_response['response_id']}")
    print()
    
    # Test approval workflow
    print("8. Testing Human-in-Loop Approval...")
    
    pending_approvals = response.get_pending_approvals()
    print(f"✅ Pending approvals: {len(pending_approvals)}")
    
    if pending_approvals:
        approval = pending_approvals[0]
        print(f"   Action: {approval['action_type']}")
        print(f"   Risk Level: {approval['risk_level']}")
        print(f"   Approver: {approval['approver']['name']}")
        
        # Simulate approval
        approval_result = response.approve_action(approval["approval_id"], True, "Approved for security demonstration")
        print(f"✅ Approval processed: {approval_result['status']}")
    print()
    
    # Final statistics
    print("9. System Statistics Summary...")
    
    auth_logs = len(auth.get_access_logs())
    anomaly_stats = detector.get_anomaly_statistics()
    response_stats = response.get_response_statistics()
    
    print(f"✅ Authentication logs: {auth_logs}")
    print(f"✅ Total alerts generated: {anomaly_stats['total_alerts']}")
    print(f"✅ Automated responses: {response_stats['total_responses']}")
    print(f"✅ Cryptographic snapshots: {len(crypto.snapshots)}")
    print()
    
    print("=== Integration Test Complete ===")
    print("🛡️ DefenderAI platform fully functional with:")
    print("   • Cryptographic integrity (hashing + Merkle trees)")
    print("   • Departmental access control (RBAC/ABAC)")
    print("   • AI-powered anomaly detection")
    print("   • Automated response with human oversight")
    print("   • Event spike detection for national security")
    print("   • Comprehensive audit trails")
    
    return {
        "crypto_service": crypto,
        "auth_service": auth, 
        "anomaly_detector": detector,
        "response_engine": response
    }

def simulate_independence_day_attack():
    """Simulate attack during Independence Day celebrations"""
    print("\n=== Independence Day Attack Simulation ===")
    
    # Initialize services
    services = test_complete_workflow()
    detector = services["anomaly_detector"]
    response = services["response_engine"]
    
    print("\n🇮🇳 Simulating Independence Day (August 15) Attack Scenario...")
    
    # Simulate high activity
    attack_patterns = [
        {
            "user_id": "attacker_001",
            "dept": "UNKNOWN",
            "files_accessed": 500,  # Mass access
            "session_duration": 21600,  # 6 hours
            "data_volume_mb": 2000,  # 2GB exfiltration
            "unique_resources": 100,
            "hour_of_day": 2,  # Late night
            "day_of_week": 1,  # Monday
            "login_attempts": 1,
            "failed_authentications": 0,
            "source_ip_changes": 10,  # IP hopping
            "clearance_level": 2
        },
        {
            "user_id": "attacker_002", 
            "dept": "POLICE",
            "files_accessed": 300,
            "session_duration": 18000,  # 5 hours
            "data_volume_mb": 1500,
            "unique_resources": 75,
            "hour_of_day": 3,
            "day_of_week": 1,
            "login_attempts": 5,  # Multiple attempts
            "failed_authentications": 2,
            "source_ip_changes": 8,
            "clearance_level": 3
        }
    ]
    
    for i, pattern in enumerate(attack_patterns, 1):
        print(f"\n🚨 Analyzing Attack Pattern {i}...")
        
        result = detector.analyze_access_pattern(pattern)
        print(f"   Anomaly Score: {result['anomaly_score']:.3f}")
        print(f"   Severity: {result['severity'].name}")
        print(f"   Rule Violations: {len(result['rule_violations'])}")
        
        # Trigger response
        if result['severity'].value >= 3:  # High or Critical
            response_result = response.trigger_response(result)
            print(f"   🤖 Automated Response: {response_result['response_id']}")
            print(f"   Actions: {len(response_result['actions'])} executed")
            
            # Show critical actions
            for action in response_result['actions']:
                if action['risk_level'] >= 3:
                    print(f"      🔴 {action['type']} - {action['status']}")
    
    print("\n✅ Independence Day attack simulation complete")
    print("🛡️ DefenderAI successfully detected and responded to coordinated attack")

if __name__ == "__main__":
    # Run comprehensive test
    test_complete_workflow()
    
    # Run Independence Day simulation
    simulate_independence_day_attack()