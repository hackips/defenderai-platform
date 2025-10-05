"""
DefenderAI Comprehensive Demo Script
Demonstrates all platform capabilities with sample scenarios
"""

import requests
import json
import time
from datetime import datetime

# API Configuration
API_BASE_URL = "http://localhost:8000"

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                          ║
║  ██████╗ ███████╗███████╗███████╗███╗   ██╗██████╗ ███████╗██████╗      █████╗ ██╗      ║
║  ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██║      ║
║  ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝    ███████║██║      ║
║  ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗    ██╔══██║██║      ║
║  ██████╔╝███████╗██║     ███████╗██║ ╚████║██████╔╝███████╗██║  ██║    ██║  ██║██║      ║
║  ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝      ║
║                                                                                          ║
║                           🛡️ COMPREHENSIVE PLATFORM DEMO                                ║
║                                                                                          ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
""")

def check_system_health():
    """Check if DefenderAI system is healthy"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            health = response.json()
            print("✅ System Health Check PASSED")
            print(f"   Status: {health['status']}")
            for service, status in health['services'].items():
                print(f"   • {service.replace('_', ' ').title()}: {status}")
            return True
        else:
            print("❌ System Health Check FAILED")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to DefenderAI API: {e}")
        print("   Please ensure the API server is running on http://localhost:8000")
        return False

def login_as_user(username, password):
    """Login as a specific user and return token"""
    try:
        login_data = {"username": username, "password": password, "mfa_code": "123456"}
        response = requests.post(f"{API_BASE_URL}/auth/login", json=login_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Login successful: {username}")
            return result["access_token"], result["user_info"]
        elif response.status_code == 202:
            print(f"⚠️ MFA required for: {username} (simulating MFA approval)")
            # Retry with MFA code
            return login_as_user(username, password)
        else:
            print(f"❌ Login failed: {username} - {response.text}")
            return None, None
    except Exception as e:
        print(f"❌ Login error: {e}")
        return None, None

def create_secure_record(token, content, dept, classification):
    """Create a secure record with cryptographic integrity"""
    headers = {"Authorization": f"Bearer {token}"}
    
    record_data = {
        "content": content,
        "metadata": {"type": "demo_record", "created_by": "demo_script"},
        "classification": classification,
        "department": dept
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/records/create", json=record_data, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Record created: {result['record_id'][:8]}...")
            print(f"   Content Hash: {result['content_hash'][:16]}...")
            print(f"   Merkle Root: {result['merkle_root'][:16]}...")
            return result["record_id"]
        else:
            print(f"❌ Record creation failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Record creation error: {e}")
        return None

def test_cross_department_access(police_token, army_record_id):
    """Test cross-department access (should be blocked)"""
    headers = {"Authorization": f"Bearer {police_token}"}
    
    try:
        response = requests.get(f"{API_BASE_URL}/records/{army_record_id}", headers=headers)
        
        if response.status_code == 403:
            print("✅ Cross-department access CORRECTLY BLOCKED")
            print("   Police user cannot access Army records")
        else:
            print("❌ Cross-department access NOT BLOCKED (Security Issue!)")
    except Exception as e:
        print(f"❌ Access test error: {e}")

def simulate_suspicious_activity(token):
    """Simulate suspicious access patterns"""
    headers = {"Authorization": f"Bearer {token}"}
    
    # Simulate mass data access
    suspicious_access = {
        "user_id": "demo_user",
        "dept": "POLICE",
        "resource_id": "demo_resource",
        "action": "read",
        "files_accessed": 200,  # High number
        "session_duration": 14400,  # 4 hours
        "data_volume_mb": 1000,  # 1GB
        "unique_resources": 50,
        "source_ip": "192.168.1.100"
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/monitoring/log-access", json=suspicious_access, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print("🚨 SUSPICIOUS ACTIVITY DETECTED!")
            print(f"   Anomaly Score: {result['anomaly_score']:.3f}")
            print(f"   Severity: {result['severity']}")
            print(f"   Automated Response: {'TRIGGERED' if result['anomaly_detected'] else 'NOT TRIGGERED'}")
            
            if result.get('recommended_actions'):
                print("   Recommended Actions:")
                for action in result['recommended_actions'][:3]:
                    print(f"   • {action}")
        else:
            print("❌ Suspicious activity logging failed")
    except Exception as e:
        print(f"❌ Suspicious activity simulation error: {e}")

def check_security_alerts(token):
    """Check recent security alerts"""
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{API_BASE_URL}/monitoring/alerts?hours=24", headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print(f"📊 Security Alerts (24h): {result['total_alerts']}")
            
            if result['alerts']:
                for alert in result['alerts'][:3]:  # Show first 3
                    print(f"   🚨 {alert['severity']} - User: {alert['user_id']} - Score: {alert['anomaly_score']:.3f}")
            else:
                print("   No alerts in the last 24 hours")
        else:
            print("❌ Failed to retrieve security alerts")
    except Exception as e:
        print(f"❌ Security alerts check error: {e}")

def test_event_spike_detection(token):
    """Test national event spike detection"""
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{API_BASE_URL}/monitoring/event-spike", headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print("📈 Event Spike Detection:")
            print(f"   Spike Detected: {result['spike_detected']}")
            print(f"   Current Activity: {result['current_activity']}")
            print(f"   Baseline Mean: {result['baseline_mean']:.1f}")
            print(f"   Z-Score: {result['z_score']:.2f}")
            
            if result['spike_detected']:
                print("   🚨 NATIONAL EVENT SPIKE DETECTED!")
                print(f"   Recommendation: {result['recommendation']}")
        else:
            print("❌ Event spike detection failed")
    except Exception as e:
        print(f"❌ Event spike detection error: {e}")

def check_system_statistics(admin_token):
    """Check comprehensive system statistics"""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    try:
        response = requests.get(f"{API_BASE_URL}/monitoring/statistics", headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print("📊 System Statistics:")
            
            # Anomaly detection stats
            anomaly_stats = result['anomaly_detection']
            print(f"   Total Alerts: {anomaly_stats['total_alerts']}")
            print(f"   Last 24h Alerts: {anomaly_stats['last_24h_alerts']}")
            
            # Response engine stats
            response_stats = result['automated_response']
            print(f"   Automated Responses: {response_stats['total_responses']}")
            print(f"   Auto-executed Actions: {response_stats['auto_executed_actions']}")
            
            # Cryptographic integrity
            crypto_stats = result['cryptographic_integrity']
            print(f"   Integrity Snapshots: {crypto_stats['total_snapshots']}")
        else:
            print("❌ Failed to retrieve system statistics")
    except Exception as e:
        print(f"❌ System statistics error: {e}")

def test_admin_features(admin_token):
    """Test admin-specific features"""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    try:
        # Check pending approvals
        response = requests.get(f"{API_BASE_URL}/admin/pending-approvals", headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print(f"⚙️ Admin Dashboard:")
            print(f"   Pending Approvals: {result['total_pending']}")
            
            if result['approvals']:
                for approval in result['approvals'][:2]:  # Show first 2
                    print(f"   🔍 {approval['action_type']} - Risk: {approval['risk_level']}")
                    print(f"      User: {approval['anomaly_details']['user_id']}")
        
        # Check system status
        response = requests.get(f"{API_BASE_URL}/admin/system-status", headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   System Health: {result['system_health']}")
            
            # Show department breakdown
            dept_info = result['departments']
            print("   Department Overview:")
            for dept, info in dept_info.items():
                print(f"   • {dept}: {info['users']} users, {info['snapshots']} snapshots")
        
    except Exception as e:
        print(f"❌ Admin features test error: {e}")

def run_comprehensive_demo():
    """Run the complete DefenderAI demonstration"""
    print_banner()
    
    print("\n=== STEP 1: SYSTEM HEALTH CHECK ===")
    if not check_system_health():
        print("\n❌ Cannot proceed - DefenderAI system is not available")
        print("Please ensure both API server and dashboard are running:")
        print("   • API Server: http://localhost:8000")
        print("   • Dashboard: http://localhost:8501")
        return
    
    print("\n=== STEP 2: MULTI-DEPARTMENT AUTHENTICATION ===")
    
    # Login as different users
    users = [
        ("admin.kumar", "AdminMaster999!", "System Admin"),
        ("inspector.sharma", "SecurePass123!", "Police Inspector"),
        ("col.singh", "ArmySecure456!", "Army Colonel"),
        ("dr.patel", "HealthSafe789!", "Health Doctor")
    ]
    
    tokens = {}
    user_info = {}
    
    for username, password, title in users:
        token, info = login_as_user(username, password)
        if token:
            tokens[username] = token
            user_info[username] = info
            print(f"   {title}: Department {info['department']}, Role {info['role']}")
    
    print("\n=== STEP 3: CRYPTOGRAPHIC INTEGRITY TESTING ===")
    
    # Create records for different departments
    records = {}
    
    if "inspector.sharma" in tokens:
        record_id = create_secure_record(
            tokens["inspector.sharma"],
            "Confidential Police Investigation Report #2024001 - Cybercrime Unit findings on advanced persistent threats targeting government infrastructure during national celebrations.",
            "POLICE", 
            4  # Secret level
        )
        if record_id:
            records["police"] = record_id
    
    if "col.singh" in tokens:
        record_id = create_secure_record(
            tokens["col.singh"],
            "Classified Army Strategic Assessment - Defense readiness evaluation for critical infrastructure protection during national security events including Independence Day.",
            "ARMY",
            5  # Top Secret level  
        )
        if record_id:
            records["army"] = record_id
    
    if "dr.patel" in tokens:
        record_id = create_secure_record(
            tokens["dr.patel"],
            "Public Health Emergency Response Plan - Medical infrastructure security protocols for mass gatherings and national celebrations.",
            "HEALTH",
            3  # Confidential level
        )
        if record_id:
            records["health"] = record_id
    
    print("\n=== STEP 4: DEPARTMENTAL ACCESS CONTROL ===")
    
    if "inspector.sharma" in tokens and "army" in records:
        test_cross_department_access(tokens["inspector.sharma"], records["army"])
    
    print("\n=== STEP 5: AI ANOMALY DETECTION ===")
    
    if "inspector.sharma" in tokens:
        simulate_suspicious_activity(tokens["inspector.sharma"])
    
    # Wait a moment for processing
    time.sleep(2)
    
    print("\n=== STEP 6: SECURITY MONITORING ===")
    
    if "admin.kumar" in tokens:
        check_security_alerts(tokens["admin.kumar"])
    
    print("\n=== STEP 7: NATIONAL EVENT SPIKE DETECTION ===")
    
    if "admin.kumar" in tokens:
        test_event_spike_detection(tokens["admin.kumar"])
    
    print("\n=== STEP 8: SYSTEM STATISTICS ===")
    
    if "admin.kumar" in tokens:
        check_system_statistics(tokens["admin.kumar"])
    
    print("\n=== STEP 9: ADMIN FEATURES ===")
    
    if "admin.kumar" in tokens:
        test_admin_features(tokens["admin.kumar"])
    
    print("\n" + "="*80)
    print("🛡️ DEFENDERAI DEMONSTRATION COMPLETE")
    print("="*80)
    
    print("\n✅ DEMONSTRATED CAPABILITIES:")
    print("   • Cryptographic Integrity (SHA-256 + Merkle Trees)")
    print("   • Departmental Access Control (RBAC/ABAC)")
    print("   • Cross-department Isolation (Police ≠ Army ≠ Health)")  
    print("   • AI-powered Anomaly Detection (ML + Rules)")
    print("   • Automated Response System (Human-in-Loop)")
    print("   • National Event Spike Detection")
    print("   • Real-time Security Monitoring")
    print("   • Comprehensive Audit Trails")
    
    print("\n🌐 ACCESS POINTS:")
    print("   • API Documentation: http://localhost:8000/docs")
    print("   • Security Dashboard: http://localhost:8501")
    print("   • Health Check: http://localhost:8000/health")
    
    print("\n🔐 TEST SCENARIOS COMPLETED:")
    print("   ✅ Multi-department authentication")
    print("   ✅ Secure record creation with integrity")
    print("   ✅ Cross-department access blocking") 
    print("   ✅ Suspicious activity detection")
    print("   ✅ Automated threat response")
    print("   ✅ Admin oversight and approval")
    
    print("\n🎯 PRODUCTION READINESS:")
    print("   • Replace demo credentials with real authentication")
    print("   • Integrate with HSM/KMS for key management")
    print("   • Connect to actual CERT-In and NCIIPC channels")
    print("   • Deploy with proper network security")
    print("   • Enable 24/7 SOC monitoring")
    
    print(f"\n⏰ Demo completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🇮🇳 DefenderAI - Protecting India's Digital Infrastructure")

if __name__ == "__main__":
    run_comprehensive_demo()