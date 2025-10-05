"""
DefenderAI Dashboard
Streamlit-based security monitoring dashboard with role-based access
"""

import streamlit as st
import requests
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import sys
import os

# Configure page
st.set_page_config(
    page_title="DefenderAI Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API Configuration
API_BASE_URL = "http://localhost:8000"

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'access_token' not in st.session_state:
    st.session_state.access_token = None
if 'user_info' not in st.session_state:
    st.session_state.user_info = {}

def make_api_request(endpoint, method="GET", data=None, headers=None):
    """Make API request with authentication"""
    if headers is None:
        headers = {}
    
    if st.session_state.access_token:
        headers["Authorization"] = f"Bearer {st.session_state.access_token}"
    
    try:
        if method == "GET":
            response = requests.get(f"{API_BASE_URL}{endpoint}", headers=headers)
        elif method == "POST":
            response = requests.post(f"{API_BASE_URL}{endpoint}", json=data, headers=headers)
        
        if response.status_code == 401:
            st.session_state.authenticated = False
            st.session_state.access_token = None
            st.rerun()
        
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        st.error(f"API Error: {e}")
        return None

def login_page():
    """Login page"""
    st.title("🛡️ DefenderAI Security Platform")
    st.markdown("---")
    
    st.markdown("""
    ## Welcome to DefenderAI
    Advanced cybersecurity platform with:
    - **Cryptographic Integrity**: Tamper-evident records with Merkle trees
    - **Department Partitioning**: Strict RBAC with per-department access
    - **AI Anomaly Detection**: Real-time behavioral analysis
    - **Automated Response**: Smart containment with human oversight
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("🔐 Login")
        
        # Sample credentials
        st.info("""
        **Sample Credentials:**
        - **Admin**: admin.kumar / AdminMaster999!
        - **Police**: inspector.sharma / SecurePass123!
        - **Army**: col.singh / ArmySecure456!
        - **Health**: dr.patel / HealthSafe789!
        """)
        
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login", type="primary"):
            login_data = {
                "username": username,
                "password": password
            }
            
            try:
                response = requests.post(f"{API_BASE_URL}/auth/login", json=login_data)
                
                if response.status_code == 200:
                    result = response.json()
                    st.session_state.authenticated = True
                    st.session_state.access_token = result["access_token"]
                    st.session_state.user_info = result["user_info"]
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
            except Exception as e:
                st.error(f"Login error: {e}")
    
    with col2:
        st.subheader("📊 System Status")
        
        # Get system health
        try:
            health = requests.get(f"{API_BASE_URL}/health").json()
            st.success("✅ System Operational")
            
            for service, status in health["services"].items():
                st.text(f"• {service.replace('_', ' ').title()}: {status}")
        except:
            st.error("❌ System Unavailable")

def dashboard_main():
    """Main dashboard"""
    st.title("🛡️ DefenderAI Security Dashboard")
    
    # User info in sidebar
    st.sidebar.markdown(f"""
    **Current User:**
    - 👤 {st.session_state.user_info['username']}
    - 🏢 {st.session_state.user_info['department']}
    - 🎖️ {st.session_state.user_info['role'].title()}
    - 🔒 Clearance Level {st.session_state.user_info['clearance']}
    """)
    
    if st.sidebar.button("🚪 Logout"):
        st.session_state.authenticated = False
        st.session_state.access_token = None
        st.session_state.user_info = {}
        st.rerun()
    
    # Navigation
    page = st.sidebar.selectbox(
        "Navigation",
        ["Overview", "Security Alerts", "Records Management", "Monitoring", "Admin Panel", "System Status"]
    )
    
    if page == "Overview":
        show_overview()
    elif page == "Security Alerts":
        show_security_alerts()
    elif page == "Records Management":
        show_records_management()
    elif page == "Monitoring":
        show_monitoring()
    elif page == "Admin Panel":
        show_admin_panel()
    elif page == "System Status":
        show_system_status()

def show_overview():
    """Overview dashboard"""
    st.header("📊 Security Overview")
    
    # Get statistics
    stats = make_api_request("/monitoring/statistics")
    
    if stats:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Alerts (24h)",
                stats["anomaly_detection"].get("last_24h_alerts", 0),
                delta=None
            )
        
        with col2:
            st.metric(
                "Automated Responses",
                stats["automated_response"].get("total_responses", 0),
                delta=None
            )
        
        with col3:
            st.metric(
                "Access Logs (24h)",
                stats["access_logs"].get("last_24h", 0),
                delta=None
            )
        
        with col4:
            st.metric(
                "Integrity Snapshots",
                stats["cryptographic_integrity"].get("total_snapshots", 0),
                delta=None
            )
        
        st.markdown("---")
        
        # Alert severity breakdown
        if stats["anomaly_detection"].get("severity_breakdown"):
            col1, col2 = st.columns([1, 1])
            
            with col1:
                st.subheader("🚨 Alert Severity Breakdown")
                severity_data = stats["anomaly_detection"]["severity_breakdown"]
                
                fig = px.pie(
                    values=list(severity_data.values()),
                    names=list(severity_data.keys()),
                    color_discrete_map={
                        "LOW": "#28a745",
                        "MEDIUM": "#ffc107", 
                        "HIGH": "#fd7e14",
                        "CRITICAL": "#dc3545"
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.subheader("🏢 Department Activity")
                dept_data = stats["anomaly_detection"].get("department_breakdown", {})
                
                if dept_data:
                    fig = px.bar(
                        x=list(dept_data.keys()),
                        y=list(dept_data.values()),
                        color=list(dept_data.keys()),
                        color_discrete_map={
                            "POLICE": "#007bff",
                            "ARMY": "#28a745",
                            "HEALTH": "#17a2b8",
                            "ADMIN": "#6c757d"
                        }
                    )
                    fig.update_layout(showlegend=False)
                    st.plotly_chart(fig, use_container_width=True)
        
        # Event spike detection
        st.subheader("📈 Event Spike Detection")
        spike_data = make_api_request("/monitoring/event-spike")
        
        if spike_data:
            if spike_data["spike_detected"]:
                st.error(f"🚨 **Event Spike Detected!** Z-score: {spike_data['z_score']:.2f}")
                st.warning(f"Recommendation: {spike_data['recommendation']}")
            else:
                st.success("✅ Normal activity levels detected")
            
            # Show activity chart
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Current Activity", spike_data["current_activity"])
            with col2:
                st.metric("Baseline Mean", f"{spike_data['baseline_mean']:.1f}")
            with col3:
                st.metric("Z-Score", f"{spike_data['z_score']:.2f}")

def show_security_alerts():
    """Security alerts page"""
    st.header("🚨 Security Alerts")
    
    # Time filter
    hours = st.selectbox("Time Window", [1, 6, 24, 72, 168], index=2)
    
    alerts = make_api_request(f"/monitoring/alerts?hours={hours}")
    
    if alerts and alerts["total_alerts"] > 0:
        st.subheader(f"📊 {alerts['total_alerts']} Alerts in Last {hours} Hours")
        
        # Create alerts DataFrame
        alerts_df = pd.DataFrame(alerts["alerts"])
        
        # Severity filter
        severity_filter = st.multiselect(
            "Filter by Severity",
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            default=["MEDIUM", "HIGH", "CRITICAL"]
        )
        
        filtered_df = alerts_df[alerts_df["severity"].isin(severity_filter)]
        
        # Display alerts
        for idx, alert in filtered_df.iterrows():
            severity_color = {
                "LOW": "🟢",
                "MEDIUM": "🟡", 
                "HIGH": "🟠",
                "CRITICAL": "🔴"
            }
            
            with st.expander(f"{severity_color[alert['severity']]} {alert['severity']} - User: {alert['user_id']} - Score: {alert['anomaly_score']:.3f}"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.write(f"**Department:** {alert['department']}")
                    st.write(f"**Timestamp:** {alert['timestamp']}")
                    st.write(f"**Rule Violations:** {alert['rule_violations']}")
                    st.write("**Recommended Actions:**")
                    for action in alert['recommended_actions']:
                        st.write(f"• {action}")
                
                with col2:
                    # Mock containment actions
                    if st.button(f"🔒 Contain User", key=f"contain_{alert['anomaly_id']}"):
                        st.success("User session revoked and re-authentication required")
                    
                    if st.button(f"📧 Notify SOC", key=f"notify_{alert['anomaly_id']}"):
                        st.info("SOC team notified via secure channel")
    else:
        st.success("✅ No security alerts in the selected time window")

def show_records_management():
    """Records management page"""
    st.header("📁 Records Management")
    
    user_dept = st.session_state.user_info["department"]
    
    # Create new record
    st.subheader("➕ Create New Record")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        record_content = st.text_area("Record Content", height=100)
        record_metadata = st.text_input("Metadata (JSON format)", value='{"type": "report", "category": "operational"}')
    
    with col2:
        record_dept = st.selectbox("Department", [user_dept] if user_dept != "ADMIN" else ["POLICE", "ARMY", "HEALTH"])
        record_classification = st.selectbox("Classification Level", [1, 2, 3, 4, 5], index=2)
        
        classification_labels = {
            1: "Public",
            2: "Restricted",
            3: "Confidential", 
            4: "Secret",
            5: "Top Secret"
        }
        st.caption(f"Selected: {classification_labels[record_classification]}")
    
    if st.button("🔐 Create Secure Record", type="primary"):
        if record_content:
            try:
                metadata = json.loads(record_metadata)
                
                record_data = {
                    "content": record_content,
                    "metadata": metadata,
                    "classification": record_classification,
                    "department": record_dept
                }
                
                result = make_api_request("/records/create", "POST", record_data)
                
                if result:
                    st.success("✅ Record created successfully with cryptographic integrity!")
                    
                    with st.expander("📋 Record Details"):
                        st.code(f"""
Record ID: {result['record_id']}
Content Hash: {result['content_hash']}
Snapshot ID: {result['snapshot_id']}
Merkle Root: {result['merkle_root']}
Signature: {result['signature']}
Created: {result['created_at']}
                        """)
            except json.JSONDecodeError:
                st.error("Invalid JSON in metadata field")
        else:
            st.error("Please enter record content")
    
    st.markdown("---")
    
    # View department records
    st.subheader(f"📂 {user_dept} Department Records")
    
    dept_records = make_api_request(f"/records/department/{user_dept}")
    
    if dept_records and dept_records["total_records"] > 0:
        st.write(f"Total Records: {dept_records['total_records']}")
        
        records_df = pd.DataFrame(dept_records["records"])
        records_df["created_at"] = pd.to_datetime(records_df["created_at"])
        
        # Display records table
        st.dataframe(
            records_df,
            column_config={
                "record_id": st.column_config.TextColumn("Record ID", width="small"),
                "content_hash": st.column_config.TextColumn("Content Hash", width="medium"),
                "classification": st.column_config.NumberColumn("Classification", width="small"),
                "created_at": st.column_config.DatetimeColumn("Created", width="medium"),
                "size": st.column_config.NumberColumn("Size (bytes)", width="small")
            },
            use_container_width=True
        )
        
        # Record integrity check
        st.subheader("🔍 Integrity Verification")
        selected_record = st.selectbox(
            "Select Record to Verify",
            options=records_df["record_id"].tolist(),
            format_func=lambda x: f"{x[:8]}... ({records_df[records_df['record_id']==x]['created_at'].iloc[0].strftime('%Y-%m-%d %H:%M')})"
        )
        
        if st.button("🔍 Verify Integrity"):
            record_details = make_api_request(f"/records/{selected_record}")
            
            if record_details:
                status = record_details["integrity_status"]
                
                if status == "verified":
                    st.success("✅ Record integrity verified - No tampering detected")
                else:
                    st.error("❌ Record integrity compromised - Tampering detected!")
                
                with st.expander("🔍 Detailed Integrity Report"):
                    st.json(record_details["tamper_evidence"])
    else:
        st.info("No records found for this department")

def show_monitoring():
    """Monitoring page"""
    st.header("📊 Security Monitoring")
    
    # Log access pattern
    st.subheader("📝 Log Access Pattern")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        files_accessed = st.number_input("Files Accessed", min_value=1, max_value=1000, value=5)
        session_duration = st.number_input("Session Duration (seconds)", value=3600)
    
    with col2:
        data_volume = st.number_input("Data Volume (MB)", min_value=1, max_value=10000, value=10)
        unique_resources = st.number_input("Unique Resources", min_value=1, max_value=100, value=3)
    
    with col3:
        source_ip = st.text_input("Source IP", value="192.168.1.100")
        action = st.selectbox("Action", ["read", "write", "download", "modify"])
    
    if st.button("📊 Analyze Access Pattern"):
        access_data = {
            "user_id": st.session_state.user_info["user_id"],
            "dept": st.session_state.user_info["department"],
            "resource_id": "resource_" + str(int(time.time())),
            "action": action,
            "files_accessed": files_accessed,
            "session_duration": session_duration,
            "data_volume_mb": data_volume,
            "unique_resources": unique_resources,
            "source_ip": source_ip
        }
        
        result = make_api_request("/monitoring/log-access", "POST", access_data)
        
        if result:
            if result["anomaly_detected"]:
                st.error(f"🚨 **Anomaly Detected!** Severity: {result['severity']}")
                st.warning(f"Anomaly Score: {result['anomaly_score']:.3f}")
                
                st.subheader("🤖 Recommended Actions")
                for action in result["recommended_actions"]:
                    st.write(f"• {action}")
            else:
                st.success("✅ Normal access pattern - No anomalies detected")
    
    st.markdown("---")
    
    # Real-time monitoring simulation
    st.subheader("📡 Real-time Activity Monitor")
    
    if st.button("🔄 Refresh Activity"):
        # Simulate real-time data
        activity_data = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "active_sessions": 15,
            "requests_per_minute": 120,
            "anomaly_score": 0.23,
            "threat_level": "LOW"
        }
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Active Sessions", activity_data["active_sessions"], delta=2)
        
        with col2:
            st.metric("Requests/Min", activity_data["requests_per_minute"], delta=-5)
        
        with col3:
            st.metric("Avg Anomaly Score", f"{activity_data['anomaly_score']:.3f}", delta=0.01)
        
        with col4:
            st.metric("Threat Level", activity_data["threat_level"])

def show_admin_panel():
    """Admin panel (admin only)"""
    if st.session_state.user_info["role"] not in ["admin", "supervisor"]:
        st.error("🔒 Admin access required")
        return
    
    st.header("⚙️ Admin Panel")
    
    # Pending approvals
    st.subheader("✋ Pending Approvals")
    
    approvals = make_api_request("/admin/pending-approvals")
    
    if approvals and approvals["total_pending"] > 0:
        for approval in approvals["approvals"]:
            with st.expander(f"🔴 {approval['action_type']} - Risk: {approval['risk_level']}"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.write(f"**Action Type:** {approval['action_type']}")
                    st.write(f"**Risk Level:** {approval['risk_level']}")
                    st.write(f"**Approver:** {approval['approver']}")
                    st.write(f"**Response Required By:** {approval['response_required_by']}")
                    st.write(f"**User:** {approval['anomaly_details']['user_id']}")
                    st.write(f"**Department:** {approval['anomaly_details']['department']}")
                
                with col2:
                    notes = st.text_area("Approver Notes", key=f"notes_{approval['approval_id']}")
                    
                    col_approve, col_reject = st.columns(2)
                    
                    with col_approve:
                        if st.button("✅ Approve", key=f"approve_{approval['approval_id']}"):
                            approval_data = {
                                "approval_id": approval['approval_id'],
                                "approved": True,
                                "approver_notes": notes
                            }
                            result = make_api_request("/admin/approve-action", "POST", approval_data)
                            if result:
                                st.success("Action approved and executed")
                                st.rerun()
                    
                    with col_reject:
                        if st.button("❌ Reject", key=f"reject_{approval['approval_id']}"):
                            approval_data = {
                                "approval_id": approval['approval_id'],
                                "approved": False,
                                "approver_notes": notes
                            }
                            result = make_api_request("/admin/approve-action", "POST", approval_data)
                            if result:
                                st.info("Action rejected")
                                st.rerun()
    else:
        st.success("✅ No pending approvals")
    
    st.markdown("---")
    
    # Audit trail
    st.subheader("📋 Audit Trail")
    
    audit_hours = st.selectbox("Audit Time Window", [6, 24, 72, 168], index=1)
    
    if st.button("📊 Generate Audit Report"):
        audit_data = make_api_request(f"/admin/audit-trail?hours={audit_hours}")
        
        if audit_data:
            st.subheader("📊 Audit Summary")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Access Events", audit_data["audit_summary"]["total_access_events"])
            
            with col2:
                st.metric("Security Alerts", audit_data["audit_summary"]["total_security_alerts"])
            
            with col3:
                st.metric("Automated Responses", audit_data["audit_summary"]["total_automated_responses"])
            
            with col4:
                st.metric("High Severity Alerts", audit_data["audit_summary"]["high_severity_alerts"])
            
            # Show recent activities
            st.subheader("🕒 Recent Access Logs")
            if audit_data["access_logs"]:
                access_df = pd.DataFrame(audit_data["access_logs"])
                st.dataframe(access_df, use_container_width=True)
            
            st.subheader("🚨 Recent Security Alerts")
            if audit_data["recent_alerts"]:
                for alert in audit_data["recent_alerts"]:
                    st.write(f"• **{alert['severity'].name}** - User: {alert['user_id']} - Score: {alert['anomaly_score']:.3f}")

def show_system_status():
    """System status page"""
    st.header("🖥️ System Status")
    
    status = make_api_request("/admin/system-status")
    
    if status:
        st.success(f"✅ System Health: {status['system_health'].title()}")
        st.caption(f"Last Updated: {status['timestamp']}")
        
        st.markdown("---")
        
        # Service status
        st.subheader("🔧 Service Status")
        
        for service_name, service_info in status["services"].items():
            with st.expander(f"📊 {service_name.replace('_', ' ').title()}", expanded=True):
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    if service_info["status"] == "operational":
                        st.success("✅ Operational")
                    else:
                        st.error("❌ Down")
                
                with col2:
                    for key, value in service_info.items():
                        if key != "status":
                            st.write(f"**{key.replace('_', ' ').title()}:** {value}")
        
        st.markdown("---")
        
        # Department overview
        st.subheader("🏢 Department Overview")
        
        dept_data = []
        for dept, info in status["departments"].items():
            dept_data.append({
                "Department": dept,
                "Users": info["users"],
                "Snapshots": info["snapshots"]
            })
        
        dept_df = pd.DataFrame(dept_data)
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig_users = px.bar(dept_df, x="Department", y="Users", title="Users by Department")
            st.plotly_chart(fig_users, use_container_width=True)
        
        with col2:
            fig_snapshots = px.bar(dept_df, x="Department", y="Snapshots", title="Snapshots by Department")
            st.plotly_chart(fig_snapshots, use_container_width=True)
    else:
        st.error("❌ Unable to retrieve system status")

def main():
    """Main application"""
    if not st.session_state.authenticated:
        login_page()
    else:
        dashboard_main()

if __name__ == "__main__":
    main()