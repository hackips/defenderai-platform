"""
DefenderAI FastAPI Main Application
RESTful API for the DefenderAI platform with departmental access control
"""

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import json
from datetime import datetime, timezone
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto_service import CryptoService
from core.auth_service import AuthService, Department, Role, ClearanceLevel
from core.anomaly_detector import AnomalyDetector
from core.response_engine import ResponseEngine

# Initialize FastAPI app
app = FastAPI(
    title="DefenderAI Security Platform",
    description="Advanced cybersecurity platform with cryptographic integrity, RBAC, and AI-powered threat detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
crypto_service = CryptoService()
auth_service = AuthService()
anomaly_detector = AnomalyDetector()
response_engine = ResponseEngine(auth_service)

# Security dependency
security = HTTPBearer()

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict

class AccessLogEntry(BaseModel):
    user_id: str
    dept: str
    resource_id: str
    action: str
    files_accessed: int = 1
    session_duration: int = 3600
    data_volume_mb: int = 10
    unique_resources: int = 1
    source_ip: str = "127.0.0.1"

class RecordCreate(BaseModel):
    content: str
    metadata: Dict
    classification: int
    department: str

class ApprovalRequest(BaseModel):
    approval_id: str
    approved: bool
    approver_notes: str = ""

# Dependency to get current user from token
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    payload = auth_service.verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "DefenderAI Security Platform API",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.now(timezone.utc),
        "endpoints": {
            "authentication": "/auth/*",
            "records": "/records/*",
            "monitoring": "/monitoring/*",
            "admin": "/admin/*",
            "docs": "/docs"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc),
        "services": {
            "crypto_service": "operational",
            "auth_service": "operational", 
            "anomaly_detector": "operational",
            "response_engine": "operational"
        }
    }

# Authentication endpoints
@app.post("/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Authenticate user and return JWT token"""
    user = auth_service.authenticate_user(request.username, request.password, request.mfa_code)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if user.get("requires_mfa"):
        raise HTTPException(status_code=202, detail="MFA required", headers={"X-Requires-MFA": "true"})
    
    # Generate token
    token = auth_service.generate_token(user, expires_minutes=60)
    
    return LoginResponse(
        access_token=token,
        expires_in=3600,
        user_info={
            "user_id": user["id"],
            "username": user["username"],
            "department": user["dept"],
            "role": user["role"],
            "clearance": user["clearance"]
        }
    )

@app.post("/auth/logout")
async def logout(current_user: Dict = Depends(get_current_user)):
    """Logout user and revoke token"""
    # In a real implementation, you'd need the actual token to revoke
    return {"message": "Logged out successfully"}

@app.get("/auth/me")
async def get_current_user_info(current_user: Dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "user_id": current_user["sub"],
        "username": current_user["username"],
        "department": current_user["dept"],
        "role": current_user["role"],
        "clearance": current_user["clearance"],
        "scopes": current_user["scopes"],
        "token_expires": current_user["exp"]
    }

# Records management endpoints
@app.post("/records/create")
async def create_record(record: RecordCreate, current_user: Dict = Depends(get_current_user)):
    """Create a new secure record with cryptographic integrity"""
    
    # Check permissions
    if not auth_service.check_access_permission(current_user, record.department, record.classification, "write"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to create record in this department")
    
    # Create cryptographic record
    crypto_record = crypto_service.compute_file_hash(record.content, record.metadata)
    crypto_record.update({
        "department": record.department,
        "classification": record.classification,
        "created_by": current_user["username"],
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    
    # Create signed snapshot
    snapshot = crypto_service.create_snapshot([crypto_record], record.department)
    
    return {
        "record_id": crypto_record["id"],
        "content_hash": crypto_record["content_hash"],
        "snapshot_id": snapshot["snapshot"]["snapshot_id"],
        "merkle_root": snapshot["snapshot"]["merkle_root"],
        "signature": snapshot["signature"][:32] + "...",  # Truncate for display
        "created_at": crypto_record["created_at"]
    }

@app.get("/records/{record_id}")
async def get_record(record_id: str, current_user: Dict = Depends(get_current_user)):
    """Get record with integrity verification"""
    
    # In a real implementation, you'd fetch from database
    # For demo, we'll search through snapshots
    for snapshot in crypto_service.snapshots:
        for record in snapshot["snapshot"]["records"]:
            if record["id"] == record_id:
                # Check permissions
                record_dept = record.get("department", "UNKNOWN")
                record_classification = record.get("classification", 5)
                
                if not auth_service.check_access_permission(current_user, record_dept, record_classification, "read"):
                    raise HTTPException(status_code=403, detail="Insufficient permissions to access this record")
                
                # Get tamper evidence
                evidence = crypto_service.get_tamper_evidence(record_id)
                
                return {
                    "record": record,
                    "integrity_status": evidence["status"],
                    "tamper_evidence": evidence,
                    "snapshot_info": {
                        "snapshot_id": snapshot["snapshot"]["snapshot_id"],
                        "merkle_root": snapshot["snapshot"]["merkle_root"],
                        "signature_valid": evidence["details"].get("signature_valid", False)
                    }
                }
    
    raise HTTPException(status_code=404, detail="Record not found")

@app.get("/records/department/{dept}")
async def get_department_records(dept: str, current_user: Dict = Depends(get_current_user)):
    """Get all records for a department"""
    
    # Check if user can access department records
    if current_user["dept"] != dept and current_user["dept"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Access denied to cross-department records")
    
    records = []
    for snapshot in crypto_service.snapshots:
        if snapshot["snapshot"]["department"] == dept:
            for record in snapshot["snapshot"]["records"]:
                record_classification = record.get("classification", 1)
                
                # Check clearance level
                if current_user["clearance"] >= record_classification:
                    records.append({
                        "record_id": record["id"],
                        "content_hash": record["content_hash"],
                        "classification": record_classification,
                        "created_at": record["timestamp"],
                        "size": record["size"]
                    })
    
    return {
        "department": dept,
        "total_records": len(records),
        "records": records
    }

# Monitoring endpoints
@app.post("/monitoring/log-access")
async def log_access(entry: AccessLogEntry, current_user: Dict = Depends(get_current_user)):
    """Log access pattern for anomaly detection"""
    
    # Enrich access log with current user info
    access_data = {
        "user_id": entry.user_id,
        "dept": entry.dept,
        "resource_id": entry.resource_id,
        "action": entry.action,
        "files_accessed": entry.files_accessed,
        "session_duration": entry.session_duration,
        "data_volume_mb": entry.data_volume_mb,
        "unique_resources": entry.unique_resources,
        "source_ip": entry.source_ip,
        "hour_of_day": datetime.now().hour,
        "day_of_week": datetime.now().weekday(),
        "login_attempts": 1,
        "failed_authentications": 0,
        "source_ip_changes": 0,
        "clearance_level": current_user["clearance"],
        "timestamp": datetime.now(timezone.utc)
    }
    
    # Analyze for anomalies
    anomaly_result = anomaly_detector.analyze_access_pattern(access_data)
    
    # Trigger automated response if needed
    if anomaly_result["severity"].value >= 2:  # Medium or higher
        response = response_engine.trigger_response(anomaly_result)
        anomaly_result["automated_response"] = {
            "response_id": response["response_id"],
            "actions_taken": len(response["actions"]),
            "status": response["status"]
        }
    
    return {
        "access_logged": True,
        "anomaly_detected": anomaly_result["severity"].value >= 2,
        "anomaly_score": anomaly_result["anomaly_score"],
        "severity": anomaly_result["severity"].name,
        "recommended_actions": anomaly_result["recommended_actions"]
    }

@app.get("/monitoring/alerts")
async def get_alerts(hours: int = 24, current_user: Dict = Depends(get_current_user)):
    """Get recent security alerts for user's department"""
    
    # Filter alerts by department unless admin
    dept_filter = None if current_user["dept"] == "ADMIN" else current_user["dept"]
    
    alerts = anomaly_detector.get_recent_alerts(hours=hours, dept=dept_filter)
    
    return {
        "total_alerts": len(alerts),
        "time_window_hours": hours,
        "department_filter": dept_filter,
        "alerts": [
            {
                "anomaly_id": alert["anomaly_id"],
                "timestamp": alert["timestamp"],
                "user_id": alert["user_id"],
                "department": alert["dept"],
                "severity": alert["severity"].name,
                "anomaly_score": alert["anomaly_score"],
                "rule_violations": len(alert["rule_violations"]),
                "recommended_actions": alert["recommended_actions"][:3]  # First 3 actions
            }
            for alert in alerts
        ]
    }

@app.get("/monitoring/statistics")
async def get_monitoring_statistics(current_user: Dict = Depends(get_current_user)):
    """Get monitoring and detection statistics"""
    
    anomaly_stats = anomaly_detector.get_anomaly_statistics()
    response_stats = response_engine.get_response_statistics()
    
    return {
        "anomaly_detection": anomaly_stats,
        "automated_response": response_stats,
        "access_logs": {
            "total_logs": len(auth_service.get_access_logs()),
            "last_24h": len(auth_service.get_access_logs(hours=24))
        },
        "cryptographic_integrity": {
            "total_snapshots": len(crypto_service.snapshots),
            "daily_merkle_root": crypto_service.create_daily_merkle_root()[:16] + "..." if crypto_service.snapshots else "N/A"
        }
    }

@app.get("/monitoring/event-spike")
async def check_event_spike(current_user: Dict = Depends(get_current_user)):
    """Check for activity spikes during national events"""
    
    # Get recent access logs
    recent_logs = auth_service.get_access_logs(hours=24)
    
    # Convert to events format for spike detection
    events = [{"timestamp": log["timestamp"]} for log in recent_logs]
    
    spike_result = anomaly_detector.detect_event_spike(events)
    
    if spike_result["spike_detected"]:
        # Trigger event spike response
        spike_anomaly = {
            "anomaly_id": "event_spike_" + str(int(datetime.now().timestamp())),
            "event_spike_detected": True,
            "z_score": spike_result["z_score"],
            "severity": "MEDIUM"
        }
        response = response_engine.trigger_response(spike_anomaly)
        spike_result["automated_response"] = response["response_id"]
    
    return spike_result

# Admin endpoints
@app.get("/admin/pending-approvals")
async def get_pending_approvals(current_user: Dict = Depends(get_current_user)):
    """Get pending approval requests (admin only)"""
    
    if current_user["role"] not in ["admin", "supervisor"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    pending = response_engine.get_pending_approvals()
    
    return {
        "total_pending": len(pending),
        "approvals": [
            {
                "approval_id": req["approval_id"],
                "action_type": req["action_type"],
                "risk_level": req["risk_level"],
                "approver": req["approver"]["name"],
                "response_required_by": req["response_required_by"],
                "anomaly_details": {
                    "user_id": req["anomaly_data"].get("user_id"),
                    "department": req["anomaly_data"].get("dept"),
                    "severity": str(req["anomaly_data"].get("severity"))
                }
            }
            for req in pending
        ]
    }

@app.post("/admin/approve-action")
async def approve_action(request: ApprovalRequest, current_user: Dict = Depends(get_current_user)):
    """Approve or reject a pending action (admin only)"""
    
    if current_user["role"] not in ["admin", "supervisor"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = response_engine.approve_action(
        request.approval_id,
        request.approved,
        request.approver_notes
    )
    
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    
    return result

@app.get("/admin/audit-trail")
async def get_audit_trail(hours: int = 24, current_user: Dict = Depends(get_current_user)):
    """Get comprehensive audit trail (admin only)"""
    
    if current_user["role"] not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    access_logs = auth_service.get_access_logs(hours=hours)
    response_history = response_engine.get_response_history(hours=hours)
    recent_alerts = anomaly_detector.get_recent_alerts(hours=hours)
    
    return {
        "time_window_hours": hours,
        "audit_summary": {
            "total_access_events": len(access_logs),
            "total_security_alerts": len(recent_alerts),
            "total_automated_responses": len(response_history),
            "high_severity_alerts": len([a for a in recent_alerts if a["severity"].value >= 3])
        },
        "access_logs": access_logs[-10:],  # Last 10 entries
        "recent_alerts": recent_alerts[:10],  # Top 10 alerts
        "response_history": response_history[:5]  # Last 5 responses
    }

@app.get("/admin/system-status")
async def get_system_status(current_user: Dict = Depends(get_current_user)):
    """Get comprehensive system status (admin only)"""
    
    if current_user["role"] not in ["admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {
        "timestamp": datetime.now(timezone.utc),
        "system_health": "operational",
        "services": {
            "crypto_service": {
                "status": "operational",
                "snapshots_created": len(crypto_service.snapshots),
                "daily_merkle_root": crypto_service.create_daily_merkle_root()[:16] + "..." if crypto_service.snapshots else "N/A"
            },
            "auth_service": {
                "status": "operational",
                "active_sessions": len(auth_service.get_active_sessions()),
                "total_users": len(auth_service.users_db),
                "access_logs_24h": len(auth_service.get_access_logs(hours=24))
            },
            "anomaly_detector": {
                "status": "operational",
                "models_trained": len(anomaly_detector.models),
                "total_alerts": len(anomaly_detector.alerts),
                "baseline_data_points": len(anomaly_detector.baseline_data)
            },
            "response_engine": {
                "status": "operational",
                "playbooks_active": len(response_engine.playbooks),
                "responses_executed": len(response_engine.executed_actions),
                "pending_approvals": len(response_engine.get_pending_approvals())
            }
        },
        "departments": {
            dept.value: {
                "users": len([u for u in auth_service.users_db.values() if u["dept"] == dept.value]),
                "snapshots": len([s for s in crypto_service.snapshots if s["snapshot"]["department"] == dept.value])
            }
            for dept in Department
        }
    }

if __name__ == "__main__":
    import uvicorn
    print("Starting DefenderAI Security Platform...")
    print("API Documentation available at: http://localhost:8000/docs")
    print("System Admin Login: admin.kumar / AdminMaster999!")
    print("Police Inspector Login: inspector.sharma / SecurePass123!")
    print("Army Colonel Login: col.singh / ArmySecure456!")
    print("Health Doctor Login: dr.patel / HealthSafe789!")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)