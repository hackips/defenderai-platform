"""
Authentication & Authorization Service
Handles departmental keys, RBAC/ABAC, JWT tokens, and access partitioning
"""

import jwt
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import hashlib
import uuid
from enum import Enum

class Department(Enum):
    POLICE = "POLICE"
    ARMY = "ARMY"
    HEALTH = "HEALTH"
    ADMIN = "ADMIN"

class Role(Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    SUPERVISOR = "supervisor"
    ADMIN = "admin"

class ClearanceLevel(Enum):
    PUBLIC = 1
    RESTRICTED = 2
    CONFIDENTIAL = 3
    SECRET = 4
    TOP_SECRET = 5

class AuthService:
    """Authentication and Authorization Service"""
    
    def __init__(self):
        self.jwt_secret = self._generate_jwt_secret()
        # Use simple SHA-256 for demo purposes
        self.users_db = {}
        self.dept_keys = {}
        self.active_tokens = set()
        self.revoked_tokens = set()
        self.access_logs = []
        
        # Initialize department keys
        self._generate_department_keys()
        
        # Create sample users
        self._create_sample_users()
    
    def _generate_jwt_secret(self) -> str:
        """Generate JWT signing secret"""
        return str(uuid.uuid4()).replace('-', '')
    
    def _generate_department_keys(self):
        """Generate unique keys for each department"""
        for dept in Department:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            self.dept_keys[dept.value] = {
                "private_key": private_key,
                "public_key": private_key.public_key(),
                "created_at": datetime.now(timezone.utc),
                "rotation_due": datetime.now(timezone.utc) + timedelta(days=90)
            }
    
    def _create_sample_users(self):
        """Create sample users for demonstration"""
        sample_users = [
            {
                "username": "inspector.sharma",
                "password": "SecurePass123!",
                "dept": Department.POLICE.value,
                "role": Role.SUPERVISOR.value,
                "clearance": ClearanceLevel.SECRET.value,
                "full_name": "Inspector Raj Sharma",
                "badge_number": "POL001"
            },
            {
                "username": "col.singh",
                "password": "ArmySecure456!",
                "dept": Department.ARMY.value,
                "role": Role.OPERATOR.value,
                "clearance": ClearanceLevel.TOP_SECRET.value,
                "full_name": "Colonel Arjun Singh",
                "service_number": "ARM002"
            },
            {
                "username": "dr.patel",
                "password": "HealthSafe789!",
                "dept": Department.HEALTH.value,
                "role": Role.ANALYST.value,
                "clearance": ClearanceLevel.CONFIDENTIAL.value,
                "full_name": "Dr. Priya Patel",
                "license_number": "MED003"
            },
            {
                "username": "admin.kumar",
                "password": "AdminMaster999!",
                "dept": Department.ADMIN.value,
                "role": Role.ADMIN.value,
                "clearance": ClearanceLevel.TOP_SECRET.value,
                "full_name": "System Admin Kumar",
                "employee_id": "ADM001"
            }
        ]
        
        for user in sample_users:
            user_id = str(uuid.uuid4())
            user_record = {
                "id": user_id,
                "username": user["username"],
                "password_hash": hashlib.sha256(user["password"].encode()).hexdigest(),
                "dept": user["dept"],
                "role": user["role"],
                "clearance": user["clearance"],
                "full_name": user["full_name"],
                "created_at": datetime.now(timezone.utc),
                "last_login": None,
                "active": True,
                "mfa_enabled": True,
                "failed_login_attempts": 0,
                "locked_until": None
            }
            # Add any additional fields from the user data
            for key, value in user.items():
                if key not in user_record and key != "password":
                    user_record[key] = value
            
            self.users_db[user_id] = user_record
    
    def authenticate_user(self, username: str, password: str, mfa_code: str = None) -> Optional[Dict]:
        """Authenticate user with username/password and optional MFA"""
        user = self._find_user_by_username(username)
        if not user:
            self._log_access_attempt(username, "FAILED", "User not found")
            return None
        
        # Check if account is locked
        if user.get("locked_until") and datetime.now(timezone.utc) < user["locked_until"]:
            self._log_access_attempt(username, "FAILED", "Account locked")
            return None
        
        # Verify password
        if hashlib.sha256(password.encode()).hexdigest() != user["password_hash"]:
            user["failed_login_attempts"] += 1
            if user["failed_login_attempts"] >= 3:
                user["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=30)
            self._log_access_attempt(username, "FAILED", "Invalid password")
            return None
        
        # Reset failed attempts on successful login
        user["failed_login_attempts"] = 0
        user["locked_until"] = None
        user["last_login"] = datetime.now(timezone.utc)
        
        # For demo purposes, skip actual MFA verification
        if user.get("mfa_enabled") and not mfa_code:
            return {"requires_mfa": True, "user_id": user["id"]}
        
        self._log_access_attempt(username, "SUCCESS", "Authentication successful")
        return user
    
    def generate_token(self, user: Dict, expires_minutes: int = 30) -> str:
        """Generate JWT token for authenticated user"""
        now = datetime.now(timezone.utc)
        
        # Define scopes based on role and department
        scopes = self._generate_scopes(user["dept"], user["role"])
        
        payload = {
            "sub": f"user:{user['id']}",
            "username": user["username"],
            "dept": user["dept"],
            "role": user["role"],
            "clearance": user["clearance"],
            "scopes": scopes,
            "iat": now,
            "exp": now + timedelta(minutes=expires_minutes),
            "jti": str(uuid.uuid4())  # JWT ID for revocation
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        self.active_tokens.add(payload["jti"])
        
        self._log_access_attempt(user["username"], "TOKEN_ISSUED", f"Token valid for {expires_minutes} minutes")
        return token
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            
            # Check if token is revoked
            if payload["jti"] in self.revoked_tokens:
                return None
            
            # Check if token is still active
            if payload["jti"] not in self.active_tokens:
                return None
            
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a specific token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"], options={"verify_exp": False})
            jti = payload["jti"]
            
            self.active_tokens.discard(jti)
            self.revoked_tokens.add(jti)
            
            self._log_access_attempt(payload.get("username", "unknown"), "TOKEN_REVOKED", "Token manually revoked")
            return True
        except:
            return False
    
    def check_access_permission(self, token_payload: Dict, resource_dept: str, resource_classification: int, action: str) -> bool:
        """Check if user has permission to access resource"""
        user_dept = token_payload.get("dept")
        user_clearance = token_payload.get("clearance")
        user_scopes = token_payload.get("scopes", [])
        
        # Check department access (strict partitioning)
        if user_dept != resource_dept and user_dept != "ADMIN":
            self._log_access_attempt(
                token_payload.get("username", "unknown"), 
                "ACCESS_DENIED", 
                f"Cross-department access attempted: {user_dept} -> {resource_dept}"
            )
            return False
        
        # Check clearance level
        if user_clearance < resource_classification:
            self._log_access_attempt(
                token_payload.get("username", "unknown"), 
                "ACCESS_DENIED", 
                f"Insufficient clearance: {user_clearance} < {resource_classification}"
            )
            return False
        
        # Check action permissions
        required_scope = f"{action}:{resource_dept.lower()}_records"
        if required_scope not in user_scopes:
            self._log_access_attempt(
                token_payload.get("username", "unknown"), 
                "ACCESS_DENIED", 
                f"Missing scope: {required_scope}"
            )
            return False
        
        self._log_access_attempt(
            token_payload.get("username", "unknown"), 
            "ACCESS_GRANTED", 
            f"Access to {resource_dept} {action} operation"
        )
        return True
    
    def _generate_scopes(self, dept: str, role: str) -> List[str]:
        """Generate scopes based on department and role"""
        base_scopes = [f"read:{dept.lower()}_records"]
        
        if role in [Role.ANALYST.value, Role.OPERATOR.value, Role.SUPERVISOR.value, Role.ADMIN.value]:
            base_scopes.append(f"write:{dept.lower()}_records")
            base_scopes.append(f"monitor:{dept.lower()}_alerts")
        
        if role in [Role.SUPERVISOR.value, Role.ADMIN.value]:
            base_scopes.append(f"admin:{dept.lower()}_system")
            base_scopes.append(f"audit:{dept.lower()}_logs")
        
        if role == Role.ADMIN.value:
            base_scopes.extend([
                "read:all_records",
                "write:all_records",
                "admin:all_systems",
                "audit:all_logs"
            ])
        
        return base_scopes
    
    def _find_user_by_username(self, username: str) -> Optional[Dict]:
        """Find user by username"""
        for user in self.users_db.values():
            if user["username"] == username:
                return user
        return None
    
    def _log_access_attempt(self, username: str, status: str, details: str):
        """Log access attempts for audit"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc),
            "username": username,
            "status": status,
            "details": details,
            "source_ip": "127.0.0.1",  # In real implementation, get from request
            "user_agent": "DefenderAI-Demo"
        }
        self.access_logs.append(log_entry)
    
    def get_access_logs(self, dept: str = None, hours: int = 24) -> List[Dict]:
        """Get access logs for monitoring"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        filtered_logs = [log for log in self.access_logs if log["timestamp"] > cutoff_time]
        
        if dept:
            # Filter logs for specific department
            dept_users = [user["username"] for user in self.users_db.values() if user["dept"] == dept]
            filtered_logs = [log for log in filtered_logs if log["username"] in dept_users]
        
        return filtered_logs
    
    def get_active_sessions(self) -> List[Dict]:
        """Get currently active sessions"""
        active_sessions = []
        
        for jti in self.active_tokens:
            # In a real implementation, you'd store session metadata separately
            # For demo, we'll create sample data
            active_sessions.append({
                "session_id": jti,
                "status": "active",
                "created_at": datetime.now(timezone.utc) - timedelta(minutes=15),
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15),
                "last_activity": datetime.now(timezone.utc) - timedelta(minutes=2)
            })
        
        return active_sessions

# Test function
def test_auth_service():
    """Test the authentication service"""
    auth = AuthService()
    
    print("=== DefenderAI Auth Service Test ===")
    
    # Test authentication
    user = auth.authenticate_user("inspector.sharma", "SecurePass123!")
    if user:
        print(f"✓ Authentication successful for {user['username']}")
        
        # Generate token
        token = auth.generate_token(user)
        print(f"✓ JWT token generated (length: {len(token)})")
        
        # Verify token
        payload = auth.verify_token(token)
        if payload:
            print(f"✓ Token verified for dept: {payload['dept']}, role: {payload['role']}")
            
            # Test access permissions
            can_access_police = auth.check_access_permission(payload, "POLICE", 4, "read")
            can_access_army = auth.check_access_permission(payload, "ARMY", 4, "read")
            
            print(f"✓ Police access permission: {can_access_police}")
            print(f"✓ Army access permission: {can_access_army}")
    
    # Show access logs
    logs = auth.get_access_logs()
    print(f"✓ Total access logs: {len(logs)}")
    
    return auth

if __name__ == "__main__":
    test_auth_service()