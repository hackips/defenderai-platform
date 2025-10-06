"""
AI-Powered Anomaly Detection Engine
Real-time monitoring with ML models for attack detection and behavioral analysis
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import json
import uuid
from enum import Enum
import threading
import time
import logging

class AnomalyLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class DetectorType(Enum):
    ISOLATION_FOREST = "isolation_forest"
    TIME_SERIES = "time_series"
    BEHAVIORAL = "behavioral"
    GEOLOCATION = "geolocation"
    PRIVILEGE_ESCALATION = "privilege_escalation"

class AnomalyDetector:
    """AI-powered anomaly detection system"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.detection_rules = []
        self.alerts = []
        self.baseline_data = []
        self.monitoring_active = False
        self.event_spike_threshold = 5.0  # Standard deviations
        
        # Initialize logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize models
        self._initialize_models()
        self._setup_detection_rules()
        
        # Generate synthetic training data
        self._generate_synthetic_data()
        
        # Train initial models
        self._train_models()
    
    def _initialize_models(self):
        """Initialize ML models for different anomaly types"""
        # Isolation Forest for general outlier detection
        self.models[DetectorType.ISOLATION_FOREST] = IsolationForest(
            contamination=0.05,  # Expect 5% anomalies
            random_state=42,
            n_estimators=100
        )
        
        # Standard scaler for feature normalization
        self.scalers[DetectorType.ISOLATION_FOREST] = StandardScaler()
        
        self.logger.info("Anomaly detection models initialized")
    
    def _setup_detection_rules(self):
        """Setup rule-based detection for immediate threats"""
        self.detection_rules = [
            {
                "name": "impossible_geolocation",
                "description": "User location change faster than physically possible",
                "type": "geolocation",
                "severity": AnomalyLevel.HIGH,
                "threshold": 1000  # km/hour
            },
            {
                "name": "mass_data_access",
                "description": "Unusual volume of data access",
                "type": "behavioral",
                "severity": AnomalyLevel.MEDIUM,
                "threshold": 100  # files per hour
            },
            {
                "name": "privilege_escalation",
                "description": "Sudden increase in privilege level",
                "type": "privilege_escalation",
                "severity": AnomalyLevel.CRITICAL,
                "threshold": 2  # clearance levels
            },
            {
                "name": "after_hours_activity",
                "description": "Activity during non-business hours",
                "type": "behavioral",
                "severity": AnomalyLevel.LOW,
                "threshold": None
            },
            {
                "name": "cross_department_access",
                "description": "Attempts to access cross-department resources",
                "type": "behavioral",
                "severity": AnomalyLevel.HIGH,
                "threshold": 1
            }
        ]
    
    def _generate_synthetic_data(self):
        """Generate synthetic access pattern data for training"""
        np.random.seed(42)
        
        # Normal patterns
        for i in range(1000):
            # Business hours activity (9 AM - 6 PM)
            hour = np.random.normal(13, 3)  # Peak at 1 PM
            hour = max(9, min(18, hour))
            
            self.baseline_data.append({
                "timestamp": datetime.now(timezone.utc) - timedelta(days=np.random.randint(1, 30)),
                "user_id": f"user_{np.random.randint(1, 50)}",
                "dept": np.random.choice(["POLICE", "ARMY", "HEALTH"]),
                "files_accessed": max(1, int(np.random.poisson(5))),
                "session_duration": max(300, int(np.random.normal(3600, 900))),  # 1 hour ± 15 min
                "data_volume_mb": max(1, int(np.random.exponential(10))),
                "unique_resources": max(1, int(np.random.poisson(3))),
                "hour_of_day": int(hour),
                "day_of_week": np.random.randint(0, 7),
                "login_attempts": 1,
                "failed_authentications": 0,
                "source_ip_changes": 0,
                "clearance_level": np.random.randint(1, 4),
                "anomaly_score": 0.0
            })
        
        # Add some anomalous patterns
        for i in range(50):
            # Suspicious patterns
            self.baseline_data.append({
                "timestamp": datetime.now(timezone.utc) - timedelta(days=np.random.randint(1, 30)),
                "user_id": f"user_{np.random.randint(1, 50)}",
                "dept": np.random.choice(["POLICE", "ARMY", "HEALTH"]),
                "files_accessed": int(np.random.uniform(50, 200)),  # High access
                "session_duration": int(np.random.uniform(7200, 14400)),  # Long sessions
                "data_volume_mb": int(np.random.uniform(100, 500)),  # High volume
                "unique_resources": int(np.random.uniform(20, 50)),  # Many resources
                "hour_of_day": np.random.choice([2, 3, 4, 22, 23]),  # Off-hours
                "day_of_week": np.random.randint(0, 7),
                "login_attempts": np.random.randint(3, 10),  # Multiple attempts
                "failed_authentications": np.random.randint(1, 5),
                "source_ip_changes": np.random.randint(2, 5),  # IP hopping
                "clearance_level": np.random.randint(1, 5),
                "anomaly_score": 1.0  # Known anomaly
            })
        
        self.logger.info(f"Generated {len(self.baseline_data)} synthetic data points")
    
    def _train_models(self):
        """Train anomaly detection models"""
        if not self.baseline_data:
            return
        
        # Prepare training data
        df = pd.DataFrame(self.baseline_data)
        
        # Feature engineering
        features = [
            'files_accessed', 'session_duration', 'data_volume_mb',
            'unique_resources', 'hour_of_day', 'day_of_week',
            'login_attempts', 'failed_authentications', 'source_ip_changes',
            'clearance_level'
        ]
        
        X = df[features].fillna(0)
        
        # Scale features
        X_scaled = self.scalers[DetectorType.ISOLATION_FOREST].fit_transform(X)
        
        # Train Isolation Forest
        self.models[DetectorType.ISOLATION_FOREST].fit(X_scaled)
        
        self.logger.info("Anomaly detection models trained successfully")
    
    def analyze_access_pattern(self, access_data: Dict) -> Dict:
        """Analyze single access pattern for anomalies"""
        # Rule-based detection first (fast)
        rule_alerts = self._check_rules(access_data)
        
        # ML-based detection
        ml_score = self._calculate_ml_anomaly_score(access_data)
        
        # Combine scores
        total_score = ml_score
        severity = AnomalyLevel.LOW
        
        if rule_alerts:
            max_rule_severity = max((alert["severity"] for alert in rule_alerts), key=lambda x: x.value)
            if max_rule_severity.value > severity.value:
                severity = max_rule_severity
            total_score += len(rule_alerts) * 0.3
        
        if total_score > 0.8:
            severity = AnomalyLevel.CRITICAL
        elif total_score > 0.6:
            severity = AnomalyLevel.HIGH
        elif total_score > 0.4:
            severity = AnomalyLevel.MEDIUM
        
        result = {
            "anomaly_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "user_id": access_data.get("user_id"),
            "dept": access_data.get("dept"),
            "anomaly_score": total_score,
            "severity": severity,
            "ml_score": ml_score,
            "rule_violations": rule_alerts,
            "details": access_data,
            "recommended_actions": self._get_recommended_actions(severity, rule_alerts)
        }
        
        # Store alert if significant
        if severity.value >= AnomalyLevel.MEDIUM.value:
            self.alerts.append(result)
            self.logger.warning(f"Anomaly detected: {severity.name} - Score: {total_score:.3f}")
        
        return result
    
    def _check_rules(self, access_data: Dict) -> List[Dict]:
        """Check rule-based detection"""
        violations = []
        
        for rule in self.detection_rules:
            if self._evaluate_rule(rule, access_data):
                violations.append({
                    "rule_name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "type": rule["type"]
                })
        
        return violations
    
    def _evaluate_rule(self, rule: Dict, data: Dict) -> bool:
        """Evaluate a specific rule against data"""
        rule_name = rule["name"]
        
        if rule_name == "impossible_geolocation":
            # Simulate geolocation check (in real system, compare with previous location)
            return data.get("source_ip_changes", 0) > 3
        
        elif rule_name == "mass_data_access":
            return data.get("files_accessed", 0) > rule["threshold"]
        
        elif rule_name == "privilege_escalation":
            # In real system, compare with historical clearance level
            return data.get("clearance_level", 1) > 4
        
        elif rule_name == "after_hours_activity":
            hour = data.get("hour_of_day", 12)
            return hour < 6 or hour > 22
        
        elif rule_name == "cross_department_access":
            # This would be detected at the auth layer and logged
            return data.get("cross_dept_attempts", 0) > 0
        
        return False
    
    def _calculate_ml_anomaly_score(self, access_data: Dict) -> float:
        """Calculate ML-based anomaly score"""
        try:
            # Prepare features
            features = [
                access_data.get('files_accessed', 0),
                access_data.get('session_duration', 0),
                access_data.get('data_volume_mb', 0),
                access_data.get('unique_resources', 0),
                access_data.get('hour_of_day', 12),
                access_data.get('day_of_week', 1),
                access_data.get('login_attempts', 1),
                access_data.get('failed_authentications', 0),
                access_data.get('source_ip_changes', 0),
                access_data.get('clearance_level', 1)
            ]
            
            # Scale features
            features_scaled = self.scalers[DetectorType.ISOLATION_FOREST].transform([features])
            
            # Get anomaly score from Isolation Forest
            # Returns -1 for anomalies, 1 for normal
            prediction = self.models[DetectorType.ISOLATION_FOREST].predict(features_scaled)[0]
            score = self.models[DetectorType.ISOLATION_FOREST].decision_function(features_scaled)[0]
            
            # Convert to 0-1 scale (higher = more anomalous)
            normalized_score = max(0, (0.5 - score) * 2)
            
            return min(1.0, normalized_score)
        
        except Exception as e:
            self.logger.error(f"Error calculating ML anomaly score: {e}")
            return 0.0
    
    def _get_recommended_actions(self, severity: AnomalyLevel, rule_violations: List[Dict]) -> List[str]:
        """Get recommended containment actions"""
        actions = []
        
        if severity == AnomalyLevel.CRITICAL:
            actions.extend([
                "IMMEDIATE: Revoke user session",
                "IMMEDIATE: Lock user account",
                "IMMEDIATE: Block source IP",
                "IMMEDIATE: Notify SOC team",
                "IMMEDIATE: Isolate affected systems"
            ])
        
        elif severity == AnomalyLevel.HIGH:
            actions.extend([
                "Revoke current session",
                "Require re-authentication with MFA",
                "Notify security team",
                "Monitor user activity closely"
            ])
        
        elif severity == AnomalyLevel.MEDIUM:
            actions.extend([
                "Log security event",
                "Increase monitoring frequency",
                "Notify supervisor"
            ])
        
        else:  # LOW
            actions.extend([
                "Log event for analysis",
                "Continue normal monitoring"
            ])
        
        # Add specific actions based on rule violations
        for violation in rule_violations:
            if violation["type"] == "geolocation":
                actions.append("Verify user location through secondary channel")
            elif violation["type"] == "privilege_escalation":
                actions.append("Audit recent privilege changes")
        
        return actions
    
    def detect_event_spike(self, recent_events: List[Dict], event_window_hours: int = 1) -> Dict:
        """Detect anomalous spikes during events (like Independence Day)"""
        if not recent_events:
            return {"spike_detected": False}
        
        # Count events in time windows
        now = datetime.now(timezone.utc)
        windows = []
        
        for i in range(24):  # Last 24 hours in 1-hour windows
            window_start = now - timedelta(hours=i+1)
            window_end = now - timedelta(hours=i)
            
            count = sum(1 for event in recent_events 
                       if window_start <= event.get("timestamp", now) < window_end)
            windows.append(count)
        
        if len(windows) < 2:
            return {"spike_detected": False}
        
        # Calculate statistics
        mean_activity = np.mean(windows[1:])  # Exclude current hour
        std_activity = np.std(windows[1:])
        current_activity = windows[0]
        
        if std_activity == 0:
            z_score = 0
        else:
            z_score = (current_activity - mean_activity) / std_activity
        
        spike_detected = z_score > self.event_spike_threshold
        
        result = {
            "spike_detected": spike_detected,
            "z_score": z_score,
            "current_activity": current_activity,
            "baseline_mean": mean_activity,
            "baseline_std": std_activity,
            "threshold": self.event_spike_threshold,
            "analysis_window": "24 hours",
            "recommendation": "Increase monitoring during event periods" if spike_detected else "Normal activity levels"
        }
        
        if spike_detected:
            self.logger.warning(f"Event spike detected: Z-score {z_score:.2f}")
        
        return result
    
    def get_recent_alerts(self, hours: int = 24, dept: str = None) -> List[Dict]:
        """Get recent alerts with optional department filtering"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        filtered_alerts = [
            alert for alert in self.alerts 
            if alert["timestamp"] > cutoff_time
        ]
        
        if dept:
            filtered_alerts = [
                alert for alert in filtered_alerts 
                if alert.get("dept") == dept
            ]
        
        # Sort by severity and timestamp
        filtered_alerts.sort(
            key=lambda x: (x["severity"].value, x["timestamp"]), 
            reverse=True
        )
        
        return filtered_alerts
    
    def get_anomaly_statistics(self) -> Dict:
        """Get anomaly detection statistics"""
        total_alerts = len(self.alerts)
        if total_alerts == 0:
            return {"total_alerts": 0}
        
        # Count by severity
        severity_counts = {}
        for level in AnomalyLevel:
            severity_counts[level.name] = sum(
                1 for alert in self.alerts 
                if alert["severity"] == level
            )
        
        # Count by department
        dept_counts = {}
        for alert in self.alerts:
            dept = alert.get("dept", "UNKNOWN")
            dept_counts[dept] = dept_counts.get(dept, 0) + 1
        
        return {
            "total_alerts": total_alerts,
            "severity_breakdown": severity_counts,
            "department_breakdown": dept_counts,
            "average_score": np.mean([alert["anomaly_score"] for alert in self.alerts]),
            "last_24h_alerts": len(self.get_recent_alerts(24))
        }

# Test function
def test_anomaly_detector():
    """Test the anomaly detection system"""
    detector = AnomalyDetector()
    
    print("=== DefenderAI Anomaly Detector Test ===")
    
    # Test normal access pattern
    normal_access = {
        "user_id": "user_123",
        "dept": "POLICE",
        "files_accessed": 5,
        "session_duration": 3600,
        "data_volume_mb": 10,
        "unique_resources": 3,
        "hour_of_day": 14,
        "day_of_week": 2,
        "login_attempts": 1,
        "failed_authentications": 0,
        "source_ip_changes": 0,
        "clearance_level": 3
    }
    
    result = detector.analyze_access_pattern(normal_access)
    print(f"✓ Normal pattern analysis - Score: {result['anomaly_score']:.3f}, Severity: {result['severity'].name}")
    
    # Test suspicious access pattern
    suspicious_access = {
        "user_id": "user_456",
        "dept": "ARMY",
        "files_accessed": 150,  # High
        "session_duration": 10800,  # Long
        "data_volume_mb": 200,  # High volume
        "unique_resources": 30,  # Many resources
        "hour_of_day": 2,  # Off hours
        "day_of_week": 6,
        "login_attempts": 1,
        "failed_authentications": 0,
        "source_ip_changes": 4,  # IP hopping
        "clearance_level": 4
    }
    
    result = detector.analyze_access_pattern(suspicious_access)
    print(f"✓ Suspicious pattern analysis - Score: {result['anomaly_score']:.3f}, Severity: {result['severity'].name}")
    print(f"✓ Rule violations: {len(result['rule_violations'])}")
    
    # Test event spike detection
    mock_events = [
        {"timestamp": datetime.now(timezone.utc) - timedelta(minutes=i*10)}
        for i in range(50)  # Many recent events
    ]
    
    spike_result = detector.detect_event_spike(mock_events)
    print(f"✓ Event spike detection - Detected: {spike_result['spike_detected']}")
    
    # Show statistics
    stats = detector.get_anomaly_statistics()
    print(f"✓ Total alerts generated: {stats['total_alerts']}")
    
    return detector

if __name__ == "__main__":
    test_anomaly_detector()
