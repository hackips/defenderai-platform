# DefenderAI Security Platform 🛡️

**Advanced Cybersecurity Platform for Critical Government Infrastructure**

DefenderAI is a comprehensive cybersecurity platform that combines cryptographic integrity, departmental access control, AI-powered anomaly detection, and automated response capabilities to protect critical government infrastructure.

## 🚀 Features

### 1. **Cryptographic Integrity**
- **SHA-256 Hashing**: Every record gets an immutable fingerprint
- **Merkle Trees**: Daily snapshots with tamper-evident roots
- **Digital Signatures**: Cryptographically signed snapshots
- **Integrity Verification**: Real-time tamper detection

### 2. **Departmental Access Control (RBAC/ABAC)**
- **Per-Department Keys**: Unique cryptographic keys for each department
- **Short-lived Tokens**: JWT tokens with configurable expiration
- **Strict Partitioning**: Police cannot access Army data and vice versa
- **Clearance Levels**: 5-tier classification system (Public to Top Secret)
- **Cross-Department Isolation**: Prevents unauthorized lateral access

### 3. **AI-Powered Anomaly Detection**
- **Isolation Forest**: Unsupervised ML for outlier detection
- **Rule-Based Detection**: Fast rules for immediate threats
- **Behavioral Analysis**: User pattern recognition
- **Time-Series Detection**: Unusual activity spike detection
- **National Event Monitoring**: Special handling for Independence Day, etc.

### 4. **Automated Response Engine**
- **Smart Playbooks**: Context-aware response automation
- **Human-in-Loop**: High-risk actions require approval
- **Risk-Based Actions**: Graduated response based on threat level
- **Real-time Containment**: Immediate token revocation, IP blocking
- **Audit Trail**: Complete record of all responses

### 5. **Security Monitoring & SIEM**
- **Real-time Dashboards**: Live security status monitoring
- **Alert Management**: Severity-based alert prioritization
- **Audit Trails**: Comprehensive logging for forensics
- **Event Correlation**: Pattern recognition across departments

### 6. **National Security Integration**
- **CERT-In Coordination**: Ready for national CERT integration
- **NCIIPC Compliance**: Aligned with critical infrastructure protection
- **Event Spike Detection**: Monitors for coordinated attacks during national events
- **Secure Communications**: Encrypted departmental messaging

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │   API Gateway    │    │  Authentication │
│   (Streamlit)   │◄──►│   (FastAPI)      │◄──►│   Service       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
        ┌───────▼──────┐ ┌─────▼──────┐ ┌─────▼──────┐
        │ Crypto       │ │ Anomaly    │ │ Response   │
        │ Service      │ │ Detector   │ │ Engine     │
        └──────────────┘ └────────────┘ └────────────┘
                │               │               │
        ┌───────▼──────┐ ┌─────▼──────┐ ┌─────▼──────┐
        │ Merkle Trees │ │ ML Models  │ │ Playbooks  │
        │ & Signatures │ │ & Rules    │ │ & Approvals│
        └──────────────┘ └────────────┘ └────────────┘
```

## 🔧 Installation & Setup

### Prerequisites
- Python 3.8+
- 2GB RAM minimum
- 1GB disk space

### Quick Start

1. **Clone and Setup**
```bash
git clone <repository-url>
cd defenderai
pip install -r requirements.txt
```

2. **Start the Platform**
```bash
python run_system.py
```

3. **Access the System**
- **Dashboard**: http://localhost:8501
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### Sample Credentials

| Role | Username | Password | Department | Clearance |
|------|----------|----------|------------|-----------|
| System Admin | admin.kumar | AdminMaster999! | ADMIN | Top Secret |
| Police Inspector | inspector.sharma | SecurePass123! | POLICE | Secret |
| Army Colonel | col.singh | ArmySecure456! | ARMY | Top Secret |
| Health Doctor | dr.patel | HealthSafe789! | HEALTH | Confidential |

## 📊 Usage Examples

### 1. **Creating Secure Records**
```python
# Via API
POST /records/create
{
    "content": "Confidential Police Report #2024001",
    "metadata": {"classification": "SECRET", "case_id": "POL2024001"},
    "classification": 4,
    "department": "POLICE"
}
```

### 2. **Monitoring Access Patterns**
```python
# Log access for anomaly detection
POST /monitoring/log-access
{
    "user_id": "inspector.sharma",
    "dept": "POLICE",
    "files_accessed": 150,  # High number triggers alert
    "session_duration": 14400,
    "data_volume_mb": 500
}
```

### 3. **Checking for Event Spikes**
```python
# Check for Independence Day attack patterns
GET /monitoring/event-spike
# Returns: {"spike_detected": true, "z_score": 7.2, "recommendation": "..."}
```

## 🧪 Testing Scenarios

### 1. **Normal Operations**
- Login with different department credentials
- Create records with various classification levels
- Verify cross-department access is blocked
- Check cryptographic integrity verification

### 2. **Anomaly Detection**
- Log suspicious access patterns (high volume, off-hours)
- Trigger rule-based detection (impossible geolocation)
- Test behavioral anomalies (unusual resource access)

### 3. **Independence Day Simulation**
- Simulate coordinated attack during national event
- Test event spike detection algorithms
- Verify automated response playbooks execute
- Check human-in-loop approval workflow

### 4. **Security Validation**
- Attempt cross-department data access
- Test token expiration and revocation
- Verify Merkle tree integrity checks
- Validate audit trail completeness

## 🔒 Security Features

### Cryptographic Protection
- **256-bit AES encryption** for sensitive data
- **RSA-2048 signatures** for integrity verification
- **HMAC authentication** for message integrity
- **Secure random generation** for keys and tokens

### Access Control
- **Zero-trust architecture** - verify every access
- **Principle of least privilege** - minimal required access
- **Time-bounded access** - automatic token expiration
- **Department isolation** - strict data segregation

### Monitoring & Detection
- **Real-time analysis** - sub-second threat detection
- **Behavioral baselines** - learn normal usage patterns
- **Anomaly scoring** - ML-based risk assessment
- **Event correlation** - pattern recognition across time

## 📋 API Endpoints

### Authentication
- `POST /auth/login` - User authentication
- `GET /auth/me` - Current user info
- `POST /auth/logout` - Session termination

### Records Management
- `POST /records/create` - Create secure record
- `GET /records/{id}` - Retrieve with integrity check
- `GET /records/department/{dept}` - Department records

### Security Monitoring
- `POST /monitoring/log-access` - Log access pattern
- `GET /monitoring/alerts` - Recent security alerts
- `GET /monitoring/event-spike` - Event spike detection
- `GET /monitoring/statistics` - System statistics

### Admin Operations
- `GET /admin/pending-approvals` - Approval queue
- `POST /admin/approve-action` - Approve/reject actions
- `GET /admin/audit-trail` - Comprehensive audit log
- `GET /admin/system-status` - System health status

## 🎯 Production Deployment

### Security Hardening
1. **Use Hardware Security Modules (HSM)** for key storage
2. **Implement proper mTLS** for all communications
3. **Deploy Web Application Firewall (WAF)**
4. **Enable DDoS protection** for public endpoints
5. **Use secure network segmentation**

### Integration Points
1. **CERT-In Integration** - Real-time threat intelligence
2. **NCIIPC Coordination** - Critical infrastructure protection
3. **SIEM Integration** - ELK Stack, Splunk, or similar
4. **Identity Providers** - Active Directory, LDAP integration
5. **Backup Systems** - Immutable offline backups

### Monitoring & Maintenance
1. **24/7 SOC Operations** - Continuous monitoring
2. **Regular Penetration Testing** - Security validation
3. **Vulnerability Management** - Patch management process
4. **Incident Response Plan** - Coordinated response procedures
5. **Business Continuity** - Disaster recovery planning

## 🚨 Emergency Procedures

### High-Risk Alerts
1. **Immediate containment** - Automatic session revocation
2. **SOC notification** - Real-time alert to security team
3. **Management escalation** - Executive notification for critical threats
4. **System isolation** - Network segmentation for affected systems

### Independence Day Protocol
1. **Enhanced monitoring** - Increased sensitivity thresholds
2. **Pre-staged responses** - Rapid containment capabilities
3. **Additional staffing** - 24/7 security operations
4. **Coordination channels** - Direct CERT-In communication

## 📞 Support & Contact

### Technical Support
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Comprehensive API and user guides
- **Community Forum**: User discussions and best practices

### Security Contacts
- **Security Team**: security@defenderai.gov.in
- **CERT-In Integration**: cert-in@defenderai.gov.in
- **Emergency Response**: emergency@defenderai.gov.in

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CERT-In** - National Computer Emergency Response Team
- **NCIIPC** - National Critical Information Infrastructure Protection Centre
- **MeitY** - Ministry of Electronics and Information Technology
- **OpenSource Community** - For the amazing tools and libraries

---

**DefenderAI - Protecting India's Digital Infrastructure** 🇮🇳🛡️