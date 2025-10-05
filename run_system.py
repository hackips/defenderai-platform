"""
DefenderAI System Startup Script
Starts the complete DefenderAI platform
"""

import subprocess
import sys
import os
import time
import threading
from datetime import datetime

def print_banner():
    """Print DefenderAI banner"""
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
║                           Advanced Cybersecurity Platform                               ║
║                     🛡️ Protecting Critical Government Infrastructure                     ║
║                                                                                          ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
""")

def check_dependencies():
    """Check if required dependencies are installed"""
    print("📋 Checking system dependencies...")
    
    required_packages = [
        "fastapi", "uvicorn", "streamlit", "pandas", "numpy", 
        "scikit-learn", "plotly", "requests", "cryptography"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"   ✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"   ❌ {package}")
    
    if missing_packages:
        print(f"\n⚠️ Missing packages: {', '.join(missing_packages)}")
        print("Installing missing dependencies...")
        
        subprocess.run([
            sys.executable, "-m", "pip", "install"
        ] + missing_packages, check=True)
        
        print("✅ Dependencies installed successfully")
    else:
        print("✅ All dependencies satisfied")
    
    return True

def run_integration_test():
    """Run integration tests"""
    print("\n🧪 Running integration tests...")
    
    try:
        # Change to the tests directory
        test_file = os.path.join(os.path.dirname(__file__), "tests", "test_integration.py")
        result = subprocess.run([sys.executable, test_file], 
                              capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ Integration tests passed")
            # Show last few lines of output
            output_lines = result.stdout.split('\n')[-10:]
            for line in output_lines:
                if line.strip():
                    print(f"   {line}")
        else:
            print("❌ Integration tests failed")
            print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print("⚠️ Integration tests timed out (60s)")
    except Exception as e:
        print(f"⚠️ Could not run integration tests: {e}")
    
    return True

def start_api_server():
    """Start the FastAPI server"""
    print("\n🚀 Starting DefenderAI API Server...")
    
    api_file = os.path.join(os.path.dirname(__file__), "api", "main.py")
    
    # Start the API server in a separate process
    api_process = subprocess.Popen([
        sys.executable, "-m", "uvicorn", 
        "api.main:app", 
        "--host", "0.0.0.0", 
        "--port", "8000",
        "--reload"
    ], cwd=os.path.dirname(__file__))
    
    print("✅ API Server starting on http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/docs")
    
    # Wait a moment for server to start
    time.sleep(3)
    
    return api_process

def start_dashboard():
    """Start the Streamlit dashboard"""
    print("\n📊 Starting DefenderAI Dashboard...")
    
    dashboard_file = os.path.join(os.path.dirname(__file__), "dashboard", "streamlit_app.py")
    
    # Start the dashboard in a separate process
    dashboard_process = subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", 
        dashboard_file,
        "--server.port", "8501",
        "--server.address", "0.0.0.0"
    ])
    
    print("✅ Dashboard starting on http://localhost:8501")
    
    # Wait a moment for dashboard to start
    time.sleep(3)
    
    return dashboard_process

def print_system_info():
    """Print system information and access credentials"""
    print("\n" + "="*80)
    print("🛡️ DEFENDERAI PLATFORM READY")
    print("="*80)
    
    print("\n📡 SYSTEM ENDPOINTS:")
    print("   • API Server:       http://localhost:8000")
    print("   • API Documentation: http://localhost:8000/docs")
    print("   • Security Dashboard: http://localhost:8501")
    print("   • Health Check:      http://localhost:8000/health")
    
    print("\n🔐 SAMPLE LOGIN CREDENTIALS:")
    print("   ┌─────────────────────────────────────────────────────────────┐")
    print("   │ Role              │ Username          │ Password            │")
    print("   ├─────────────────────────────────────────────────────────────┤")
    print("   │ System Admin      │ admin.kumar       │ AdminMaster999!     │")
    print("   │ Police Inspector  │ inspector.sharma  │ SecurePass123!      │")
    print("   │ Army Colonel      │ col.singh         │ ArmySecure456!      │")
    print("   │ Health Doctor     │ dr.patel          │ HealthSafe789!      │")
    print("   └─────────────────────────────────────────────────────────────┘")
    
    print("\n🚀 PLATFORM FEATURES:")
    print("   ✅ Cryptographic Integrity (SHA-256 + Merkle Trees)")
    print("   ✅ Department-based Access Control (RBAC/ABAC)")
    print("   ✅ AI-Powered Anomaly Detection (Isolation Forest + Rules)")
    print("   ✅ Automated Response Playbooks (Human-in-Loop)")
    print("   ✅ Real-time Security Monitoring")
    print("   ✅ National Event Spike Detection")
    print("   ✅ Tamper-evident Audit Trails")
    print("   ✅ Cross-department Access Isolation")
    
    print("\n🎯 QUICK START GUIDE:")
    print("   1. Open http://localhost:8501 in your browser")
    print("   2. Login with any of the sample credentials above") 
    print("   3. Explore the Security Dashboard")
    print("   4. Try creating records, monitoring alerts, and testing anomaly detection")
    print("   5. Admin users can approve/reject automated responses")
    
    print("\n📋 TESTING SCENARIOS:")
    print("   • Create records with different classification levels")
    print("   • Test cross-department access (should be blocked)")
    print("   • Log suspicious access patterns to trigger alerts")
    print("   • Simulate Independence Day attack scenarios")
    print("   • Verify cryptographic integrity of records")
    
    print("\n⚠️ SECURITY NOTES:")
    print("   • This is a demonstration platform with sample data")
    print("   • In production, use proper HSM/KMS for key management")
    print("   • Implement proper network security and isolation")
    print("   • Connect to actual CERT-In and NCIIPC channels")
    print("   • Use real MFA and strong authentication mechanisms")
    
    print("\n" + "="*80)
    print(f"⏰ System started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🔧 To stop the system: Press Ctrl+C")
    print("="*80)

def main():
    """Main function to start the DefenderAI platform"""
    try:
        # Print banner
        print_banner()
        
        # Check dependencies 
        if not check_dependencies():
            return
        
        # Run integration tests
        run_integration_test()
        
        # Start API server
        api_process = start_api_server()
        
        # Start dashboard
        dashboard_process = start_dashboard()
        
        # Print system info
        print_system_info()
        
        # Keep the processes running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down DefenderAI platform...")
            
            # Terminate processes
            api_process.terminate()
            dashboard_process.terminate()
            
            # Wait for processes to end
            api_process.wait()
            dashboard_process.wait()
            
            print("✅ DefenderAI platform shut down successfully")
    
    except Exception as e:
        print(f"❌ Error starting DefenderAI platform: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())