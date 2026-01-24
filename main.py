#!/usr/bin/env python3
"""
Company Security Alert & Threat Intelligence Dashboard
Main application entry point
"""

import logging
import schedule
import time
import threading
from datetime import datetime
from src.config_manager import ConfigManager
from src.threat_intelligence import ThreatIntelligenceCollector
from src.vulnerability_correlation import VulnerabilityCorrelation
from src.alert_system import AlertSystem
from src.email_alerts import EmailAlertSystem
from src.dashboard import SecurityDashboard

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/security_dashboard.log'),
            logging.StreamHandler()
        ]
    )

def collect_threat_intelligence(config_manager, threat_collector, vuln_correlator, alert_system, email_system):
    """Collect threat intelligence and generate alerts"""
    try:
        logging.info("Starting threat intelligence collection...")
        
        # Fetch recent CVEs
        cves = threat_collector.fetch_recent_cves(days_back=7)
        logging.info(f"Fetched {len(cves)} CVEs")
        
        # Fetch malware indicators
        malware_indicators = threat_collector.fetch_malware_indicators()
        logging.info(f"Fetched {len(malware_indicators)} malware indicators")
        
        # Generate sample internal logs
        internal_logs = threat_collector.generate_sample_logs()
        
        # Analyze internal logs for suspicious activities
        suspicious_activities = threat_collector.analyze_internal_logs(internal_logs)
        logging.info(f"Identified {len(suspicious_activities)} suspicious activities")
        
        # Correlate vulnerabilities with assets
        correlated_vulns = vuln_correlator.correlate_cves_with_assets(cves)
        logging.info(f"Correlated {len(correlated_vulns)} vulnerabilities with assets")
        
        # Correlate malware with assets
        correlated_threats = vuln_correlator.correlate_malware_with_assets(malware_indicators)
        logging.info(f"Correlated {len(correlated_threats)} malware threats with assets")
        
        # Generate alerts
        vulnerability_alerts = alert_system.generate_alerts_from_vulnerabilities(correlated_vulns)
        malware_alerts = alert_system.generate_alerts_from_malware(correlated_threats)
        activity_alerts = alert_system.generate_alerts_from_activities(suspicious_activities)
        
        all_alerts = vulnerability_alerts + malware_alerts + activity_alerts
        logging.info(f"Generated {len(all_alerts)} total alerts")
        
        # Add alerts to the system
        alert_system.add_alerts(all_alerts)
        
        # Send email notifications for high/critical alerts
        if all_alerts:
            # Send individual notifications for critical alerts
            critical_alerts = [alert for alert in all_alerts if alert['severity'] == 'Critical']
            for alert in critical_alerts:
                email_system.send_alert_notification(alert)
            
            # Send batch summary for high alerts
            high_alerts = [alert for alert in all_alerts if alert['severity'] == 'High']
            if high_alerts:
                email_system.send_batch_alert_summary(high_alerts)
        
        logging.info("Threat intelligence collection completed")
        
    except Exception as e:
        logging.error(f"Error in threat intelligence collection: {e}")

def run_background_tasks(config_manager, threat_collector, vuln_correlator, alert_system, email_system):
    """Run background threat intelligence collection"""
    # Schedule threat intelligence collection every 5 minutes
    schedule.every(5).minutes.do(
        collect_threat_intelligence,
        config_manager, threat_collector, vuln_correlator, alert_system, email_system
    )
    
    # Initial collection
    collect_threat_intelligence(config_manager, threat_collector, vuln_correlator, alert_system, email_system)
    
    # Run scheduled tasks
    while True:
        schedule.run_pending()
        time.sleep(1)

def main():
    """Main application entry point"""
    # Setup logging
    setup_logging()
    logging.info("Starting Security Alert & Threat Intelligence Dashboard...")
    
    try:
        # Initialize configuration manager
        config_manager = ConfigManager()
        logging.info("Configuration loaded successfully")
        
        # Initialize threat intelligence collector
        threat_collector = ThreatIntelligenceCollector(config_manager.get_threat_intel_config())
        
        # Initialize vulnerability correlation
        vuln_correlator = VulnerabilityCorrelation(config_manager.get_assets())
        
        # Initialize alert system
        alert_system = AlertSystem(config_manager.get_alert_thresholds())
        
        # Initialize email alert system
        email_system = EmailAlertSystem(config_manager.get_email_config())
        
        # Start background threat intelligence collection in a separate thread
        background_thread = threading.Thread(
            target=run_background_tasks,
            args=(config_manager, threat_collector, vuln_correlator, alert_system, email_system),
            daemon=True
        )
        background_thread.start()
        logging.info("Background threat intelligence collection started")
        
        # Initialize and run dashboard
        dashboard = SecurityDashboard(alert_system, config_manager.get_dashboard_config())
        logging.info("Dashboard initialized successfully")
        
        # Get dashboard configuration
        dashboard_config = config_manager.get_dashboard_config()
        host = dashboard_config.get("host", "0.0.0.0")
        port = dashboard_config.get("port", 8050)
        debug = dashboard_config.get("debug", False)
        
        logging.info(f"Starting dashboard on {host}:{port}")
        print(f"\n🛡️ Security Dashboard is running!")
        print(f"📊 Access the dashboard at: http://{host}:{port}")
        print(f"🔄 Auto-refresh interval: {dashboard_config.get('auto_refresh_interval', 30)} seconds")
        print(f"📧 Email alerts configured: {'Yes' if config_manager.get_email_config() else 'No'}")
        print(f"\nPress Ctrl+C to stop the application\n")
        
        # Run the dashboard
        dashboard.run(debug=debug)
        
    except KeyboardInterrupt:
        logging.info("Application stopped by user")
        print("\n👋 Security Dashboard stopped. Goodbye!")
    except Exception as e:
        logging.error(f"Application error: {e}")
        print(f"\n❌ Application error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
