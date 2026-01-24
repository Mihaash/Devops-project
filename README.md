# 🛡️ Company Security Alert & Threat Intelligence Dashboard

A comprehensive real-time cybersecurity monitoring system that provides threat intelligence, vulnerability analysis, automated alerting, and professional dashboard visualization for Security Operations Centers (SOC).

## 🚀 Features

### 🔍 Threat Intelligence Collection
- **CVE Monitoring**: Automatically fetches recent Common Vulnerabilities and Exposures
- **Malware Indicators**: Collects malicious IP addresses, domains, and file hashes
- **Internal Log Analysis**: Monitors login attempts, application behavior, and network anomalies
- **Real-time Updates**: Continuous threat intelligence gathering every 5 minutes

### 🎯 Vulnerability Correlation
- **Asset Inventory Management**: Tracks company servers, applications, and software versions
- **Smart Correlation**: Automatically matches vulnerabilities with affected assets
- **Severity Classification**: Prioritizes threats based on CVSS scores and asset criticality
- **Remediation Recommendations**: Provides actionable mitigation steps

### 🚨 Alert System
- **Multi-level Severity**: Low, Medium, High, and Critical alert classification
- **Duplicate Prevention**: Intelligent deduplication to avoid alert flooding
- **Comprehensive Metadata**: Detailed alert information with timestamps and recommendations
- **Alert Statistics**: Real-time metrics and trend analysis

### 📊 Real-time Dashboard
- **Dark Professional Theme**: SOC-style interface optimized for monitoring
- **Auto-refresh**: Updates every 30 seconds for live threat visibility
- **Interactive Charts**: Severity distribution, alert types, and timeline visualization
- **Detailed Alert Table**: Sortable and filterable alert information
- **Responsive Design**: Works on desktop and mobile devices

### 📧 Email Notifications
- **Automated Alerts**: Immediate email notifications for High and Critical threats
- **Professional Templates**: HTML and plain text email formats
- **Batch Summaries**: Consolidated alerts for efficient incident response
- **Duplicate Prevention**: Avoids repeated notifications for same threats

### 🐳 Docker Deployment
- **Containerized**: Easy deployment with Docker and Docker Compose
- **Production Ready**: Includes health checks and proper configuration
- **Scalable**: Can be deployed in containerized environments
- **Isolated**: Secure and consistent deployment across environments

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Dashboard                      │
├─────────────────────────────────────────────────────────────┤
│  Threat Intelligence  │  Vulnerability Correlation Engine  │
│  Collection Module   │                                     │
│                      │                                     │
│  • CVE Database      │  • Asset Inventory Management       │
│  • Malware Feeds     │  • Vulnerability Matching           │
│  • Internal Logs     │  • Severity Classification          │
├─────────────────────────────────────────────────────────────┤
│                    Alert System                            │
│                      │                                     │
│  • Alert Generation  │  • Email Notifications              │
│  • Deduplication     │  • Dashboard Updates                │
│  • Severity Analysis │  • Alert Statistics                 │
├─────────────────────────────────────────────────────────────┤
│                 Real-time Dashboard                        │
│                      │                                     │
│  • Dark Theme UI     │  • Auto-refresh (30s)              │
│  • Interactive Charts│  • Alert Details Table             │
│  • Metrics Cards     │  • Timeline Visualization          │
└─────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

- Python 3.9 or higher
- Docker and Docker Compose (for containerized deployment)
- Gmail account (for email notifications) or SMTP server

## 🚀 Quick Start

### Option 1: Docker Deployment (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd security-dashboard
   ```

2. **Configure email settings**
   ```bash
   # Edit config.yaml with your email settings
   nano config.yaml
   ```

3. **Run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

4. **Access the dashboard**
   ```
   http://localhost:8050
   ```

### Option 2: Local Development

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure settings**
   ```bash
   # Update config.yaml with your settings
   nano config.yaml
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

4. **Access the dashboard**
   ```
   http://localhost:8050
   ```

## ⚙️ Configuration

### Email Configuration
Update `config.yaml` with your email settings:

```yaml
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  sender_email: "security-alerts@company.com"
  sender_password: "your-app-password"  # Use app password for Gmail
  recipient_emails:
    - "security-team@company.com"
    - "soc-manager@company.com"
```

### Asset Inventory
Update the assets section with your company's infrastructure:

```yaml
assets:
  servers:
    - name: "web-server-01"
      ip: "192.168.1.10"
      software:
        - name: "Apache"
          version: "2.4.41"
        - name: "OpenSSL"
          version: "1.1.1"
  applications:
    - name: "company-webapp"
      version: "1.2.3"
      framework: "Django"
```

### Dashboard Settings
Customize dashboard behavior:

```yaml
dashboard:
  host: "0.0.0.0"
  port: 8050
  debug: false
  auto_refresh_interval: 30  # seconds
```

## 📊 Dashboard Features

### Metrics Cards
- **Total Alerts**: Overall number of security alerts
- **Critical**: Count of critical severity alerts
- **High**: Count of high severity alerts  
- **Active Threats**: Number of currently active alerts

### Visualizations
- **Severity Distribution**: Pie chart showing alert breakdown by severity
- **Alert Types**: Bar chart displaying different alert categories
- **Timeline**: 24-hour timeline of alert activity

### Alert Table
- **Real-time Updates**: Auto-refreshes with latest alerts
- **Color-coded Severity**: Visual priority indicators
- **Sortable Columns**: Sort by time, severity, type, etc.
- **Filterable**: Search and filter capabilities

## 🚨 Alert Types

### Vulnerability Alerts
- CVE-based vulnerability detection
- Asset correlation and impact assessment
- CVSS score-based severity classification
- Patch and remediation recommendations

### Malware Alerts
- Malicious IP address detection
- Domain-based threat indicators
- File hash malware identification
- Confidence-based threat scoring

### Activity Alerts
- Brute force login attempts
- Unusual application behavior
- Network traffic anomalies
- Resource usage monitoring

## 📧 Email Notifications

### Trigger Conditions
- **Critical Alerts**: Immediate individual notifications
- **High Alerts**: Batched summary notifications
- **Duplicate Prevention**: No repeated emails for same threats

### Email Content
- Professional HTML and plain text formats
- Detailed alert information
- Recommended actions
- Dashboard access links

## 🔧 Customization

### Adding New Threat Sources
Extend the `ThreatIntelligenceCollector` class:

```python
def fetch_custom_threats(self):
    # Add your custom threat intelligence source
    pass
```

### Custom Alert Types
Add new alert types in `AlertType` enum:

```python
class AlertType(Enum):
    VULNERABILITY = "Vulnerability"
    MALWARE = "Malware"
    CUSTOM_TYPE = "Custom Alert"
```

### Dashboard Customization
Modify the `SecurityDashboard` class to add new visualizations or change the UI theme.

## 🐳 Docker Deployment

### Build and Run
```bash
# Build the image
docker build -t security-dashboard .

# Run the container
docker run -p 8050:8050 -v $(pwd)/config.yaml:/app/config.yaml security-dashboard
```

### Docker Compose
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## 📈 Monitoring and Maintenance

### Log Files
- Application logs: `logs/security_dashboard.log`
- Docker logs: `docker-compose logs security-dashboard`

### Health Checks
- Container health check endpoint: `http://localhost:8050/`
- Automatic restart on failure

### Performance Tuning
- Adjust alert collection intervals
- Configure maximum alert limits
- Optimize database queries for large deployments

## 🔒 Security Considerations

### Email Security
- Use app passwords for Gmail instead of main passwords
- Enable TLS for SMTP connections
- Consider using dedicated security email accounts

### Network Security
- Deploy behind reverse proxy in production
- Use HTTPS for dashboard access
- Implement proper firewall rules

### Data Protection
- Regular log rotation
- Secure configuration file storage
- Consider database encryption for sensitive data

## 🛠️ Troubleshooting

### Common Issues

**Dashboard not loading**
```bash
# Check if port is available
netstat -tulpn | grep 8050

# Check Docker logs
docker-compose logs security-dashboard
```

**Email notifications not working**
```bash
# Verify SMTP settings
# Check app password for Gmail
# Review logs for authentication errors
```

**No alerts showing**
```bash
# Check threat intelligence collection logs
# Verify asset inventory configuration
# Review alert system logs
```

### Debug Mode
Enable debug mode in `config.yaml`:

```yaml
dashboard:
  debug: true
```

## 📚 API Reference

### Configuration Classes
- `ConfigManager`: Handles configuration loading and validation
- `ThreatIntelligenceCollector`: Collects threat data from various sources
- `VulnerabilityCorrelation`: Correlates threats with assets
- `AlertSystem`: Manages alert generation and deduplication
- `EmailAlertSystem`: Handles email notifications
- `SecurityDashboard`: Provides real-time web interface

### Key Methods
- `fetch_recent_cves()`: Get latest CVE information
- `correlate_cves_with_assets()`: Match vulnerabilities to assets
- `generate_alerts_from_vulnerabilities()`: Create vulnerability alerts
- `send_alert_notification()`: Send email notifications

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For support and questions:
- Create an issue in the repository
- Review the troubleshooting section
- Check the application logs

## 🔄 Version History

- **v1.0.0**: Initial release with core functionality
  - Threat intelligence collection
  - Vulnerability correlation
  - Real-time dashboard
  - Email notifications
  - Docker deployment

---

**⚠️ Disclaimer**: This is a demonstration project for educational purposes. In production environments, ensure proper security hardening, regular updates, and compliance with organizational security policies.
