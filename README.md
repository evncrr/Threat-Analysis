# Cyber Threat Analysis
## Project Overview
- This project analyzes cybersecurity threat data from network traffic and phishing URLs to generate actionable threat intelligence insights.
- Uses SQL tables, views, aggregation analytics, and anomaly detection to help monitor attacks, analyze risk levels, and detect suspicious patterns.
- The system supports cybersecurity teams by identifying high-risk traffic, comparing different threat vectors, and generating normalized risk scores across datasets.
## Dataset
### Network Traffic Data
- Network connection metrics
- Protocol and service information
- Packet and byte statistics
- Attack classification labels
- Example fields: id, proto, service, state, sbytes, dbytes, rate, attack_cat, label
### Phishing URL Data
- URL structural features
- Domain and DNS characteristics
- Security certificate indicators
- Email and redirection signals
- Example fields: URL structure counts, length_url, tls_ssl_certificate, domain_in_ip, phishing
## Tables
### Network Traffic Table
- Stores network intrusion detection records and supports threat classification analytics.
### Phishing URLs Table
- Stores phishing detection features used to identify malicious websites.
## Views
- threat_risk_intelligence – Breaks down attacks by protocol and category.
- top_attack_categories – Ranks attack categories by frequency and severity.
- high_risk_traffic – Detects anomalous high-volume network traffic.
- unified_threat_landscape – Compares network threats and phishing threats across datasets.
- http_attack_vs_phishing_tls – Compares HTTP-based attacks with phishing TLS security patterns.
- ftp_attack_vs_phishing_email – Compares FTP abuse activity with phishing email embedding behavior.
- dns_amplification_vs_phishing_domains – Compares DNS network threats with suspicious domain patterns.
- phishing_summary – Summarizes phishing vs legitimate URL feature averages.
## Key metrics analyzed:
- URL complexity
- Security certificate presence
- Domain spoofing indicators
- Redirection behavior
- Risk Scoring
## Key Insights
- Identify high-volume and high-severity attack patterns.
- Detect anomalous network traffic behavior.
- Compare phishing and network-based cyber threats.
- Evaluate cybersecurity risk using normalized scoring.
- Support security monitoring and threat response decisions.
## Technical Highlights
- SQL views used for reusable threat analytics reporting.
- Aggregation functions including COUNT, AVG, SUM, and ROUND.
- Anomaly detection using statistical deviation thresholds.
- Conditional logic for security feature evaluation.
- Cross-dataset intelligence comparison using UNION queries.
