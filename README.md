# NetSecure
The tool provides real-time packet analysis, identifies network anomalies like port scans and DoS floods, and integrates live threat intelligence via REST APIs for proactive threat identification.
Key Features
Real-Time Packet Analysis: Captures and analyzes network traffic on the fly, providing immediate insights into network activity.

Interactive SOC Dashboard: A modern, professional user interface featuring a live traffic graph and detailed logs for packets and alerts.

Advanced Anomaly Detection: Identifies suspicious network behavior, including:

DoS Floods: Detects unusually high volumes of packets from a single source.

Port Scans: Flags attempts by a source IP to probe multiple ports on a target.

ARP Spoofing: Monitors for signs of Man-in-the-Middle (MITM) attacks on the local network.

Live Threat Intelligence: Integrates with the AbuseIPDB API to check suspicious IP addresses against a global database of known malicious actors.

Geolocation: Identifies the country of origin for external IP addresses to help visualize traffic sources.

Configurable Alerting: Sends real-time alerts for critical events via Email and Slack (configurable via config.ini).

Detailed Logging: All captured packets and triggered alerts are logged to a local SQLite database for persistent storage and later analysis.

