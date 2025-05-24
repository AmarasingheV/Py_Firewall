# Py_Firewall

## Overview
This project is a Python-based firewall application with a web interface, developed as part of a group project (COHNDNE241F-016 and COHNDNE241F-024). It is designed to monitor and control network traffic, offering features like packet filtering, anomaly detection (IDS/IPS), network scanning, blacklisting, and alias management. The application uses Flask for the web interface, Scapy for packet handling, and NetfilterQueue for packet filtering on Linux systems.

**Note:** This project is for educational and testing purposes only. It is not intended for production use without proper security hardening and testing.

## Major Components
- **`firewall.py`**: The main script that handles packet filtering, anomaly detection, and the Flask web server.
  - Uses Scapy to parse and analyze network packets.
  - Integrates with NetfilterQueue to intercept and filter packets via iptables.
  - Implements IDS (Intrusion Detection System) and IPS (Intrusion Prevention System) modes for anomaly detection and auto-blocking.
  - Provides a REST API for the web interface to manage rules, aliases, blacklist, and settings.
- **`web/dashboard.html`**: The main dashboard page for the web interface.
  - Displays network interfaces, logs, firewall rules, users, aliases, network scan results, and blacklisted IPs.
  - Allows users to add/edit/delete rules, manage aliases, and configure IDS/IPS settings.
- **`web/script.js`**: JavaScript for the dashboard.
  - Handles dynamic updates (e.g., logs, rules, blacklist) via periodic API calls.
  - Implements form submissions for adding/editing rules, aliases, and blacklisted IPs.
  - Manages network scans and toggles IDS/IPS settings.
- **`web/style.css`**: CSS for styling the web interface.
  - Provides a dark theme with a responsive layout for the dashboard.
- **`web/login.html`**: A simple login page for user authentication.
- **`install_dependencies.sh`**: A shell script to install required dependencies.

## Prerequisites
- **Operating System**: Linux (due to iptables and NetfilterQueue dependencies).
- **Python**: Version 3.6 or higher.
- **Dependencies**:
  - Run the provided script to install dependencies:
    ```bash
    chmod +x install_dependencies.sh
    ./install_dependencies.sh
