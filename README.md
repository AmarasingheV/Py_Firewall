# Py_Firewall

## Overview
This project is a Python-based firewall application with a web interface, developed as part of a group project. It is designed to monitor and control network traffic, offering features like packet filtering, anomaly detection (IDS/IPS), network scanning, blacklisting, and alias management. The application uses Flask for the web interface, Scapy for packet handling, and NetfilterQueue for packet filtering on Linux systems.

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
    ```
    chmod +x install_dependencies.sh
    ./install_dependencies.sh

Installation

    Clone the repository:
    

    git clone https://github.com/AmarasingheV/Py_Firewall.git
    cd Py_Firewall
    Install dependencies (as listed above).
    Ensure the web directory contains dashboard.html, login.html, script.js, and style.css.

Usage

    Run the firewall script as root:

    sudo python3 firewall.py
    Access the web interface at http://localhost:5000 in your browser.
    Log in with the default credentials:
        Username: admin
        Password: admin123
    Use the dashboard to:
        Monitor network interfaces.
        View and export logs.
        Add/edit/delete firewall rules.
        Manage users and aliases.
        Perform network scans and manage blacklisted IPs.
        Configure IDS/IPS settings.

Features

    Packet Filtering: Define rules to allow or drop packets based on source/destination IP, protocol, and ports.
    IDS/IPS: Detect anomalies (e.g., high packet rates) and optionally auto-block IPs in IPS mode.
    Network Scanning: Scan networks for open ports using nmap.
    Blacklist Management: Manually blacklist IPs or remove them from the blacklist.
    Aliases: Group IPs into aliases for easier rule management.
    Logging: View and export packet logs.
    User Management: Add, modify, or delete users via the web interface.

Troubleshooting

    Network Scan Issues:
        Ensure nmap is installed and has proper permissions:


chmod +x /usr/bin/nmap
Verify the network range (e.g., 192.168.0.0/24) matches your network:
bash

    ip addr
    Check firewall.log for errors.

Permission Errors: Run the script as root (sudo).
Port Conflicts: Ensure port 5000 is free, or modify the port in firewall.py.

Disclaimers

    Educational Use Only: This firewall is intended for learning and testing purposes. It has not been thoroughly tested for production environments.
    Security Risks: The application stores passwords in plain text (encrypted in users.json). For production use, implement proper password hashing (e.g., with bcrypt).
    No Warranty: The software is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
    Root Privileges: Running as root poses security risks. Use with caution and only in a controlled environment.
    Network Impact: Misconfigured rules or scans may disrupt network traffic. Test in a safe environment first.

License

This project is licensed under the MIT License. See the LICENSE file for details.
