import json
import threading
import logging
import logging.handlers
import netifaces
import psutil
import socket
import nmap
import subprocess
import shutil
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, sendp
from netfilterqueue import NetfilterQueue
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
from datetime import datetime
import os
import io
import signal
import sys
import ipaddress
from collections import defaultdict

# Setup logging with rotation
logger = logging.getLogger('firewall')
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler('firewall.log', maxBytes=5*1024*1024, backupCount=3)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Flask app
app = Flask(__name__, static_folder='web', template_folder='web')
app.secret_key = os.urandom(24)

# Global variables
rules = []
logs = []
interfaces = {}
aliases = []
blacklist = []
notifications = []
nat_rules = []
scan_results = defaultdict(int)
anomaly_notified = set()
prev_interfaces = set(netifaces.interfaces())
ips_settings = {
    "mode": "IDS",
    "packet_threshold": 5000,
    "auto_block": True,
    "block_duration": 3600
}
blocked_ips = {}
system_stats = {"cpu": 0, "memory": 0}
cached_scan_data = []

# Ensure JSON directory exists
json_dir = 'web'
if not os.path.exists(json_dir):
    os.makedirs(json_dir)

# Load/save JSON files
def load_json(file_path, default_data):
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return default_data
    return default_data

def save_json(file_path, data):
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.debug(f"Saved {file_path}")
    except Exception as e:
        logger.error(f"Error saving {file_path}: {e}")

# Initialize JSON files
def initialize_json_files():
    json_files = {
        'web/users.json': [{"username": "admin", "password": "admin123"}],
        'web/rules.json': [],
        'web/aliases.json': [],
        'web/blacklist.json': [],
        'web/notifications.json': [],
        'web/ips_settings.json': {
            "mode": "IDS",
            "packet_threshold": 5000,
            "auto_block": True,
            "block_duration": 3600
        },
        'web/nat_rules.json': [{"type": "MASQUERADE", "interface": "ens224"}]
    }
    for file_path, default_data in json_files.items():
        if not os.path.exists(file_path):
            save_json(file_path, default_data)
            logger.info(f"Created {file_path} with default data")

# Apply nftables rules
def apply_nftables_rules():
    internal_iface = 'ens160'
    external_iface = 'ens224'
    firewall_nat_ip = '192.168.39.153'
    nft_script = f"""
flush ruleset

table inet firewall {{
    chain input {{
        type filter hook input priority 0; policy drop;
        iifname "{internal_iface}" ip saddr 10.10.10.0/24 tcp dport {{ 22, 5000 }} accept
        ct state established,related accept
        queue num 2
        log prefix "INPUT_DROP: " drop
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        ip saddr 10.10.10.11 ip daddr 10.10.10.140 icmp type echo-request log prefix "ICMP_DROP: " drop
        ip saddr 10.10.10.11 ip daddr 10.10.10.140 icmp type echo-reply log prefix "ICMP_DROP: " drop
        ip saddr 10.10.10.140 ip daddr 10.10.10.11 icmp type echo-request log prefix "ICMP_DROP: " drop
        ip saddr 10.10.10.140 ip daddr 10.10.10.11 icmp type echo-reply log prefix "ICMP_DROP: " drop
        iifname "{internal_iface}" oifname "{external_iface}" ip saddr 10.10.10.0/24 log prefix "FIREWALL: "
        ip saddr 10.10.10.11 ip daddr 8.8.8.8 icmp type echo-request accept
        ip saddr 8.8.8.8 ip daddr 10.10.10.11 icmp type echo-reply accept
        queue num 2
        log prefix "FORWARD_DROP: " drop
    }}
    chain output {{
        type filter hook output priority 0; policy drop;
        icmp type redirect log prefix "ICMP_REDIRECT_DROP: " drop
        oifname "{internal_iface}" tcp sport {{ 22, 5000 }} accept
        oifname "{external_iface}" ip saddr {firewall_nat_ip} icmp type echo-request accept
        oifname "{external_iface}" ip saddr {firewall_nat_ip} udp dport 53 accept
        oifname "{external_iface}" ip saddr {firewall_nat_ip} tcp dport 53 accept
        oifname "{external_iface}" ip saddr {firewall_nat_ip} tcp dport 80 accept
        oifname "{external_iface}" ip saddr {firewall_nat_ip} tcp dport 443 accept
        ct state established,related accept
        queue num 2
        log prefix "OUTPUT_DROP: " drop
    }}
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
        oifname "{external_iface}" masquerade
    }}
}}

table bridge firewall {{
    chain forward {{
        type filter hook forward priority 0; policy drop;
        ip saddr 10.10.10.11 ip daddr 10.10.10.140 icmp type echo-request log prefix "BRIDGE_ICMP_DROP: " drop
        ip saddr 10.10.10.140 ip daddr 10.10.10.11 icmp type echo-request log prefix "BRIDGE_ICMP_DROP: " drop
        ip saddr 10.10.10.11 ip daddr 10.10.10.140 icmp type echo-reply log prefix "BRIDGE_ICMP_DROP: " drop
        ip saddr 10.10.10.140 ip daddr 10.10.10.11 icmp type echo-reply log prefix "BRIDGE_ICMP_DROP: " drop
        accept
        log prefix "BRIDGE_DROP: " drop
    }}
}}
"""
    try:
        with open('/etc/nftables.conf', 'w') as f:
            f.write(nft_script)
        subprocess.run(['nft', '-f', '/etc/nftables.conf'], check=True)
        logger.info(f"Applied nftables rules: default drop, ICMP 10.10.10.11<->10.10.10.140 dropped on {internal_iface}, bridge filtering enabled")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error applying nftables rules: {e}")
        print(f"nftables error: {e}", file=sys.stderr)
        # Fallback: Allow basic connectivity
        os.system("nft flush ruleset")
        os.system(f"nft add table inet firewall")
        os.system(f"nft add chain inet firewall input {{ type filter hook input priority 0 \\; policy accept \\; }}")
        os.system(f"nft add chain inet firewall forward {{ type filter hook forward priority 0 \\; policy accept \\; }}")
        os.system(f"nft add chain inet firewall output {{ type filter hook output priority 0 \\; policy accept \\; }}")
        logger.warning("Applied fallback nftables rules (accept all)")

# Disable Proxy ARP and ICMP redirects
def disable_proxy_arp_and_redirects():
    internal_iface = 'ens160'
    try:
        # Disable Proxy ARP
        os.system("echo 0 > /proc/sys/net/ipv4/conf/all/proxy_arp")
        os.system(f"echo 0 > /proc/sys/net/ipv4/conf/{internal_iface}/proxy_arp")
        logger.info(f"Disabled Proxy ARP on all interfaces and {internal_iface}")
        
        # Disable ICMP redirects
        os.system("echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects")
        os.system(f"echo 0 > /proc/sys/net/ipv4/conf/{internal_iface}/send_redirects")
        logger.info(f"Disabled ICMP redirects on all interfaces and {internal_iface}")
    except Exception as e:
        logger.error(f"Error disabling Proxy ARP or ICMP redirects: {e}")

# ARP spoofing to force traffic through firewall
def arp_spoof():
    internal_iface = 'ens160'
    client1_ip = '10.10.10.11'
    client2_ip = '10.10.10.140'
    firewall_mac = '00:0C:29:FB:65:05'  # From previous arp -a output
    client1_mac = '00:0C:29:E0:7F:78'  # MAC address of 10.10.10.11
    client2_mac = '00:0C:29:23:8F:A6'  # MAC address of 10.10.10.140
    try:
        # Spoof client1 to think client2's MAC is firewall's MAC
        packet1 = Ether(dst=client1_mac, src=firewall_mac) / ARP(
            op=2, psrc=client2_ip, pdst=client1_ip, hwdst=client1_mac, hwsrc=firewall_mac
        )
        # Spoof client2 to think client1's MAC is firewall's MAC
        packet2 = Ether(dst=client2_mac, src=firewall_mac) / ARP(
            op=2, psrc=client1_ip, pdst=client2_ip, hwdst=client2_mac, hwsrc=firewall_mac
        )
        # Send ARP packets more frequently to ensure immediate effect
        for _ in range(5):  # Send 5 times initially to ensure cache update
            sendp(packet1, iface=internal_iface, verbose=False)
            sendp(packet2, iface=internal_iface, verbose=False)
            logger.debug(f"Sent ARP spoof packets to {client1_ip} (MAC: {client1_mac}) and {client2_ip} (MAC: {client2_mac})")
            threading.Event().wait(0.5)  # Reduced interval for initial burst
        # Continue sending periodically
        while True:
            sendp(packet1, iface=internal_iface, verbose=False)
            sendp(packet2, iface=internal_iface, verbose=False)
            logger.debug(f"Sent ARP spoof packets to {client1_ip} (MAC: {client1_mac}) and {client2_ip} (MAC: {client2_mac})")
            threading.Event().wait(2)  # Send every 2 seconds
    except Exception as e:
        logger.error(f"ARP spoofing error: {e}")
        notifications.append({"time": str(datetime.now()), "message": f"ARP spoofing failed: {e}. Consider subnet separation."})
        save_json('web/notifications.json', notifications)

# Start Flask in a separate thread
def start_flask():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', 5000))
        s.close()
        logger.info("Port 5000 is available, starting Flask")
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except socket.error as e:
        logger.error(f"Port 5000 is in use: {e}")
        print(f"Error: Port 5000 is in use. Please free the port and try again.", file=sys.stderr)

# Initial data
initialize_json_files()
users = load_json('web/users.json', [{"username": "root", "password": "root@123"}])
rules = load_json('web/rules.json', [])
aliases = load_json('web/aliases.json', [])
blacklist = load_json('web/blacklist.json', [])
notifications = load_json('web/notifications.json', [])
ips_settings = load_json('web/ips_settings.json', ips_settings)
nat_rules = load_json('web/nat_rules.json', [{"type": "MASQUERADE", "interface": "ens224"}])
logger.info(f"Loaded rules: {rules}")
logger.info(f"Loaded users: {users}")
logger.info(f"Loaded aliases: {aliases}")

# Serve static files
@app.route('/<filename>')
def serve_static(filename):
    if filename in ['style.css', 'script.js']:
        return app.send_static_file(filename)
    return app.send_from_directory(app.template_folder, 'login.html')

# Protocol to port mapping
PROTOCOL_PORTS = {
    "ICMP": None,
    "TCP": None,
    "UDP": None,
    "HTTP": 80,
    "HTTPS": 443,
    "FTP": [20, 21],
    "SSH": 22,
    "TELNET": 23,
    "SMTP": 25,
    "DNS": 53,
    "POP3": 110,
    "IMAP": 143,
    "RDP": 3389,
    "MYSQL": 3306,
    "POSTGRESQL": 5432,
    "SNMP": [161, 162],
    "LDAP": 389,
    "LDAPS": 636,
    "NTP": 123,
    "SIP": [5060, 5061],
    "TFTP": 69
}

# Reset anomaly counts
def reset_anomaly_counts():
    global scan_results
    scan_results.clear()
    logger.info("Reset anomaly packet counts")
    threading.Timer(60, reset_anomaly_counts).start()

# Helper function to check if an IP belongs to a network (CIDR)
def ip_in_network(ip, network):
    try:
        ip_addr = ipaddress.ip_address(ip)
        ip_net = ipaddress.ip_network(network, strict=False)
        return ip_addr in ip_net
    except ValueError as e:
        logger.error(f"Invalid IP or network format - IP: {ip}, Network: {network}, Error: {e}")
        return False

# Helper function to check if an IP matches an alias entry (specific IP or CIDR)
def ip_matches_alias_entry(ip, entry):
    if '/' in entry:  # CIDR notation
        return ip_in_network(ip, entry)
    else:  # Specific IP
        return ip == entry

# Packet handling
def packet_handler(pkt):
    try:
        packet = IP(pkt.get_payload())
        ip_src = packet.src
        ip_dst = packet.dst
        proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(packet.proto, str(packet.proto))
        port_src = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else None
        port_dst = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else None

        logger.debug(f"Processing packet: {ip_src}:{port_src or '-'} -> {ip_dst}:{port_dst or '-'} [{proto}]")

        # Ignore localhost traffic
        if ip_src.startswith('127.') or ip_dst.startswith('127.'):
            logger.debug(f"Skipping localhost packet: {ip_src}:{port_src or '-'} -> {ip_dst}:{port_dst or '-'} [{proto}]")
            pkt.accept()
            return

        # Blacklist check
        for entry in blacklist:
            if entry["ip"] in [ip_src, ip_dst]:
                pkt.drop()
                log_entry = f"BLACKLISTED {ip_src}:{port_src or '-'} -> {ip_dst}:{port_dst or '-'} [{proto}] - DROP (Reason: {entry['reason']})"
                logs.append({"time": str(datetime.now()), "entry": log_entry})
                logger.info(log_entry)
                return

        # Check temporary blocks
        current_time = datetime.now().timestamp()
        if ip_src in blocked_ips:
            if blocked_ips[ip_src]["expiry"] > current_time:
                pkt.drop()
                log_entry = f"TEMP BLOCKED {ip_src}:{port_src or '-'} -> {ip_dst}:{port_dst or '-'} [{proto}] - DROP (Reason: {blocked_ips[ip_src]['reason']})"
                logs.append({"time": str(datetime.now()), "entry": log_entry})
                logger.info(log_entry)
                return
            else:
                del blocked_ips[ip_src]

        # Anomaly detection
        scan_results[ip_src] += 1
        logger.debug(f"Packet count for {ip_src}: {scan_results[ip_src]}")
        if scan_results[ip_src] > ips_settings["packet_threshold"] and ip_src not in anomaly_notified:
            log_entry = f"ANOMALY DETECTED {ip_src} - High packet rate (Threshold: {ips_settings['packet_threshold']})"
            logs.append({"time": str(datetime.now()), "entry": log_entry})
            notifications.append({"time": str(datetime.now()), "message": log_entry})
            anomaly_notified.add(ip_src)
            if ips_settings["mode"] == "IPS" and ips_settings["auto_block"]:
                expiry = current_time + ips_settings["block_duration"]
                blocked_ips[ip_src] = {"expiry": expiry, "reason": "High packet rate"}
                notifications.append({"time": str(datetime.now()), "message": f"IP {ip_src} auto-blocked for {ips_settings['block_duration']} seconds"})
                save_json('web/notifications.json', notifications)
                logger.info(log_entry)

        # Rule-based filtering
        action = "DROP"  # Default to DROP if no rule matches
        for rule in rules:
            logger.debug(f"Evaluating rule: {rule}")

            # Source IP matching
            src_match = False
            rule_src_ip = rule.get("src_ip")
            if rule_src_ip is None:  # 'any'
                src_match = True
                logger.debug(f"Source IP match: 'any'")
            elif '/' in str(rule_src_ip):  # CIDR notation (e.g., 10.10.10.0/24)
                src_match = ip_in_network(ip_src, rule_src_ip)
                logger.debug(f"Source IP CIDR match: {ip_src} in {rule_src_ip} -> {src_match}")
            elif any(rule_src_ip == alias["name"] for alias in aliases):  # Alias
                matching_aliases = [alias for alias in aliases if alias["name"] == rule_src_ip]
                for alias in matching_aliases:
                    src_match = any(ip_matches_alias_entry(ip_src, entry) for entry in alias["entries"])
                    logger.debug(f"Source IP alias match: {ip_src} in alias {alias['name']} entries {alias['entries']} -> {src_match}")
                    if src_match:
                        break
            else:  # Specific IP
                src_match = rule_src_ip == ip_src
                logger.debug(f"Source IP specific match: {ip_src} == {rule_src_ip} -> {src_match}")

            # Destination IP matching
            dst_match = False
            rule_dst_ip = rule.get("dst_ip")
            if rule_dst_ip is None:  # 'any'
                dst_match = True
                logger.debug(f"Destination IP match: 'any'")
            elif '/' in str(rule_dst_ip):  # CIDR notation (e.g., 0.0.0.0/0)
                dst_match = ip_in_network(ip_dst, rule_dst_ip)
                logger.debug(f"Destination IP CIDR match: {ip_dst} in {rule_dst_ip} -> {dst_match}")
            elif any(rule_dst_ip == alias["name"] for alias in aliases):  # Alias
                matching_aliases = [alias for alias in aliases if alias["name"] == rule_dst_ip]
                for alias in matching_aliases:
                    dst_match = any(ip_matches_alias_entry(ip_dst, entry) for entry in alias["entries"])
                    logger.debug(f"Destination IP alias match: {ip_dst} in alias {alias['name']} entries {alias['entries']} -> {dst_match}")
                    if dst_match:
                        break
            else:  # Specific IP
                dst_match = rule_dst_ip == ip_dst
                logger.debug(f"Destination IP specific match: {ip_dst} == {rule_dst_ip} -> {dst_match}")

            # Protocol matching
            proto_match = False
            rule_proto = rule.get("proto")
            if rule_proto in ["TCP", "UDP", "ICMP"]:
                proto_match = rule_proto == proto
            elif rule_proto in PROTOCOL_PORTS:
                base_proto = "TCP" if rule_proto not in ["SNMP", "NTP", "SIP", "TFTP", "DNS"] else "UDP"
                if rule_proto == "DNS":
                    base_proto = proto
                proto_match = proto == base_proto
            else:
                proto_match = True
            logger.debug(f"Protocol match: {proto} == {rule_proto} -> {proto_match}")

            # Port matching
            src_port_match = False
            dst_port_match = False
            if proto == "ICMP":
                src_port_match = rule.get("src_port") is None
                dst_port_match = rule.get("dst_port") is None
            else:
                if rule.get("src_port"):
                    src_port_match = port_src == rule["src_port"]
                else:
                    src_port_match = True
                if rule.get("dst_port"):
                    if isinstance(PROTOCOL_PORTS.get(rule_proto), list):
                        dst_port_match = port_dst in PROTOCOL_PORTS[rule_proto]
                    else:
                        dst_port_match = port_dst == rule["dst_port"] or port_dst == PROTOCOL_PORTS.get(rule_proto)
                else:
                    dst_port_match = True
            logger.debug(f"Port match: src {port_src} == {rule.get('src_port')} -> {src_port_match}, dst {port_dst} == {rule.get('dst_port')} -> {dst_port_match}")

            if src_match and dst_match and proto_match and src_port_match and dst_port_match:
                logger.debug(f"Rule match: {rule}, Action: {rule['action']}")
                action = rule["action"]
                break
            else:
                logger.debug(f"Rule did not match: src_match={src_match}, dst_match={dst_match}, proto_match={proto_match}, src_port_match={src_port_match}, dst_port_match={dst_port_match}")

        log_entry = f"{ip_src}:{port_src or '-'} -> {ip_dst}:{port_dst or '-'} [{proto}] - {action}"
        logs.append({"time": str(datetime.now()), "entry": log_entry})
        logger.info(log_entry)
        if len(logs) > 1000:
            logs.pop(0)

        if action == "DROP":
            pkt.drop()
        else:
            pkt.accept()
    except Exception as e:
        logger.error(f"Packet handling error: {e}")
        pkt.accept()

# Start packet filtering
def start_filtering():
    try:
        nfqueue = NetfilterQueue()
        logger.info("Attempting to bind to queue 2")
        nfqueue.bind(2, packet_handler)
        logger.info("Successfully bound to queue 2")
        print("NetfilterQueue running on queue 2...")
        nfqueue.run()
    except Exception as e:
        logger.error(f"Failed to start netfilterqueue: {e}")
        print(f"NetfilterQueue error: {e}", file=sys.stderr)

# Update network interfaces
def update_interfaces():
    global interfaces, prev_interfaces
    interfaces = {}
    try:
        io_counters = psutil.net_io_counters(pernic=True)
        current_interfaces = set(netifaces.interfaces())
        new_interfaces = current_interfaces - prev_interfaces
        if new_interfaces:
            for iface in new_interfaces:
                notifications.append({"time": str(datetime.now()), "message": f"New adapter detected: {iface}"})
                save_json('web/notifications.json', notifications)
            prev_interfaces = current_interfaces
        for iface in current_interfaces:
            addrs = netifaces.ifaddresses(iface)
            ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'N/A')
            stats = io_counters.get(iface, None)
            if stats:
                interfaces[iface] = {
                    "ip": ip,
                    "sent": stats.bytes_sent,
                    "recv": stats.bytes_recv,
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv
                }
    except Exception as e:
        logger.error(f"Error updating interfaces: {e}")

# System stats update
def update_system_stats():
    try:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        memory_usage = psutil.virtual_memory().percent
        system_stats["cpu"] = float(cpu_usage)
        system_stats["memory"] = float(memory_usage)
        logger.debug(f"System stats updated: CPU={cpu_usage}%, Memory={memory_usage}%")
    except Exception as e:
        logger.error(f"Error updating system stats: {e}")
        system_stats["cpu"] = 0.0
        system_stats["memory"] = 0.0

# Check nmap availability
def check_nmap():
    if not shutil.which('nmap'):
        error_msg = "nmap not installed. Install with 'sudo dnf install nmap'"
        logger.error(error_msg)
        return False, error_msg
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        logger.info(f"nmap version: {result.stdout.strip()}")
        return True, ""
    except Exception as e:
        error_msg = f"nmap check failed: {e}"
        logger.error(error_msg)
        return False, error_msg

# Network scan
def network_scan(network='10.10.10.0/24', port_range='1-1000'):
    global cached_scan_data
    nmap_ok, nmap_error = check_nmap()
    if not nmap_ok:
        notifications.append({"time": str(datetime.now()), "message": nmap_error})
        save_json('web/notifications.json', notifications)
        return []

    try:
        nm = nmap.PortScanner()
        logger.info(f"Starting network scan on {network} with ports {port_range}")
        scan_args = f'-sS -p {port_range} --privileged' if os.geteuid() == 0 else f'-sn -p {port_range}'
        nm.scan(hosts=network, arguments=scan_args)
        scan_data = []
        for host in nm.all_hosts():
            ports = []
            for proto in nm[host].all_protocols():
                ports.extend(nm[host][proto].keys())
            scan_data.append({
                "host": host,
                "state": nm[host].state(),
                "ports": ports,
                "hostname": nm[host].hostname() or 'Unknown'
            })
        logger.info(f"Network scan completed for {network}, found {len(scan_data)} hosts: {scan_data}")
        notifications.append({"time": str(datetime.now()), "message": f"Network scan completed for {network}: {len(scan_data)} hosts found"})
        save_json('web/notifications.json', notifications)
        cached_scan_data = scan_data
        return scan_data
    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan error: {e}")
        notifications.append({"time": str(datetime.now()), "message": f"Network scan failed: {e} (Check nmap permissions)"})
        save_json('web/notifications.json', notifications)
        return []
    except Exception as e:
        logger.error(f"Network scan failed: {e}")
        notifications.append({"time": str(datetime.now()), "message": f"Network scan failed: {e}"})
        save_json('web/notifications.json', notifications)
        return []

# Get connected clients via ARP table
def get_connected_clients():
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        clients = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and '(' in line:
                ip = parts[1].strip('()')
                mac = parts[3]
                iface = parts[-1] if parts[-1] in netifaces.interfaces() else 'unknown'
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = 'Unknown'
                clients.append({
                    "ip": ip,
                    "mac": mac,
                    "interface": iface,
                    "hostname": hostname
                })
        logger.info(f"Found {len(clients)} connected clients")
        return clients
    except Exception as e:
        logger.error(f"Error fetching connected clients: {e}")
        return []

# Cleanup nftables
def cleanup_nftables(signum, frame):
    os.system("nft flush ruleset")
    logger.info("Cleaned up nftables ruleset")
    sys.exit(0)

# NAT rule application
def apply_nat_rules():
    try:
        for rule in nat_rules:
            if rule["type"] == "MASQUERADE":
                cmd = f'nft add rule inet firewall postrouting oifname "{rule["interface"]}" masquerade'
            elif rule["type"] == "SNAT":
                cmd = f'nft add rule inet firewall postrouting oifname "{rule["interface"]}" snat to {rule["source_ip"]}'
            elif rule["type"] == "PAT":
                cmd = f'nft add rule inet firewall prerouting iifname "{rule["interface"]}" {rule["proto"]} dport {rule["orig_port"]} dnat to {rule["dest_ip"]}:{rule["dest_port"]}'
            subprocess.run(cmd, shell=True, check=True)
            logger.info(f"Applied NAT rule: {cmd}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error applying NAT rule {rule}: {e}")
        notifications.append({"time": str(datetime.now()), "message": f"Failed to apply NAT rule: {e}"})

@app.route('/')
@app.route('/login')
def login_page():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    logger.debug(f"Login attempt: username={username}, password={password}")
    for user in users:
        if user['username'] == username and user['password'] == password:
            session['username'] = username
            logger.info(f"Login successful for {username}")
            return redirect(url_for('dashboard'))
    logger.warning(f"Login failed for {username}")
    return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    logger.info("User logged out")
    return redirect(url_for('login_page'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        logger.warning("Unauthorized dashboard access attempt")
        return redirect(url_for('login_page'))
    update_interfaces()
    update_system_stats()
    return render_template('dashboard.html', username=session['username'], interfaces=interfaces, system_stats=system_stats, recent_logs=logs[-5:])

@app.route('/logs')
def get_logs():
    return jsonify(logs)

@app.route('/export_logs')
def export_logs():
    log_str = "\n".join([f"{log['time']} - {log['entry']}" for log in logs])
    return send_file(io.BytesIO(log_str.encode()), as_attachment=True, download_name="firewall_logs.txt")

@app.route('/rules')
def get_rules():
    return jsonify(rules)

@app.route('/add_rule', methods=['POST'])
def add_rule():
    data = request.json
    proto = data['proto']
    src_port = data['src_port'] if data['src_port'] not in ["", "any"] else None
    dst_port = data['dst_port'] if data['dst_port'] not in ["", "any"] else None

    if proto == "ICMP" and (src_port or dst_port):
        return jsonify({"status": "error", "message": "ICMP rules cannot specify ports"})

    if proto in PROTOCOL_PORTS and PROTOCOL_PORTS[proto]:
        if dst_port and isinstance(PROTOCOL_PORTS[proto], list):
            if int(dst_port) not in PROTOCOL_PORTS[proto]:
                return jsonify({"status": "error", "message": f"Destination port {dst_port} invalid for {proto}"})
        elif dst_port and PROTOCOL_PORTS[proto] and int(dst_port) != PROTOCOL_PORTS[proto]:
            return jsonify({"status": "error", "message": f"Destination port {dst_port} invalid for {proto}"})

    new_rule = {
        "src_ip": data['src_ip'] if data['src_ip'] != "" else None,
        "dst_ip": data['dst_ip'] if data['dst_ip'] != "" else None,
        "proto": proto if proto != "any" else None,
        "src_port": int(src_port) if src_port else None,
        "dst_port": int(dst_port) if dst_port else None,
        "action": data['action']
    }
    rules.append(new_rule)
    save_json('web/rules.json', rules)
    logger.info(f"Added rule: {new_rule}")
    return jsonify({"status": "success"})

@app.route('/edit_rule', methods=['POST'])
def edit_rule():
    data = request.json
    index = data['index']
    proto = data['proto']
    src_port = data['src_port'] if data['src_port'] not in ["", "any"] else None
    dst_port = data['dst_port'] if data['dst_port'] not in ["", "any"] else None

    if proto == "ICMP" and (src_port or dst_port):
        return jsonify({"status": "error", "message": "ICMP rules cannot specify ports"})

    if proto in PROTOCOL_PORTS and PROTOCOL_PORTS[proto]:
        if dst_port and isinstance(PROTOCOL_PORTS[proto], list):
            if int(dst_port) not in PROTOCOL_PORTS[proto]:
                return jsonify({"status": "error", "message": f"Destination port {dst_port} invalid for {proto}"})
        elif dst_port and PROTOCOL_PORTS[proto] and int(dst_port) != PROTOCOL_PORTS[proto]:
            return jsonify({"status": "error", "message": f"Destination port {dst_port} invalid for {proto}"})

    try:
        rules[index] = {
            "src_ip": data['src_ip'] if data['src_ip'] != "" else None,
            "dst_ip": data['dst_ip'] if data['dst_ip'] != "" else None,
            "proto": proto if proto != "any" else None,
            "src_port": int(src_port) if src_port else None,
            "dst_port": int(dst_port) if dst_port else None,
            "action": data['action']
        }
        save_json('web/rules.json', rules)
        logger.info(f"Edited rule at index {index}: {rules[index]}")
        return jsonify({"status": "success"})
    except IndexError:
        return jsonify({"status": "error", "message": "Invalid rule index"})

@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    data = request.json
    index = data['index']
    try:
        deleted_rule = rules.pop(index)
        save_json('web/rules.json', rules)
        logger.info(f"Deleted rule at index {index}: {deleted_rule}")
        return jsonify({"status": "success"})
    except IndexError:
        return jsonify({"status": "error", "message": "Invalid rule index"})

@app.route('/update_rule_order', methods=['POST'])
def update_rule_order():
    global rules
    new_order = request.json['order']
    try:
        rules = [rules[i] for i in new_order]
        save_json('web/rules.json', rules)
        logger.info(f"Updated rule order: {rules}")
        return jsonify({"status": "success"})
    except:
        return jsonify({"status": "error", "message": "Invalid rule order"})

@app.route('/move_rule', methods=['POST'])
def move_rule():
    global rules
    data = request.json
    index = data['index']
    direction = data['direction']
    try:
        if direction == 'up' and index > 0:
            rules[index], rules[index-1] = rules[index-1], rules[index]
        elif direction == 'down' and index < len(rules)-1:
            rules[index], rules[index+1] = rules[index+1], rules[index]
        else:
            return jsonify({"status": "error", "message": "Cannot move rule"})
        save_json('web/rules.json', rules)
        logger.info(f"Moved rule at index {index} {direction}: {rules}")
        return jsonify({"status": "success"})
    except IndexError:
        return jsonify({"status": "error", "message": "Invalid rule index"})

@app.route('/nat_rules', methods=['GET', 'POST'])
def manage_nat_rules():
    global nat_rules
    if request.method == 'POST':
        data = request.json
        new_rule = {
            "type": data['type'],
            "interface": data['interface'],
            "proto": data.get('proto', None),
            "orig_port": int(data.get('orig_port', 0)) or None,
            "dest_ip": data.get('dest_ip', None),
            "dest_port": int(data.get('dest_port', 0)) or None,
            "source_ip": data.get('source_ip', None)
        }
        nat_rules.append(new_rule)
        save_json('web/nat_rules.json', nat_rules)
        apply_nat_rules()
        return jsonify({"status": "success"})
    return jsonify(nat_rules)

@app.route('/delete_nat_rule', methods=['POST'])
def delete_nat_rule():
    data = request.json
    index = data['index']
    try:
        nat_rules.pop(index)
        save_json('web/nat_rules.json', nat_rules)
        apply_nat_rules()
        return jsonify({"status": "success"})
    except IndexError:
        return jsonify({"status": "error", "message": "Invalid NAT rule index"})

@app.route('/users')
def get_users():
    return jsonify(users)

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    new_user = {"username": data['username'], "password": data['password']}
    users.append(new_user)
    save_json('web/users.json', users)
    return jsonify({"status": "success"})

@app.route('/delete_user', methods=['POST'])
def delete_user():
    data = request.json
    global users
    users = [u for u in users if u['username'] != data['username']]
    save_json('web/users.json', users)
    return jsonify({"status": "success"})

@app.route('/modify_user', methods=['POST'])
def modify_user():
    data = request.json
    for user in users:
        if user['username'] == data['username']:
            user['password'] = data['new_password']
            break
    save_json('web/users.json', users)
    return jsonify({"status": "success"})

@app.route('/aliases')
def get_aliases():
    return jsonify(aliases)

@app.route('/add_alias', methods=['POST'])
def add_alias():
    data = request.json
    entries = data['entries'].split(',')
    # Validate entries
    validated_entries = []
    for entry in entries:
        entry = entry.strip()
        if '/' in entry:  # CIDR
            try:
                ipaddress.ip_network(entry, strict=False)
                validated_entries.append(entry)
            except ValueError:
                logger.error(f"Invalid CIDR in alias entry: {entry}")
                return jsonify({"status": "error", "message": f"Invalid CIDR format: {entry}"})
        else:  # Specific IP
            try:
                ipaddress.ip_address(entry)
                validated_entries.append(entry)
            except ValueError:
                logger.error(f"Invalid IP in alias entry: {entry}")
                return jsonify({"status": "error", "message": f"Invalid IP format: {entry}"})
    aliases.append({
        "name": data['name'],
        "description": data['description'],
        "entries": validated_entries
    })
    save_json('web/aliases.json', aliases)
    logger.info(f"Added alias: {data['name']} with entries {validated_entries}")
    return jsonify({"status": "success"})

@app.route('/delete_alias', methods=['POST'])
def delete_alias():
    data = request.json
    index = data['index']
    try:
        deleted_alias = aliases.pop(index)
        save_json('web/aliases.json', aliases)
        logger.info(f"Deleted alias: {deleted_alias}")
        return jsonify({"status": "success"})
    except IndexError:
        return jsonify({"status": "error", "message": "Invalid alias index"})

@app.route('/edit_alias', methods=['POST'])
def edit_alias():
    data = request.json
    index = data['index']
    entries = data['entries'].split(', ')
    # Validate entries
    validated_entries = []
    for entry in entries:
        entry = entry.strip()
        if '/' in entry:  # CIDR
            try:
                ipaddress.ip_network(entry, strict=False)
                validated_entries.append(entry)
            except ValueError:
                logger.error(f"Invalid CIDR in alias entry: {entry}")
                return jsonify({"status": "error", "message": f"Invalid CIDR format: {entry}"})
        else:  # Specific IP
            try:
                ipaddress.ip_address(entry)
                validated_entries.append(entry)
            except ValueError:
                logger.error(f"Invalid IP in alias entry: {entry}")
                return jsonify({"status": "error", "message": f"Invalid IP format: {entry}"})
    try:
        aliases[index] = {
            "name": data['name'],
            "description": data['description'],
            "entries": validated_entries
        }
        save_json('web/aliases.json', aliases)
        logger.info(f"Edited alias at index {index}: {aliases[index]}")
        return jsonify({"status": "success"})
    except IndexError:
        return jsonify({"status": "error", "message": "Invalid alias index"})

@app.route('/upload_aliases', methods=['POST'])
def upload_aliases():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"}, 400)
    file = request.files['file']
    name = request.form.get('name', 'Uploaded Alias')
    description = request.form.get('description', 'Uploaded from file')
    entries = file.read().decode().splitlines()
    # Validate entries
    validated_entries = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if '/' in entry:
            try:
                ipaddress.ip_network(entry, strict=False)
                validated_entries.append(entry)
            except ValueError:
                logger.error(f"Invalid CIDR in uploaded alias entry: {entry}")
                return jsonify({"status": "error", "message": f"Invalid CIDR format: {entry}"})
        else:
            try:
                ipaddress.ip_address(entry)
                validated_entries.append(entry)
            except ValueError:
                logger.error(f"Invalid IP in uploaded alias entry: {entry}")
                return jsonify({"status": "error", "message": f"Invalid IP format: {entry}"})
    aliases.append({"name": name, "description": description, "entries": validated_entries})
    save_json('web/aliases.json', aliases)
    logger.info(f"Uploaded alias: {name} with entries {validated_entries}")
    return jsonify({"status": "success"})

@app.route('/blacklist')
def get_blacklist():
    current_time = datetime.now().timestamp()
    temp_blocks = [
        {"ip": ip, "reason": info["reason"], "added": str(datetime.fromtimestamp(info["expiry"])), "temporary": True}
        for ip, info in blocked_ips.items() if info["expiry"] > current_time
    ]
    return jsonify(blacklist + temp_blocks)

@app.route('/add_to_blacklist', methods=['POST'])
def add_to_blacklist():
    data = request.json
    ip = data['ip']
    reason = data.get('reason', 'Manual block')
    for entry in blacklist:
        if entry['ip'] == ip:
            return jsonify({"status": "success"})
    blacklist.append({"ip": ip, "reason": reason, "added": str(datetime.now())})
    save_json('web/blacklist.json', blacklist)
    notifications.append({"time": str(datetime.now()), "message": f"IP {ip} added to blacklist"})
    save_json('web/notifications.json', notifications)
    return jsonify({"status": "success"})

@app.route('/edit_blacklist', methods=['POST'])
def edit_blacklist():
    data = request.json
    ip = data['ip']
    new_reason = data['reason']
    for entry in blacklist:
        if entry['ip'] == ip:
            entry['reason'] = new_reason
            break
    save_json('web/blacklist.json', blacklist)
    return jsonify({"status": "success"})

@app.route('/remove_from_blacklist', methods=['POST'])
def remove_from_blacklist():
    data = request.json
    ip = data['ip']
    global blacklist, blocked_ips
    blacklist = [entry for entry in blacklist if entry['ip'] != ip]
    if ip in blocked_ips:
        del blocked_ips[ip]
    save_json('web/blacklist.json', blacklist)
    notifications.append({"time": str(datetime.now()), "message": f"IP {ip} removed from blacklist"})
    save_json('web/notifications.json', notifications)
    return jsonify({"status": "success"})

@app.route('/notifications')
def get_notifications():
    return jsonify(notifications)

@app.route('/clear_notifications', methods=['POST'])
def clear_notifications():
    global notifications, anomaly_notified
    notifications = []
    anomaly_notified.clear()
    save_json('web/notifications.json', notifications)
    return jsonify({"status": "success"})

@app.route('/ips_settings', methods=['GET', 'POST'])
def manage_ips_settings():
    global ips_settings
    if request.method == 'POST':
        data = request.json
        ips_settings = {
            "mode": data.get('mode', 'IDS'),
            "packet_threshold": int(data.get('packet_threshold', 5000)),
            "auto_block": data.get('auto_block', True) == True,
            "block_duration": int(data.get('block_duration', 3600))
        }
        save_json('web/ips_settings.json', ips_settings)
        return jsonify({"status": "success"})
    return jsonify(ips_settings)

@app.route('/clients')
def get_clients():
    clients = get_connected_clients()
    return jsonify(clients)

@app.route('/interfaces')
def get_interfaces():
    update_interfaces()
    return jsonify(interfaces)

@app.route('/system_stats')
def get_system_stats():
    update_system_stats()
    return jsonify(system_stats)

@app.route('/scan', methods=['GET', 'POST'])
def get_scan():
    global cached_scan_data
    if request.method == 'POST':
        network = request.json.get('network', '10.10.10.0/24')
        port_range = request.json.get('port_range', '1-1000')
        logger.info(f"Explicit scan requested: {network}, ports {port_range}")
        scan_data = network_scan(network, port_range)
        return jsonify({"status": "success" if scan_data else "error", "scan_results": scan_data, "anomalies": dict(scan_results)})
    else:
        logger.debug("Returning cached scan results for GET request")
        return jsonify({"status": "success" if cached_scan_data else "error", "scan_results": cached_scan_data, "anomalies": dict(scan_results)})

if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup_nftables)
    signal.signal(signal.SIGTERM, cleanup_nftables)
    os.system("nft flush ruleset")
    os.system("iptables -F")
    os.system("iptables -t nat -F")
    # Disable firewalld to avoid conflicts
    os.system("systemctl stop firewalld")
    os.system("systemctl disable firewalld")
    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    disable_proxy_arp_and_redirects()
    apply_nftables_rules()
    # Clear ARP caches on clients (if accessible)
    try:
        subprocess.run(['ip', 'neigh', 'flush', '10.10.10.11'], check=True)
        subprocess.run(['ip', 'neigh', 'flush', '10.10.10.140'], check=True)
        logger.info("Flushed ARP caches for 10.10.10.11 and 10.10.10.140")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to flush ARP caches: {e}. You may need to clear ARP caches manually on the clients.")
    # Start ARP spoofing in a separate thread
    arp_thread = threading.Thread(target=arp_spoof, daemon=True)
    arp_thread.start()
    # Start NetfilterQueue in a separate thread
    filter_thread = threading.Thread(target=start_filtering, daemon=True)
    filter_thread.start()
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    reset_anomaly_counts()
    # Keep the main thread alive
    try:
        while True:
            threading.Event().wait(60)
    except KeyboardInterrupt:
        cleanup_nftables(None, None)
