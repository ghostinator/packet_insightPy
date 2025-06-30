#!/usr/bin/env python3
"""
Packet Insight Utilities - Shared functions for PCAP analysis
"""
import json
import os
import time
import logging
from collections import defaultdict
from datetime import datetime
from tqdm import tqdm
import sys
import pyshark
import platform
import subprocess

# Import configuration
from config import PacketInsightConfig

# Create default configuration instance
config = PacketInsightConfig()

# Set up debug mode
debug_mode = False

def get_tshark_path():
    """Get the path to tshark executable"""
    system = platform.system()
    # If running as a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        bundle_dir = sys._MEIPASS
        if system == "Windows":
            tshark_path = os.path.join(bundle_dir, 'tshark', 'tshark.exe')
            if os.path.exists(tshark_path):
                return tshark_path
    
    # For all OS: try to find system tshark
    if system == "Windows":
        # Check common Windows locations
        common_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe"
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Try to find in PATH
        try:
            result = subprocess.run(["where", "tshark"], capture_output=True, text=True, check=True)
            if result.stdout.strip():
                return result.stdout.strip().split('\n')[0]
        except subprocess.SubprocessError:
            pass
    else:  # macOS/Linux
        # Try to find in PATH
        try:
            result = subprocess.run(["which", "tshark"], capture_output=True, text=True, check=True)
            if result.stdout.strip():
                return result.stdout.strip()
        except subprocess.SubprocessError:
            pass
    
    # Default tshark command (let the system find it)
    return "tshark"


def get_active_interfaces():
    """Detect active network interfaces with IP addresses"""
    active_interfaces = []
    system = platform.system()
    
    if system == "Windows":
        try:
            # Get interface list with tshark
            tshark_path = get_tshark_path()
            result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True, check=True)
            interfaces = result.stdout.splitlines()
            
            # Parse tshark output
            for iface in interfaces:
                if " (" in iface and ")" in iface:
                    # Extract interface name from "1. \Device\NPF_{GUID} (Ethernet)"
                    name = iface.split("(", 1)[1].rsplit(")", 1)[0].strip()
                    active_interfaces.append(name)
        except Exception:
            # Fallback to netsh
            result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "Connected" in line and "Dedicated" in line:
                    parts = line.split()
                    if len(parts) > 3:
                        active_interfaces.append(" ".join(parts[3:]))
    else:  # macOS/Linux
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs:
                active_interfaces.append(iface)
    
    return active_interfaces


def set_tshark_path():
    """
    Sets the path to tshark for PyShark in a cross-platform, portable way.
    - On Windows: uses bundled tshark if present, else falls back to system install.
    - On macOS/Linux: uses system tshark.
    """
    system = platform.system()
    # If running as a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        bundle_dir = sys._MEIPASS
        if system == "Windows":
            tshark_path = os.path.join(bundle_dir, 'tshark', 'tshark.exe')
            if os.path.exists(tshark_path):
                pyshark.config.config.set_tshark_path(tshark_path)
                return
        # For macOS/Linux, you could bundle tshark, but it's uncommon.
        # Most users will have tshark installed system-wide.
    # For all OS: try to use system tshark
    # (PyShark does this by default, so no need to set explicitly)
    pass  # Do nothing if not found; PyShark will handle or error

# Call this at the start of your main script
set_tshark_path()

BASELINE_PATH = "network_baselines.json"

def initialize_stats():
    """Initialize statistics dictionary"""
    return {
        'packet_count': 0,
        'total_bytes': 0,
        'start_time': time.time(),
        'start_timestamp': float('inf'),
        'end_timestamp': 0,
        'retransmissions': 0,
        'resets': 0,
        'dns_issues': 0,
        'http_errors': defaultdict(int),
        'tcp_syn_delays': [],
        'udp_jitter': [],
        'top_talkers': defaultdict(int),
        'protocols': defaultdict(int),
        'conversations': defaultdict(int),
        'throughput_samples': [],
        'prev_udp_time': {},
        'malformed_packets': 0,  # Counter for malformed packets
        # TLS stats
        'tls_handshakes': 0,
        'tls_versions': defaultdict(int),
        'tls_cipher_suites': defaultdict(int),
        'tls_alerts': 0,
        'expired_certs': [],
        'self_signed_certs': [],
        # DNS stats
        'dns_queries': defaultdict(int),
        'dns_response_times': [],
        'dns_record_types': defaultdict(int),
        'pending_dns_queries': {},
        # DHCP stats
        'dhcp_servers': defaultdict(int),
        'dhcp_discover': 0,
        'dhcp_offer': 0,
        'dhcp_request': 0,
        'dhcp_ack': 0,
        'dhcp_nak': 0
    }

def update_stats(stats, packet):
    """Update statistics with packet data"""
    stats['packet_count'] += 1
    try:
        current_time = float(packet.sniff_timestamp)
        
        # Update time range
        stats['start_timestamp'] = min(stats['start_timestamp'], current_time)
        stats['end_timestamp'] = max(stats['end_timestamp'], current_time)
        
        # Update packet size
        if hasattr(packet, 'length'):
            packet_size = int(packet.length)
            stats['total_bytes'] += packet_size
            stats['throughput_samples'].append((current_time, packet_size))
        
        # Update protocols
        protocol = packet.transport_layer or packet.highest_layer
        stats['protocols'][protocol] += 1
        
        # IP layer analysis
        if 'IP' in packet:
            src, dst = packet.ip.src, packet.ip.dst
            stats['top_talkers'][src] += 1
            stats['top_talkers'][dst] += 1
            stats['conversations'][(src, dst)] += 1
        
        # TCP diagnostics
        if 'TCP' in packet:
            if hasattr(packet.tcp, 'analysis_retransmission'):
                stats['retransmissions'] += 1
            if 'RST' in str(packet.tcp.flags):
                stats['resets'] += 1
            if 'SYN' in str(packet.tcp.flags) and not hasattr(packet.tcp, 'analysis_acks_frame'):
                stats['tcp_syn_delays'].append(current_time)
        
        # UDP diagnostics
        if 'UDP' in packet:
            flow_key = (packet.ip.src, packet.ip.dst, packet.udp.srcport, packet.udp.dstport)
            if flow_key in stats['prev_udp_time']:
                stats['udp_jitter'].append(current_time - stats['prev_udp_time'][flow_key])
            stats['prev_udp_time'][flow_key] = current_time
        
        # Application layer - HTTP
        if 'HTTP' in packet:
            if hasattr(packet.http, 'response_code'):
                code = packet.http.response_code
                if code.startswith(('4', '5')):
                    stats['http_errors'][code] += 1
        
        # TLS/SSL analysis
        if 'TLS' in packet:
            try:
                # Check for handshake records
                if hasattr(packet.tls, 'record_content_type') and packet.tls.record_content_type == '22':
                    stats['tls_handshakes'] += 1
                    
                    # Extract TLS version and cipher from Server Hello
                    if hasattr(packet.tls, 'handshake_type') and packet.tls.handshake_type == '2': # Server Hello
                        if hasattr(packet.tls, 'handshake_version'):
                            stats['tls_versions'][packet.tls.handshake_version] += 1
                        if hasattr(packet.tls, 'handshake_ciphersuite'):
                            stats['tls_cipher_suites'][packet.tls.handshake_ciphersuite] += 1

                # Check for alerts
                if hasattr(packet.tls, 'record_content_type') and packet.tls.record_content_type == '21':
                    stats['tls_alerts'] += 1

                # Certificate analysis (very basic, needs improvement for real validation)
                if hasattr(packet.tls, 'handshake_certificate'):
                    # This is a simplified check. Real validation is complex.
                    cert_not_after = getattr(packet.tls, 'x509af_utcTime', None)
                    if cert_not_after:
                        try:
                            expire_date = datetime.strptime(cert_not_after, '%y%m%d%H%M%SZ')
                            if expire_date < datetime.now():
                                stats['expired_certs'].append(packet.ip.dst)
                        except ValueError:
                            pass # Ignore parsing errors
                    
                    # Check for self-signed (issuer == subject)
                    issuer = getattr(packet.tls, 'x509af_issuer_rdnSequence', None)
                    subject = getattr(packet.tls, 'x509af_subject_rdnSequence', None)
                    if issuer and subject and issuer == subject:
                        stats['self_signed_certs'].append(packet.ip.dst)

            except (AttributeError, ValueError, KeyError) as e:
                if debug_mode:
                    print(f"Skipping malformed TLS packet: {e}")
                stats['malformed_packets'] += 1
        
        # DNS analysis
        if 'DNS' in packet:
            try:
                # Basic DNS issues tracking
                if packet.dns.flags_response == '0' and not hasattr(packet.dns, 'response_time'):
                    stats['dns_issues'] += 1
                    
                # Track query types and names
                if hasattr(packet.dns, 'qry_name'):
                    stats['dns_queries'][packet.dns.qry_name] += 1
                    stats['dns_record_types'][packet.dns.qry_type] += 1
                    
                    # If it's a query, store its timestamp
                    if packet.dns.flags_response == '0':
                        query_id = packet.dns.id
                        stats['pending_dns_queries'][query_id] = current_time

                # If it's a response, calculate response time
                elif packet.dns.flags_response == '1':
                    query_id = packet.dns.id
                    if query_id in stats['pending_dns_queries']:
                        response_time = current_time - stats['pending_dns_queries'].pop(query_id)
                        stats['dns_response_times'].append(response_time)

            except (AttributeError, ValueError, KeyError) as e:
                if debug_mode:
                    print(f"Skipping malformed DNS packet: {e}")
                stats['malformed_packets'] += 1
        
        # DHCP analysis
        if 'DHCP' in packet or 'BOOTP' in packet:  # DHCP uses BOOTP as its base
            try:
                # Check for DHCP message type
                if hasattr(packet, 'dhcp') and hasattr(packet.dhcp, 'option_dhcp_message_type'):
                    dhcp_type = packet.dhcp.option_dhcp_message_type
                    
                    if dhcp_type == '1':  # Discover
                        stats['dhcp_discover'] += 1
                    elif dhcp_type == '2':  # Offer
                        stats['dhcp_offer'] += 1
                        if 'IP' in packet:
                            stats['dhcp_servers'][packet.ip.src] += 1
                    elif dhcp_type == '3':  # Request
                        stats['dhcp_request'] += 1
                    elif dhcp_type == '5':  # ACK
                        stats['dhcp_ack'] += 1
                    elif dhcp_type == '6':  # NAK
                        stats['dhcp_nak'] += 1
                        
            except (AttributeError, ValueError, KeyError) as e:
                if debug_mode:
                    print(f"Skipping malformed DHCP packet: {e}")
                stats['malformed_packets'] += 1
                    
    except (AttributeError, ValueError, KeyError) as e:
        if debug_mode:
            print(f"Skipping malformed packet: {e}")
        stats['malformed_packets'] += 1

def generate_report(stats):
    """Generate formatted analysis report"""
    # Calculate metrics
    processing_time = time.time() - stats['start_time']
    capture_duration = stats['end_timestamp'] - stats['start_timestamp']
    avg_packet_size = stats['total_bytes'] / stats['packet_count'] if stats['packet_count'] else 0
    throughput = stats['total_bytes'] * 8 / capture_duration if capture_duration > 0 else 0
    
    # Print report header
    print(f"\n[✓] Analysis completed in {processing_time:.2f}s")
    print(f"\n## Network Summary [Packets: {stats['packet_count']} | Duration: {capture_duration:.2f}s]")
    print(f"- Total Data: {stats['total_bytes'] / 1e6:.2f} MB")
    print(f"- Avg Packet Size: {avg_packet_size:.0f} bytes")
    print(f"- Estimated Throughput: {throughput / 1e6:.2f} Mbps")
    if stats['malformed_packets'] > 0:
        print(f"- Malformed Packets: {stats['malformed_packets']} ({stats['malformed_packets']/stats['packet_count']:.1%})")
    
    # Protocol distribution
    print("\n### Protocol Distribution")
    for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"- {proto}: {count} packets ({count/stats['packet_count']:.1%})")
    
    # Top issues
    print("\n### Top Issues")
    print(f"- TCP Retransmissions: {stats['retransmissions']}")
    print(f"- TCP Resets: {stats['resets']}")
    print(f"- DNS Timeouts/Failures: {stats['dns_issues']}")
    
    if stats['http_errors']:
        total_http_errors = sum(stats['http_errors'].values())
        print(f"- HTTP Errors: {total_http_errors} total")
        for code, count in stats['http_errors'].items():
            print(f"  • {code}: {count} errors")
    
    # Connection quality metrics
    if stats['tcp_syn_delays']:
        avg_delay = sum(stats['tcp_syn_delays'])/len(stats['tcp_syn_delays'])
        print(f"- Avg TCP Handshake Delay: {avg_delay:.4f}s")
        if avg_delay > config.get('syn_delay_threshold', 0.5):
            print(f"  ⚠️ WARNING: High SYN delay (>{config.get('syn_delay_threshold', 0.5)}s)")
    
    if stats['udp_jitter']:
        avg_jitter = sum(stats['udp_jitter'])/len(stats['udp_jitter'])
        print(f"- Avg UDP Jitter: {avg_jitter:.4f}s")
        if avg_jitter > config.get('high_jitter_threshold', 0.1):
            print(f"  ⚠️ WARNING: High jitter (>{config.get('high_jitter_threshold', 0.1)}s)")
    
    # Critical warnings
    if stats['retransmissions'] > stats['packet_count'] * config.get('retransmission_threshold', 0.05):
        rate = stats['retransmissions']/stats['packet_count']
        print(f"\n⚠️ CRITICAL: High retransmission rate ({rate:.1%} > {config.get('retransmission_threshold', 0.05):.0%} threshold)")
    
    # TLS/SSL Report
    if stats['tls_handshakes'] > 0:
        print("\n### TLS/SSL Analysis")
        print(f"- Total TLS Handshakes: {stats['tls_handshakes']}")
        print(f"- TLS Alerts: {stats['tls_alerts']}")

        if stats['tls_versions']:
            print("- TLS Versions Detected:")
            version_map = {
                '0x0301': 'TLS 1.0', '0x0302': 'TLS 1.1',
                '0x0303': 'TLS 1.2', '0x0304': 'TLS 1.3'
            }
            for version, count in stats['tls_versions'].items():
                version_name = version_map.get(version, f"Unknown ({version})")
                warning = "⚠️ (Insecure)" if version in ['0x0301', '0x0302'] else ""
                print(f"  • {version_name}: {count} handshakes {warning}")

        if stats['expired_certs']:
            print("  ⚠️ WARNING: Expired Certificates Found:")
            for ip in set(stats['expired_certs']):
                print(f"    - Server: {ip}")
        
        if stats['self_signed_certs']:
            print("  ⚠️ WARNING: Self-Signed Certificates Found:")
            for ip in set(stats['self_signed_certs']):
                print(f"    - Server: {ip}")
    
    # DNS Deep Dive Report
    if stats['dns_queries']:
        print("\n### DNS Analysis")
        
        # Performance
        if stats['dns_response_times']:
            avg_dns_response = sum(stats['dns_response_times']) / len(stats['dns_response_times'])
            max_dns_response = max(stats['dns_response_times'])
            print(f"- Avg DNS Response Time: {avg_dns_response:.4f}s (Max: {max_dns_response:.4f}s)")
            if avg_dns_response > 0.2:
                print("  ⚠️ WARNING: High average DNS response time (>0.2s)")

        # Top Queried Domains
        if stats['dns_queries']:
            print("- Top 5 Queried Domains:")
            sorted_queries = sorted(stats['dns_queries'].items(), key=lambda item: item[1], reverse=True)
            for domain, count in sorted_queries[:5]:
                print(f"  • {domain}: {count} queries")

        # Record Types
        if stats['dns_record_types']:
            print("- Query Types Distribution:")
            record_type_map = {
                '1': 'A (IPv4)', '28': 'AAAA (IPv6)', '5': 'CNAME',
                '15': 'MX', '16': 'TXT', '6': 'SOA', '2': 'NS'
            }
            for record_type, count in stats['dns_record_types'].items():
                type_name = record_type_map.get(record_type, f"Type {record_type}")
                print(f"  • {type_name}: {count} queries")
    
    # DHCP Analysis Report
    if stats['dhcp_discover'] > 0 or stats['dhcp_offer'] > 0:
        print("\n### DHCP Analysis")
        print(f"- DHCP Process: {stats['dhcp_discover']} Discovers, {stats['dhcp_offer']} Offers, "
              f"{stats['dhcp_request']} Requests, {stats['dhcp_ack']} ACKs, {stats['dhcp_nak']} NAKs")
        
        # Success rate
        if stats['dhcp_discover'] > 0:
            success_rate = stats['dhcp_ack'] / stats['dhcp_discover'] if stats['dhcp_discover'] > 0 else 0
            print(f"- DHCP Success Rate: {success_rate:.1%}")
            if success_rate < 0.9 and stats['dhcp_discover'] > 5:
                print("  ⚠️ WARNING: Low DHCP success rate (<90%)")
        
        # Multiple DHCP servers
        if len(stats['dhcp_servers']) > 1:
            print("  ⚠️ WARNING: Multiple DHCP servers detected:")
            for server_ip, count in stats['dhcp_servers'].items():
                print(f"    - {server_ip}: {count} offers")
    
    # Top talkers and conversations
    print("\n### Top 15 Talkers")
    sorted_talkers = sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:15]
    for ip, count in sorted_talkers:
        print(f"- {ip}: {count} packets")
    
    print("\n### Top 5 Conversations")
    sorted_convos = sorted(stats['conversations'].items(), key=lambda x: x[1], reverse=True)[:5]
    for convo, count in sorted_convos:
        if isinstance(convo, str) and "_" in convo:
            # This is a converted tuple key
            parts = convo.split("_")
            if len(parts) >= 2:
                print(f"- {parts[0]} ↔ {parts[1]}: {count} packets")
        elif isinstance(convo, tuple) and len(convo) >= 2:
            print(f"- {convo[0]} ↔ {convo[1]}: {count} packets")
        else:
            print(f"- {convo}: {count} packets")

def analyze_pcap(pcap_path):
    """Analyze a PCAP file to extract and return network statistics."""
    # Verify file exists before processing
    if not os.path.exists(pcap_path):
        print(f"[!] Error: File '{pcap_path}' not found")
        return initialize_stats()  # Return empty stats

    stats = initialize_stats()
    cap = None
    try:
        # Use a simple approach without custom event loop management
        cap = pyshark.FileCapture(
            pcap_path,
            display_filter='tcp || udp || icmp || dns || http || dhcp || bootp || tls',
            only_summaries=False,
            custom_parameters=['-s 128'],
            debug=False,
            keep_packets=False
        )
        
        # Process all packets at once to avoid event loop issues
        all_packets = list(cap)
        
        # Now process the packets from our local list
        for packet in tqdm(all_packets, desc="Processing packets", unit="pkt"):
            update_stats(stats, packet)
            
    except (pyshark.capture.capture.TSharkCrashException, 
            FileNotFoundError, 
            PermissionError) as e:
        print(f"[!] Capture error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        logging.exception("Full traceback:")
    finally:
        # Explicitly close the capture to prevent event loop errors
        if cap:
            try:
                # Monkey patch the close method to avoid event loop issues
                if hasattr(cap, 'close'):
                    # Replace the close method with a no-op
                    def noop(*args, **kwargs):
                        pass
                    cap.close = noop
                
                # Clear the capture object
                cap = None
            except Exception as e:
                if debug_mode:
                    print(f"[!] Error closing capture: {e}")
    
    # Clean up non-serializable data before returning
    # Remove the prev_udp_time dictionary which contains tuple keys
    if 'prev_udp_time' in stats:
        del stats['prev_udp_time']
    
    # Convert conversations dictionary to use string keys
    if 'conversations' in stats:
        conversations = {}
        for k, v in stats['conversations'].items():
            if isinstance(k, tuple):
                new_key = "_".join(str(item) for item in k)
                conversations[new_key] = v
            else:
                conversations[k] = v
        stats['conversations'] = conversations
    
    return stats

def get_baseline_type():
    """Determine baseline type based on current time"""
    now = datetime.now()
    return "workday" if now.weekday() < 5 else "weekend"

def load_baseline():
    """Load baseline data from file"""
    if os.path.exists(BASELINE_PATH):
        with open(BASELINE_PATH, 'r') as f:
            return json.load(f)
    return None

def save_baseline(baseline_data):
    """Save baseline data to file"""
    with open(BASELINE_PATH, 'w') as f:
        json.dump(baseline_data, f, indent=2)

def analyze_pcap_safe(pcap_path):
    """Safe wrapper for analyze_pcap that handles pyshark cleanup"""
    import gc
    
    # Disable the garbage collector temporarily to prevent premature cleanup
    gc.disable()
    
    try:
        # Run the analysis
        result = analyze_pcap(pcap_path)
        
        # Force garbage collection to clean up pyshark objects
        gc.enable()
        gc.collect()
        
        return result
    except Exception as e:
        print(f"Error in analyze_pcap_safe: {e}")
        gc.enable()
        return initialize_stats()
