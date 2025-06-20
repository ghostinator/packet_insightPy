#!/usr/bin/env python3
"""
Packet Insight Utilities - Shared functions for PCAP analysis
"""
import json
import os
import time
from collections import defaultdict
from datetime import datetime
from tqdm import tqdm
import sys
import pyshark
import platform

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
        'prev_udp_time': {}
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
        
        # Application layer
        if 'DNS' in packet:
            if packet.dns.flags_response == '0' and not hasattr(packet.dns, 'response_time'):
                stats['dns_issues'] += 1
        if 'HTTP' in packet:
            if hasattr(packet.http, 'response_code'):
                code = packet.http.response_code
                if code.startswith(('4', '5')):
                    stats['http_errors'][code] += 1
                    
    except AttributeError:
        # Skip packets with missing attributes
        pass

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
    
    # Protocol distribution
    print("\n### Protocol Distribution")
    for proto, count in stats['protocols'].items():
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
        if avg_delay > 0.5:
            print("  ⚠️ WARNING: High SYN delay (>0.5s)")
    
    if stats['udp_jitter']:
        avg_jitter = sum(stats['udp_jitter'])/len(stats['udp_jitter'])
        print(f"- Avg UDP Jitter: {avg_jitter:.4f}s")
        if avg_jitter > 0.1:
            print("  ⚠️ WARNING: High jitter (>0.1s)")
    
    # Critical warnings
    if stats['retransmissions'] > stats['packet_count'] * 0.05:
        rate = stats['retransmissions']/stats['packet_count']
        print(f"\n⚠️ CRITICAL: High retransmission rate ({rate:.1%} > 5% threshold)")
    
    # Top talkers and conversations
    print("\n### Top 15 Talkers")
    sorted_talkers = sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:15]
    for ip, count in sorted_talkers:
        print(f"- {ip}: {count} packets")
    
    print("\n### Top 5 Conversations")
    sorted_convos = sorted(stats['conversations'].items(), key=lambda x: x[1], reverse=True)[:5]
    for (src, dst), count in sorted_convos:
        print(f"- {src} ↔ {dst}: {count} packets")

def analyze_pcap(pcap_path):
    """Analyze a PCAP file to extract and return network statistics."""
    # Verify file exists before processing
    if not os.path.exists(pcap_path):
        print(f"[!] Error: File '{pcap_path}' not found")
        return initialize_stats()  # Return empty stats

    stats = initialize_stats()
    try:
        cap = pyshark.FileCapture(
            pcap_path,
            display_filter='tcp || udp || icmp || dns || http',
            only_summaries=False,
            custom_parameters=['-s 128'],
            debug=False,
            keep_packets=False
        )
        
        for packet in tqdm(cap, desc="Processing packets", unit="pkt"):
            update_stats(stats, packet)
    except Exception as e:
        print(f"\n[!] Error during analysis: {e}")
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
