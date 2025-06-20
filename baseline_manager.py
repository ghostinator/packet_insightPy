#!/usr/bin/env python3
"""
Baseline Manager - Create/Update Network Baselines
"""
import argparse
import json
import os
import sys
from packet_utils import analyze_pcap, get_baseline_type, load_baseline, save_baseline

BASELINE_PATH = "network_baselines.json"

def update_baseline(pcap_path):
    # Verify file exists
    if not os.path.exists(pcap_path):
        print(f"[!] Error: File '{pcap_path}' not found")
        sys.exit(1)
        
    stats = analyze_pcap(pcap_path)
    
    # Check if any packets were processed
    if stats['packet_count'] == 0:
        print("[!] Error: No packets processed. Cannot create baseline.")
        sys.exit(1)
    
    baseline_type = get_baseline_type()
    
    # Load existing baseline or create new
    baseline_data = load_baseline() or {"workday": {}, "weekend": {}}
    
    # Calculate metrics for baseline
    baseline_data[baseline_type] = {
        "tcp_retransmission_rate": stats['retransmissions'] / stats['packet_count'],
        "tcp_resets": stats['resets'],
        "avg_tcp_handshake_delay": (
            sum(stats['tcp_syn_delays'])/len(stats['tcp_syn_delays']) 
            if stats['tcp_syn_delays'] else 0
        ),
        "avg_udp_jitter": (
            sum(stats['udp_jitter'])/len(stats['udp_jitter']) 
            if stats['udp_jitter'] else 0
        ),
        "http_error_rate": (
            sum(stats['http_errors'].values()) / stats['packet_count']
            if stats['packet_count'] else 0
        )
    }
    
    # Save updated baseline
    save_baseline(baseline_data)
    print(f"[✓] {baseline_type.capitalize()} baseline updated")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create/update network baseline')
    parser.add_argument('pcap_file', help='Path to normal-traffic PCAP file')
    args = parser.parse_args()
    update_baseline(args.pcap_file)
