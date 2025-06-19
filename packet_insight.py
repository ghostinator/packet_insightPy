#!/usr/bin/env python3
"""
Packet Insight - Advanced PCAP Analysis Tool
Simplifies network diagnostics for support engineers
"""
import sys
import pyshark
import time
from collections import defaultdict
from tqdm import tqdm

def analyze_pcap(pcap_path):
    """Optimized PCAP analyzer with advanced diagnostics"""
    try:
        print(f"\n[+] Analyzing {pcap_path}...")
        start_time = time.time()
        
        # Optimized capture configuration
        cap = pyshark.FileCapture(
            pcap_path,
            display_filter='tcp || udp || icmp || dns || http',
            only_summaries=False,
            custom_parameters=['-s 128'],  # Capture only first 128 bytes
            debug=False,
            keep_packets=False
        )
        
        # Initialize diagnostics
        stats = {
            'packet_count': 0,
            'total_bytes': 0,
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
            'throughput_samples': []
        }

        prev_packet_time = None
        prev_udp_time = {}
        
        # Process packets with progress bar
        for packet in tqdm(cap, desc="Processing packets", unit="pkt"):
            stats['packet_count'] += 1
            try:
                current_time = float(packet.sniff_timestamp)
                
                # Track time range
                stats['start_timestamp'] = min(stats['start_timestamp'], current_time)
                stats['end_timestamp'] = max(stats['end_timestamp'], current_time)
                
                # Track packet size
                if hasattr(packet, 'length'):
                    packet_size = int(packet.length)
                    stats['total_bytes'] += packet_size
                    stats['throughput_samples'].append((current_time, packet_size))
                
                # Track protocols
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
                
                # UDP diagnostics (per flow)
                if 'UDP' in packet:
                    flow_key = (packet.ip.src, packet.ip.dst, packet.udp.srcport, packet.udp.dstport)
                    if flow_key in prev_udp_time:
                        stats['udp_jitter'].append(current_time - prev_udp_time[flow_key])
                    prev_udp_time[flow_key] = current_time
                
                # Application layer diagnostics
                if 'DNS' in packet:
                    if packet.dns.flags_response == '0' and not hasattr(packet.dns, 'response_time'):
                        stats['dns_issues'] += 1
                
                if 'HTTP' in packet:
                    if hasattr(packet.http, 'response_code'):
                        code = packet.http.response_code
                        if code.startswith(('4', '5')):
                            stats['http_errors'][code] += 1
            
            except AttributeError:
                # Skip packets with missing layers
                continue
        
        # Post-processing calculations
        processing_time = time.time() - start_time
        capture_duration = stats['end_timestamp'] - stats['start_timestamp']
        avg_packet_size = stats['total_bytes'] / stats['packet_count'] if stats['packet_count'] else 0
        
        # Calculate throughput
        throughput = 0
        if capture_duration > 0:
            throughput = stats['total_bytes'] * 8 / capture_duration  # bps
        
        # Generate report
        print(f"\n[✓] Analysis completed in {processing_time:.2f}s")
        print(f"\n## Network Summary [Packets: {stats['packet_count']} | Duration: {capture_duration:.2f}s]")
        print(f"- Total Data: {stats['total_bytes'] / 1e6:.2f} MB")
        print(f"- Avg Packet Size: {avg_packet_size:.0f} bytes")
        print(f"- Estimated Throughput: {throughput / 1e6:.2f} Mbps")
        
        print("\n### Protocol Distribution")
        for proto, count in stats['protocols'].items():
            print(f"- {proto}: {count} packets ({count/stats['packet_count']:.1%})")
        
        print("\n### Top Issues")
        print(f"- TCP Retransmissions: {stats['retransmissions']}")
        print(f"- TCP Resets: {stats['resets']}")
        print(f"- DNS Timeouts/Failures: {stats['dns_issues']}")
        
        if stats['http_errors']:
            print(f"- HTTP Errors: {sum(stats['http_errors'].values())} total")
            for code, count in stats['http_errors'].items():
                print(f"  • {code}: {count} errors")
        
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
        
        # Critical issue warnings
        if stats['retransmissions'] > stats['packet_count'] * 0.05:
            rate = stats['retransmissions']/stats['packet_count']
            print(f"\n⚠️ CRITICAL: High retransmission rate ({rate:.1%} > 5% threshold)")
        
        print("\n### Top 5 Talkers")
        for ip, count in sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"- {ip}: {count} packets")
            
        print("\n### Top 3 Conversations")
        for (src, dst), count in sorted(stats['conversations'].items(), key=lambda x: x[1], reverse=True)[:3]:
            print(f"- {src} ↔ {dst}: {count} packets")
            
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./packet_insight.py <path_to_pcap>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
