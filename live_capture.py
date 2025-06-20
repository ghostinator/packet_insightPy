#!/usr/bin/env python3
"""
Real-time Network Insight - Live Packet Analysis
"""
import pyshark
import time
from packet_utils import initialize_stats, update_stats, generate_report

def live_analysis(interface='en0', update_interval=10):
    """Analyze live network traffic"""
    stats = initialize_stats()
    print(f"Starting live capture on {interface}... (Ctrl+C to stop)")
    
    capture = pyshark.LiveCapture(
        interface=interface,
        display_filter='tcp || udp || icmp || dns || http',
        custom_parameters=['-s 128']
    )
    
    last_update = time.time()
    
    try:
        for packet in capture.sniff_continuously():
            update_stats(stats, packet)
            
            # Periodic updates
            if time.time() - last_update >= update_interval:
                print("\n" + "-"*40)
                print(f"Live Update @ {time.strftime('%H:%M:%S')}")
                generate_report(stats, show_all=False)
                last_update = time.time()
                
    except KeyboardInterrupt:
        print("\nCapture stopped. Final report:")
        generate_report(stats)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Live network analysis')
    parser.add_argument('-i', '--interface', default='en0', 
                        help='Network interface (default: en0)')
    parser.add_argument('-t', '--interval', type=int, default=10,
                        help='Update interval in seconds (default: 10)')
    args = parser.parse_args()
    
    live_analysis(interface=args.interface, update_interval=args.interval)
