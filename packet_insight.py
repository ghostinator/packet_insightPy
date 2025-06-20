#!/usr/bin/env python3
"""
Packet Insight - Portable Network Analysis Tool
"""
import argparse
import os
import sys
import time
import json
import subprocess
import platform
from packet_utils import analyze_pcap, generate_report, get_baseline_type, load_baseline, save_baseline

# Configuration
BASELINE_PATH = "network_baselines.json"
DEFAULT_INTERFACE = "en0" if platform.system() == "Darwin" else "eth0"

def detect_network_interface():
    """Automatically detect primary network interface"""
    system = platform.system()
    try:
        if system == "Darwin":  # macOS
            result = subprocess.run(["route", "-n", "get", "default"], 
                                   capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "interface:" in line:
                    return line.split()[-1]
        elif system == "Linux":
            result = subprocess.run(["ip", "route", "show", "default"], 
                                   capture_output=True, text=True, check=True)
            if result.stdout:
                return result.stdout.split()[4]
    except Exception:
        pass
    return DEFAULT_INTERFACE

def get_active_interfaces():
    """Detect active network interfaces with IP addresses"""
    active_interfaces = []
    system = platform.system()
    
    if system == "Windows":
        try:
            # Get interface list with tshark
            from pyshark.tshark.tshark import get_tshark_path
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
            result = subprocess.run(["netsh", "interface", "show", "interface"], 
                                   capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "Connected" in line and "Dedicated" in line:
                    parts = line.split()
                    if len(parts) > 3:
                        active_interfaces.append(" ".join(parts[3:]))
    else:  # macOS/Linux
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs:
                    active_interfaces.append(iface)
        except ImportError:
            # If netifaces not installed, fallback to default
            active_interfaces.append(detect_network_interface())
    
    return active_interfaces

def capture_packets(duration=60, filename="capture.pcap", interface=None):
    """Capture live packets with automatic tool selection"""
    if not interface:
        active_interfaces = get_active_interfaces()
        interface = active_interfaces[0] if active_interfaces else None

    print(f"\n[+] Starting packet capture on {interface or 'all interfaces'} for {duration} seconds...")
    
    # Try tcpdump first (faster and more reliable)
    try:
        subprocess.run(
            ["tcpdump", "-i", interface, "-w", filename, "-G", str(duration), "-W", "1"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"[✓] Capture saved to {filename}")
        return filename
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] tcpdump not found. Using PyShark fallback...")
        return capture_with_pyshark(duration, filename, interface)

def capture_with_pyshark(duration, filename, interface):
    """Fallback capture using PyShark"""
    try:
        import pyshark
        capture = pyshark.LiveCapture(
            interface=interface,
            output_file=filename,
            custom_parameters=['-s 128']
        )
        capture.sniff(timeout=duration)
        return filename
    except Exception as e:
        print(f"[!] Capture failed: {e}")
        return None

def interactive_mode():
    """Interactive mode for portable troubleshooting"""
    print("\n" + "="*50)
    print("Packet Insight - Network Diagnostics")
    print("="*50)
    
    # Check for existing baseline
    baseline = load_baseline()
    baseline_exists = baseline and any(baseline.values())
    
    while True:
        print("\nOptions:")
        print("1. Capture new baseline")
        print("2. Analyze existing PCAP file")
        print("3. Capture and analyze live traffic")
        print("4. View current baseline")
        print("5. Clear baseline")
        print("6. Exit")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == "1":  # Capture new baseline
            duration = int(input("Capture duration (seconds) [60]: ") or 60)
            filename = input("Output filename [baseline.pcap]: ") or "baseline.pcap"
            
            # Auto-detect active interfaces
            active_interfaces = get_active_interfaces()
            if not active_interfaces:
                print("⚠️ No active interfaces found!")
                continue
                
            # Interface selection logic
            if len(active_interfaces) == 1:
                interface = active_interfaces[0]
                print(f"Using active interface: {interface}")
            else:
                print("\nActive interfaces:")
                for i, iface in enumerate(active_interfaces, 1):
                    print(f"{i}. {iface}")
                    
                selection = input("Select interface number (or Enter for all): ")
                if selection.isdigit() and 0 < int(selection) <= len(active_interfaces):
                    interface = active_interfaces[int(selection)-1]
                    print(f"Using interface: {interface}")
                else:
                    interface = None
                    print("Using all interfaces")
            
            captured_file = capture_packets(duration, filename, interface)
            if captured_file:
                print("\n[+] Creating baseline from capture...")
                update_baseline(captured_file)
        
        elif choice == "2":  # Analyze existing PCAP
            pcap_file = input("Path to PCAP file: ").strip()
            if not os.path.exists(pcap_file):
                print(f"[!] File not found: {pcap_file}")
            else:
                stats = analyze_pcap(pcap_file)
                generate_report(stats)
                
                # Offer to save as baseline
                if baseline_exists and input("\nSave as baseline? [y/N]: ").lower() == 'y':
                    update_baseline(pcap_file)
        
        elif choice == "3":  # Live capture and analysis
            duration = int(input("Capture duration (seconds) [60]: ") or 60)
            filename = input("Output filename [live_capture.pcap]: ") or "live_capture.pcap"
            
            # Auto-detect active interfaces
            active_interfaces = get_active_interfaces()
            if not active_interfaces:
                print("⚠️ No active interfaces found!")
                continue
                
            # Interface selection logic
            if len(active_interfaces) == 1:
                interface = active_interfaces[0]
                print(f"Using active interface: {interface}")
            else:
                print("\nActive interfaces:")
                for i, iface in enumerate(active_interfaces, 1):
                    print(f"{i}. {iface}")
                    
                selection = input("Select interface number (or Enter for all): ")
                if selection.isdigit() and 0 < int(selection) <= len(active_interfaces):
                    interface = active_interfaces[int(selection)-1]
                    print(f"Using interface: {interface}")
                else:
                    interface = None
                    print("Using all interfaces")
            
            captured_file = capture_packets(duration, filename, interface)
            if captured_file:
                stats = analyze_pcap(captured_file)
                generate_report(stats)
                
                # Offer to save as baseline
                if input("\nSave as baseline? [y/N]: ").lower() == 'y':
                    update_baseline(captured_file)
        
        elif choice == "4":  # View baseline
            if baseline_exists:
                print("\nCurrent Baseline Values:")
                for period, metrics in baseline.items():
                    print(f"\n{period.capitalize()}:")
                    for metric, value in metrics.items():
                        print(f"  - {metric}: {value:.4f}")
            else:
                print("\nNo baseline established yet")
        
        elif choice == "5":  # Clear baseline
            if os.path.exists(BASELINE_PATH):
                os.remove(BASELINE_PATH)
                print("[✓] Baseline cleared")
                baseline_exists = False
            else:
                print("[!] Baseline file not found")
        
        elif choice == "6":  # Exit
            print("Exiting...")
            sys.exit(0)
        
        else:
            print("[!] Invalid choice")
        
        input("\nPress Enter to continue...")

def update_baseline(pcap_path):
    """Update baseline from PCAP file"""
    stats = analyze_pcap(pcap_path)
    if stats['packet_count'] == 0:
        print("[!] Error: No packets processed. Cannot create baseline.")
        return
    
    baseline_type = get_baseline_type()
    baseline_data = load_baseline() or {"workday": {}, "weekend": {}}
    
    # Calculate metrics
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
        )
    }
    
    save_baseline(baseline_data)
    print(f"[✓] {baseline_type.capitalize()} baseline updated")

def portable_troubleshoot():
    """Automatic troubleshooting workflow"""
    # Check if baseline exists
    if not os.path.exists(BASELINE_PATH):
        print("No baseline found. Creating initial baseline...")
        capture_packets(60, "baseline.pcap")
        update_baseline("baseline.pcap")
    
    # Capture current traffic
    print("Capturing network traffic for analysis...")
    capture_file = "troubleshoot.pcap"
    capture_packets(120, capture_file)
    
    # Analyze and compare
    stats = analyze_pcap(capture_file)
    generate_report(stats)
    
    # Highlight anomalies
    baseline = load_baseline()
    if baseline:
        baseline_type = get_baseline_type()
        current_metrics = {
            "tcp_retransmission_rate": stats['retransmissions'] / stats['packet_count'],
            "http_error_rate": sum(stats['http_errors'].values()) / stats['packet_count']
        }
        
        print("\n### Baseline Comparison")
        for metric, value in current_metrics.items():
            baseline_value = baseline[baseline_type].get(metric, 0)
            deviation = abs(value - baseline_value) / baseline_value if baseline_value else 0
            if deviation > 0.5:
                print(f"⚠️ {metric.replace('_', ' ').title()}: "
                      f"{value:.4f} vs baseline {baseline_value:.4f} "
                      f"({deviation:.0%} deviation)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Packet Insight - Portable Network Diagnostics')
    parser.add_argument('pcap_file', nargs='?', help='Path to PCAP file')
    parser.add_argument('--interactive', action='store_true', help='Launch interactive mode')
    parser.add_argument('--troubleshoot', action='store_true', help='Automatic troubleshooting mode')
    parser.add_argument('--clear-baseline', action='store_true', help='Clear existing baseline')
    args = parser.parse_args()
    
    # Handle clear baseline request
    if args.clear_baseline:
        if os.path.exists(BASELINE_PATH):
            os.remove(BASELINE_PATH)
            print("[✓] Baseline cleared")
        else:
            print("[!] Baseline file not found")
        sys.exit(0)
    
    # Automatic troubleshooting mode
    if args.troubleshoot:
        portable_troubleshoot()
        sys.exit(0)
    
    # Launch interactive mode if requested or no file provided
    if args.interactive or not args.pcap_file:
        interactive_mode()
    else:
        # Verify file exists
        if not os.path.exists(args.pcap_file):
            print(f"[!] Error: File '{args.pcap_file}' not found")
            if input("Launch interactive mode? [Y/n]: ").lower() != 'n':
                interactive_mode()
            else:
                sys.exit(1)
        
        # Analyze provided PCAP
        stats = analyze_pcap(args.pcap_file)
        generate_report(stats)
        
        # Offer to save as baseline
        baseline = load_baseline()
        if baseline and any(baseline.values()):
            if input("\nSave as baseline? [y/N]: ").lower() == 'y':
                update_baseline(args.pcap_file)
