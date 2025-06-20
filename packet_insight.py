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
import threading
import pyshark
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
    """Detect active network interfaces with IP addresses cross-platform."""
    import platform
    import subprocess
    active_interfaces = []
    system = platform.system()
    
    if system == "Windows":
        try:
            # Use tshark to list interfaces
            from pyshark.tshark.tshark import get_tshark_path
            tshark_path = get_tshark_path()
            result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True, check=True)
            interfaces = result.stdout.splitlines()
            
            # Parse tshark output
            for iface in interfaces:
                if " (" in iface and ")" in iface:
                    # Extract interface name from "1. \Device\NPF_{GUID} (Ethernet)"
                    name = iface.split("(", 1)[1].split(")", 1)[0].strip()
                    active_interfaces.append(name)
        except Exception:
            # Fallback to netsh
            try:
                result = subprocess.run(["netsh", "interface", "show", "interface"], 
                                       capture_output=True, text=True, check=True)
                for line in result.stdout.splitlines():
                    if "Connected" in line and "Dedicated" in line:
                        parts = line.split()
                        if len(parts) > 3:
                            active_interfaces.append(" ".join(parts[3:]))
            except Exception:
                pass
    
    elif system == "Linux":
        try:
            # Preferred method: netifaces
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs:
                    active_interfaces.append(iface)
        except ImportError:
            # Fallback to ip command
            try:
                result = subprocess.run(["ip", "-o", "link", "show"], 
                                       capture_output=True, text=True, check=True)
                for line in result.stdout.splitlines():
                    if "state UP" in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            iface = parts[1].strip().split('@')[0]
                            active_interfaces.append(iface)
            except Exception:
                pass
    
    elif system == "Darwin":  # macOS
        try:
            # Get mapping of device names to friendly names
            name_map = get_macos_interface_names()
            result = subprocess.run(["ifconfig"], capture_output=True, text=True, check=True)
            current_if = None
            for line in result.stdout.splitlines():
                if not line.startswith('\t') and ':' in line:
                    current_if = line.split(':')[0]
                if current_if and "inet " in line and "127.0.0.1" not in line:
                    if current_if not in active_interfaces:
                        active_interfaces.append(current_if)
            # Attach friendly names for display
            interface_display = []
            for iface in active_interfaces:
                friendly = name_map.get(iface, "")
                if friendly:
                    interface_display.append(f"{iface} ({friendly})")
                else:
                    interface_display.append(iface)
            return interface_display
        except Exception as e:
            print(f"[!] Error detecting interfaces: {e}")
            active_interfaces = [detect_network_interface()]

    
    return active_interfaces or [detect_network_interface()]

def extract_device_name(interface_display_name: str) -> str:
    """Extract device name from display string (e.g., 'en11 (USB LAN)' -> 'en11')"""
    return interface_display_name.split(' (', 1)[0]

def get_macos_interface_names():
    """Return a dict mapping device names (en0) to human-friendly names (Wi-Fi, USB Ethernet, etc)."""
    import platform
    import subprocess
    if platform.system() != 'Darwin':
        return {}
    try:
        output = subprocess.check_output(['networksetup', '-listallhardwareports'], text=True)
        lines = output.splitlines()
        mapping = {}
        current_port = None
        for line in lines:
            if line.startswith('Hardware Port:'):
                current_port = line.split(':', 1)[1].strip()
            elif line.startswith('Device:') and current_port:
                device = line.split(':', 1)[1].strip()
                mapping[device] = current_port
                current_port = None
        return mapping
    except Exception as e:
        return {}


def get_tshark_path():
    """Find tshark executable with cross-platform support"""
    system = platform.system()
    
    # Try common paths first
    common_paths = {
        "Windows": [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe"
        ],
        "Darwin": [
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
            "/usr/local/bin/tshark"
        ],
        "Linux": [
            "/usr/bin/tshark"
        ]
    }
    
    # Check if tshark is in PATH
    try:
        subprocess.run(["tshark", "-v"], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "tshark"
    except Exception:
        pass
    
    # Check platform-specific paths
    for path in common_paths.get(system, []):
        if os.path.exists(path):
            return path
    
    return None

def capture_packets(duration=60, filename="capture.pcap", interface=None):
    tshark_path = get_tshark_path()
    if not tshark_path:
        print("[!] tshark not found. Please ensure Wireshark is installed.")
        return None

    # Extract device name if interface contains friendly name
    device_name = extract_device_name(interface) if interface else None

    # Build capture command
    cmd = [
        tshark_path,
        "-i", device_name or "any",
        "-a", f"duration:{duration}",
        "-w", filename,
        "-s", "128"  # Header-only capture
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print(f"[✓] Capture saved to {filename}")
        return filename
    except subprocess.CalledProcessError as e:
        print(f"[!] Capture failed: {e}")
        return None


def prompt_interface_selection(active_interfaces):
    """Prompt user to select an interface with friendly names"""
    name_map = get_macos_interface_names() if platform.system() == "Darwin" else {}
    
    if len(active_interfaces) == 1:
        iface = active_interfaces[0]
        friendly = name_map.get(iface, iface)
        print(f"Using active interface: {friendly}")
        return iface
    else:
        print("\nMultiple active interfaces detected:")
        for i, iface in enumerate(active_interfaces, 1):
            friendly = name_map.get(iface, iface)
            print(f"{i}. {friendly}")
        
        while True:
            selection = input("Select interface number: ").strip()
            if selection.isdigit() and 1 <= int(selection) <= len(active_interfaces):
                selected = active_interfaces[int(selection) - 1]
                friendly = name_map.get(selected, selected)
                print(f"Using interface: {friendly}")
                return selected
            else:
                print("Invalid selection. Please enter a valid number.")



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
            interface = prompt_interface_selection(active_interfaces)
            
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
            interface = prompt_interface_selection(active_interfaces)
            
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
    """Update baseline from PCAP file with enhanced reliability"""
    stats = analyze_pcap(pcap_path)
    if stats['packet_count'] == 0:
        print("[!] Error: No packets processed. Cannot create baseline.")
        return False
    
    baseline_type = get_baseline_type()
    baseline_data = load_baseline() or {"workday": {}, "weekend": {}}
    
    # Calculate metrics with safety checks
    try:
        baseline_data[baseline_type] = {
            "tcp_retransmission_rate": safe_divide(stats['retransmissions'], stats['packet_count']),
            "tcp_resets": stats['resets'],
            "avg_tcp_handshake_delay": safe_divide(sum(stats['tcp_syn_delays']), len(stats['tcp_syn_delays'])) if stats['tcp_syn_delays'] else 0,
            "avg_udp_jitter": safe_divide(sum(stats['udp_jitter']), len(stats['udp_jitter'])) if stats['udp_jitter'] else 0,
            "http_error_rate": safe_divide(sum(stats['http_errors'].values()), stats['packet_count'])
        }
    except Exception as e:
        print(f"[!] Error calculating metrics: {e}")
        return False
    
    # Save with atomic write and error handling
    try:
        abs_path = os.path.abspath(BASELINE_PATH)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        
        # Atomic write to prevent corruption
        temp_path = abs_path + ".tmp"
        with open(temp_path, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        # Replace existing file
        if os.path.exists(abs_path):
            os.remove(abs_path)
        os.rename(temp_path, abs_path)
        
        print(f"[✓] {baseline_type.capitalize()} baseline updated")
        print(f"    Saved to: {abs_path}")
        return True
    except Exception as e:
        print(f"[!] Failed to save baseline: {e}")
        return False

def safe_divide(numerator, denominator):
    """Safe division with zero handling"""
    return numerator / denominator if denominator else 0

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
