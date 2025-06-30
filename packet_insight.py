#!/usr/bin/env python3
"""
Packet Insight - Portable Network Analysis Tool
VERSION = "1.0.0"
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
from packet_utils import analyze_pcap_safe as analyze_pcap, generate_report, get_baseline_type, load_baseline, save_baseline
from config import PacketInsightConfig
from export import export_report
from live_capture import get_active_interfaces, prompt_interface_selection

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
    
    # Load configuration
    config = PacketInsightConfig.from_file()
    
    while True:
        print("\nOptions:")
        print("1. Capture new baseline")
        print("2. Analyze existing PCAP file")
        print("3. Capture and analyze live traffic")
        print("4. View current baseline")
        print("5. Clear baseline")
        print("6. Export configuration")
        print("7. Import configuration")
        print("8. Exit")
        
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
                # Ask for output format
                print("\nOutput format options:")
                print("1. Text (console output)")
                print("2. JSON file")
                print("3. CSV file")
                print("4. HTML report")
                format_choice = input("Select format [1]: ").strip() or "1"
                
                output_format = "text"
                if format_choice == "2":
                    output_format = "json"
                elif format_choice == "3":
                    output_format = "csv"
                elif format_choice == "4":
                    output_format = "html"
                
                # Analyze the file
                stats = analyze_pcap(pcap_file)
                
                # Generate report in selected format
                if output_format == "text":
                    generate_report(stats)
                else:
                    export_report(stats, output_format)
                
                # Offer to save as baseline
                if input("\nSave as baseline? [y/N]: ").lower() == 'y':
                    update_baseline(pcap_file)
        
        elif choice == "3":  # Live capture and analysis
            duration = int(input("Capture duration (seconds) [60]: ") or 60)
            filename = input("Output filename [live_capture.pcap]: ") or "live_capture.pcap"
            
            # Ask about rolling captures
            use_rolling = input("Use rolling captures? [y/N]: ").lower() == 'y'
            rolling_size = None
            rolling_interval = None
            
            if use_rolling:
                rolling_size = int(input(f"Roll after size in MB [{config.rolling_capture_size_mb}]: ") or config.rolling_capture_size_mb)
                rolling_interval = int(input(f"Roll after minutes [{config.rolling_capture_interval_min}]: ") or config.rolling_capture_interval_min)
            
            # Ask for output format
            print("\nOutput format options:")
            print("1. Text (console output)")
            print("2. JSON file")
            print("3. CSV file")
            print("4. HTML report")
            format_choice = input("Select format [1]: ").strip() or "1"
            
            output_format = "text"
            if format_choice == "2":
                output_format = "json"
            elif format_choice == "3":
                output_format = "csv"
            elif format_choice == "4":
                output_format = "html"
            
            # Auto-detect active interfaces
            active_interfaces = get_active_interfaces()
            if not active_interfaces:
                print("⚠️ No active interfaces found!")
                continue
                
            # Interface selection logic
            interface = prompt_interface_selection(active_interfaces)
            
            if use_rolling:
                # Use the enhanced live capture with rolling files
                from live_capture import live_analysis
                try:
                    live_analysis(
                        interface=interface,
                        output_format=output_format,
                        rolling_size_mb=rolling_size,
                        rolling_interval_min=rolling_interval,
                        enable_alerts=True
                    )
                except KeyboardInterrupt:
                    print("\nCapture stopped by user.")
            else:
                # Use traditional single-file capture
                captured_file = capture_packets(duration, filename, interface)
                if captured_file:
                    stats = analyze_pcap(captured_file)
                    
                    # Generate report in selected format
                    if output_format == "text":
                        generate_report(stats)
                    else:
                        export_report(stats, output_format)
                    
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
        
        elif choice == "6":  # Export configuration
            config_format = input("Configuration format (yaml/ini) [yaml]: ").strip().lower() or "yaml"
            if config_format not in ["yaml", "ini"]:
                print("[!] Invalid format. Using YAML.")
                config_format = "yaml"
                
            config_path = input(f"Output path [packet_insight.{config_format}]: ").strip() or f"packet_insight.{config_format}"
            
            # Save configuration
            config.save_to_file(config_path)
        
        elif choice == "7":  # Import configuration
            config_path = input("Path to configuration file: ").strip()
            if not os.path.exists(config_path):
                print(f"[!] File not found: {config_path}")
            else:
                # Load configuration from file
                new_config = PacketInsightConfig.from_file(config_path)
                
                # Update the configuration in other modules
                import packet_utils
                packet_utils.config = new_config
                
                import report_generator
                report_generator.config = new_config
                
                import export
                export.config = new_config
                
                import live_capture
                live_capture.config = new_config
                
                # Update current config
                config = new_config
                print(f"[✓] Configuration imported from {config_path}")
        
        elif choice == "8":  # Exit
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
    
    # Save baseline data
    try:
        save_baseline(baseline_data)
        
        print(f"[✓] {baseline_type.capitalize()} baseline updated")
        print(f"    Saved to: {os.path.abspath(BASELINE_PATH)}")
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
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--export-config', help='Export default configuration to specified file')
    
    # Output format options
    parser.add_argument('--format', choices=['text', 'json', 'csv', 'html'], default='text',
                      help='Output format for analysis results')
    parser.add_argument('--output', help='Output file path for reports')
    
    # Live capture options
    parser.add_argument('--live', action='store_true', help='Perform live capture instead of analyzing a file')
    parser.add_argument('--interface', help='Network interface for live capture')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds for live capture')
    parser.add_argument('--rolling-size', type=int, help='Start a new capture file after reaching this size in MB')
    parser.add_argument('--rolling-interval', type=int, help='Start a new capture file after this many minutes')
    
    args = parser.parse_args()
    
    # Load configuration
    config = PacketInsightConfig.from_file(args.config)
    
    # Update the configuration in other modules
    import packet_utils
    packet_utils.config = config
    
    import report_generator
    report_generator.config = config
    
    import export
    export.config = config
    
    import live_capture
    live_capture.config = config
    
    # Export configuration if requested
    if args.export_config:
        config.save_to_file(args.export_config)
        print(f"Configuration exported to {args.export_config}")
        sys.exit(0)
    
    # Handle clear baseline request
    if args.clear_baseline:
        if os.path.exists(BASELINE_PATH):
            os.remove(BASELINE_PATH)
            print("[✓] Baseline cleared")
        else:
            print("[!] Baseline file not found")
        sys.exit(0)
    
    # Live capture mode
    if args.live:
        from live_capture import live_analysis
        
        # Determine interface
        interface = args.interface
        if not interface:
            active_interfaces = get_active_interfaces()
            if not active_interfaces:
                print("[!] No active interfaces found")
                sys.exit(1)
            interface = prompt_interface_selection(active_interfaces)
        
        # Start live capture with rolling files if specified
        try:
            live_analysis(
                interface=interface,
                output_format=args.format,
                rolling_size_mb=args.rolling_size,
                rolling_interval_min=args.rolling_interval,
                enable_alerts=True
            )
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
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
        
        # Generate report in selected format
        if args.format == "text":
            generate_report(stats)
        else:
            export_report(stats, args.format, args.output)
        
        # Offer to save as baseline
        baseline = load_baseline()
        if baseline and any(baseline.values()):
            if input("\nSave as baseline? [y/N]: ").lower() == 'y':
                update_baseline(args.pcap_file)