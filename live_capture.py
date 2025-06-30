#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import datetime
import threading
import pyshark
import netifaces
from tqdm import tqdm
from config import PacketInsightConfig

# Create default configuration instance
config = PacketInsightConfig()

# Constants
DEFAULT_CAPTURE_DURATION = config.get('default_capture_duration', 60)  # seconds
DEFAULT_PACKET_LIMIT = config.get('max_packets_in_memory', 10000)   # packets
DEFAULT_CAPTURE_FILTER = ""    # no filter

def get_active_interfaces():
    """Get list of active network interfaces"""
    active_interfaces = []
    
    try:
        # Get all interfaces
        interfaces = netifaces.interfaces()
        
        for iface in interfaces:
            # Skip loopback on non-testing environments
            if iface == 'lo' or iface == 'localhost' or iface.startswith('loop'):
                continue
                
            # Check if interface has an IPv4 address
            try:
                if netifaces.AF_INET in netifaces.ifaddresses(iface):
                    # Get friendly name on macOS
                    if sys.platform == 'darwin':
                        try:
                            import subprocess
                            result = subprocess.run(['networksetup', '-listallhardwareports'], 
                                                   capture_output=True, text=True)
                            output = result.stdout
                            for line in output.split('\n'):
                                if iface in line:
                                    # Extract the friendly name from previous line
                                    idx = output.split('\n').index(line) - 1
                                    if idx >= 0:
                                        friendly_name = output.split('\n')[idx].replace('Hardware Port: ', '')
                                        active_interfaces.append((iface, friendly_name))
                                        break
                            else:
                                # If no friendly name found, use the interface name
                                active_interfaces.append((iface, iface))
                        except:
                            active_interfaces.append((iface, iface))
                    else:
                        # For other platforms, just use the interface name
                        active_interfaces.append((iface, iface))
            except ValueError:
                # Interface doesn't have an IPv4 address
                pass
    except Exception as e:
        print(f"Error getting interfaces: {e}")
    
    return active_interfaces

def prompt_interface_selection(interfaces):
    """Prompt user to select a network interface"""
    print("\nAvailable network interfaces:")
    for i, (iface, name) in enumerate(interfaces):
        print(f"  {i+1}. {name} ({iface})")
    
    while True:
        try:
            choice = int(input("\nSelect interface number: "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice-1][0]  # Return the interface name
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a number.")

def generate_capture_filename(interface, rolling=False):
    """Generate a filename for the capture file"""
    # Replace spaces and special characters in interface name to make a valid filename
    safe_interface = interface.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if rolling:
        return f"capture_{safe_interface}_{timestamp}.pcap"
    else:
        return f"live_capture_{safe_interface}_{timestamp}.pcap"

def check_tshark_installed():
    """Check if tshark is installed and available in the PATH"""
    import subprocess
    import shutil
    
    # First try using shutil which is more efficient
    if shutil.which('tshark'):
        return True
    
    # If shutil didn't find it, try running tshark --version as a fallback
    try:
        subprocess.run(['tshark', '--version'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE, 
                      check=False)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def start_capture(interface, output_file, duration=None, packet_limit=None, capture_filter=""):
    """Start a live capture on the specified interface"""
    # Check if tshark is installed
    if not check_tshark_installed():
        print("\nERROR: tshark is not installed or not in your PATH.")
        print("Please install Wireshark/tshark before using this feature.")
        print("Installation instructions:")
        print("  - macOS: brew install wireshark or download from https://www.wireshark.org/download.html")
        print("  - Linux: sudo apt install tshark or sudo yum install wireshark")
        print("  - Windows: download from https://www.wireshark.org/download.html")
        return None
    
    # Create capture object
    if duration:
        print(f"Starting capture on {interface} for {duration} seconds...")
    elif packet_limit:
        print(f"Starting capture on {interface} for {packet_limit} packets...")
    else:
        print(f"Starting capture on {interface} (press Ctrl+C to stop)...")
    
    # Start the capture
    try:
        # Use tshark for capture (more reliable than pyshark for live capture)
        import subprocess
        cmd = ['tshark', '-i', interface, '-w', output_file]
        
        # Add duration if specified
        if duration:
            cmd.extend(['-a', f'duration:{duration}'])
        
        # Add packet limit if specified
        if packet_limit:
            cmd.extend(['-c', str(packet_limit)])
        
        # Add capture filter if specified
        if capture_filter:
            cmd.extend(['-f', capture_filter])
        
        # Start the capture process
        process = subprocess.Popen(cmd)
        
        # Wait for the capture to complete
        process.wait()
        
        print(f"\nCapture completed. Saved to {output_file}")
        return output_file
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        return output_file
    except Exception as e:
        print(f"\nError during capture: {e}")
        return None

def process_packets_realtime(interface, callback=None, display_filter=None):
    """Process packets in real-time with optional callback"""
    capture = None
    try:
        # Create a live capture
        capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)
        
        # Process packets in small batches to avoid memory issues
        batch_size = 100
        while True:
            # Capture a small batch of packets
            packets = capture.sniff_continuously(packet_count=batch_size)
            
            # Process the batch
            for packet in packets:
                if callback:
                    callback(packet)
                    
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as e:
        print(f"\nError during real-time processing: {e}")
    finally:
        # Properly clean up resources
        if capture:
            try:
                # Monkey patch the close method to avoid event loop issues
                if hasattr(capture, 'close'):
                    # Replace the close method with a no-op
                    def noop(*args, **kwargs):
                        pass
                    capture.close = noop
                
                # Clear the capture object
                capture = None
            except Exception as e:
                print(f"Error cleaning up capture: {e}")

def live_analysis(interface, duration=None, output_format='text', rolling_size_mb=None, 
                 rolling_interval_min=None, enable_alerts=True):
    """Perform live capture and analysis with optional rolling files"""
    # Import here to avoid circular imports
    from packet_utils import analyze_pcap_safe as analyze_pcap
    from packet_utils import generate_report
    from export import export_report
    
    # Check if tshark is installed before proceeding
    if not check_tshark_installed():
        print("\nERROR: tshark is not installed or not in your PATH.")
        print("Please install Wireshark/tshark before using this feature.")
        print("Installation instructions:")
        print("  - macOS: brew install wireshark or download from https://www.wireshark.org/download.html")
        print("  - Linux: sudo apt install tshark or sudo yum install wireshark")
        print("  - Windows: download from https://www.wireshark.org/download.html")
        return
    
    # Set up rolling capture if requested
    if rolling_size_mb or rolling_interval_min:
        print(f"Starting rolling capture on {interface}")
        if rolling_size_mb:
            print(f"  - New file every {rolling_size_mb}MB")
        if rolling_interval_min:
            print(f"  - New file every {rolling_interval_min} minutes")
        
        try:
            while True:
                # Generate filename for this capture segment
                output_file = generate_capture_filename(interface, rolling=True)
                
                # Determine capture duration for this segment
                segment_duration = rolling_interval_min * 60 if rolling_interval_min else None
                
                # Start capture for this segment
                capture_thread = threading.Thread(
                    target=start_capture,
                    args=(interface, output_file, segment_duration, None, "")
                )
                capture_thread.start()
                
                # Monitor file size if needed
                start_time = time.time()
                while capture_thread.is_alive():
                    # Check if we need to stop based on file size
                    if rolling_size_mb and os.path.exists(output_file):
                        file_size_mb = os.path.getsize(output_file) / (1024 * 1024)
                        if file_size_mb >= rolling_size_mb:
                            # Stop the current capture
                            import subprocess
                            subprocess.run(['pkill', '-f', f'tshark -i {interface}'])
                            break
                    
                    # Check if we need to stop based on time
                    if rolling_interval_min:
                        elapsed_min = (time.time() - start_time) / 60
                        if elapsed_min >= rolling_interval_min:
                            break
                    
                    # Sleep to avoid high CPU usage
                    time.sleep(1)
                
                # Wait for capture to finish
                capture_thread.join()
                
                # Check if the capture file was created
                if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                    print(f"\nWarning: No data captured in {output_file}")
                    continue
                
                # Analyze the capture file
                print(f"\nAnalyzing {output_file}...")
                stats = analyze_pcap(output_file)
                
                # Generate report
                if output_format == 'text':
                    generate_report(stats)
                else:
                    report_file = output_file.replace('.pcap', f'.{output_format}')
                    export_report(stats, output_format, report_file)
                    print(f"Report saved to {report_file}")
                    
                # Show alerts if enabled
                if enable_alerts:
                    show_alerts(stats)
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
    else:
        # Single capture
        output_file = generate_capture_filename(interface)
        result = start_capture(interface, output_file, duration)
        
        # Check if capture was successful
        if not result or not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            print(f"\nError: No data captured or capture failed")
            return
        
        # Analyze the capture file
        print(f"\nAnalyzing {output_file}...")
        stats = analyze_pcap(output_file)
        
        # Generate report
        if output_format == 'text':
            generate_report(stats)
        else:
            report_file = output_file.replace('.pcap', f'.{output_format}')
            export_report(stats, output_format, report_file)
            print(f"Report saved to {report_file}")
            
        # Show alerts if enabled
        if enable_alerts:
            show_alerts(stats)

# Example usage
if __name__ == "__main__":
    # Get active interfaces
    interfaces = get_active_interfaces()
    
    if not interfaces:
        print("No active interfaces found.")
        sys.exit(1)
    
    # Prompt user to select an interface
    interface = prompt_interface_selection(interfaces)
    
    # Start live capture and analysis
    live_analysis(interface, duration=60)

def show_alerts(stats):
    """Show alerts based on statistics"""
    # Import configuration
    from config import PacketInsightConfig
    config = PacketInsightConfig()
    
    # Check for high retransmission rate
    if stats['retransmissions'] > stats['packet_count'] * config.get('retransmission_threshold', 0.05):
        rate = stats['retransmissions']/stats['packet_count']
        print(f"\n⚠️ ALERT: High retransmission rate ({rate:.1%} > {config.get('retransmission_threshold', 0.05):.0%} threshold)")
    
    # Check for high TCP handshake delay
    if stats['tcp_syn_delays']:
        avg_delay = sum(stats['tcp_syn_delays'])/len(stats['tcp_syn_delays'])
        if avg_delay > config.get('syn_delay_threshold', 0.5):
            print(f"\n⚠️ ALERT: High TCP handshake delay ({avg_delay:.4f}s > {config.get('syn_delay_threshold', 0.5)}s threshold)")
    
    # Check for high UDP jitter
    if stats['udp_jitter']:
        avg_jitter = sum(stats['udp_jitter'])/len(stats['udp_jitter'])
        if avg_jitter > config.get('high_jitter_threshold', 0.1):
            print(f"\n⚠️ ALERT: High UDP jitter ({avg_jitter:.4f}s > {config.get('high_jitter_threshold', 0.1)}s threshold)")
    
    # Check for DNS issues
    if stats['dns_response_times']:
        avg_dns_response = sum(stats['dns_response_times']) / len(stats['dns_response_times'])
        if avg_dns_response > config.get('dns_timeout_threshold', 1.0):
            print(f"\n⚠️ ALERT: High DNS response time ({avg_dns_response:.4f}s > {config.get('dns_timeout_threshold', 1.0)}s threshold)")
    
    # Check for HTTP errors
    if stats['http_errors']:
        total_http_errors = sum(stats['http_errors'].values())
        if total_http_errors > 0:
            print(f"\n⚠️ ALERT: HTTP errors detected ({total_http_errors} total)")
            for code, count in stats['http_errors'].items():
                print(f"  • {code}: {count} errors")
    
    # Check for TLS issues
    if stats['tls_versions']:
        for version in stats['tls_versions']:
            if version in ['0x0301', '0x0302']:  # TLS 1.0, TLS 1.1
                print(f"\n⚠️ ALERT: Insecure TLS version detected ({version})")
    
    if stats['expired_certs']:
        print("\n⚠️ ALERT: Expired certificates detected")
    
    if stats['self_signed_certs']:
        print("\n⚠️ ALERT: Self-signed certificates detected")