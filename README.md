# Packet Insight 🕵️‍♂️📦

**Advanced PCAP Analysis for Support Engineers**  
Packet Insight transforms complex packet captures into actionable insights. Designed for field and support teams, it highlights critical issues and performance metrics—no deep protocol expertise required.

---

## Features

### 🚀 Optimized Performance
- **100x faster** than full packet analysis  
- Header-only processing (`-s 128` capture)  
- Memory-efficient streaming  
- Real-time progress tracking  

### 🔍 Advanced Diagnostics
- **Bandwidth Analysis**: Throughput, data volume, packet size  
- **Connection Quality**: TCP handshake delays, UDP jitter  
- **Protocol Issues**: TCP retransmissions, DNS failures, HTTP errors  
- **Top Talkers & Conversations**: Identify heavy hitters  
- **TLS/SSL Analysis**: Version detection, cipher suites, certificate issues
- **DNS Deep Dive**: Query response times, record types, top domains
- **DHCP Troubleshooting**: Track DHCP process, detect multiple servers

### ⚠️ Intelligent Alerts
- Automatic warnings for:  
  - High retransmission rates (>5%)  
  - Excessive TCP handshake delays (>0.5s)  
  - Critical HTTP error patterns  
  - Insecure TLS versions and self-signed certificates
  - Slow DNS responses and DHCP issues
- **Auto-Baselining**: Creates network-specific performance baselines  

### ✨ User Experience
- **Interactive Mode**: Guided workflows  
- **Auto-Interface Detection**: Finds active network adapters  
- **Human-Friendly Names**: Clear interface identification (macOS)  
- **Multiple Output Formats**: Export as JSON, CSV, or HTML reports
- **Configuration Files**: Persistent settings via YAML/INI files
- **Rolling Captures**: Automatically create new capture files at set intervals
- **Real-time Alerts**: Display alerts during live capture sessions

---

## Installation

### 1. Install Python 3.6+
- [Python Downloads](https://python.org/downloads)  
- **Windows**: Check "Add Python to PATH" during installation  

### 2. Install Dependencies
```
pip install pyshark tqdm netifaces pyyaml
```

### 3. Install Packet Capture Tools (Required)
Packet Insight requires tshark (the command-line version of Wireshark) to capture network traffic.

| OS       | Command                                                                 |
|----------|-------------------------------------------------------------------------|
| Windows  | Install [Wireshark](https://www.wireshark.org/) with Npcap             |
| macOS    | `brew install wireshark`                                               |
| Linux    | `sudo apt install tshark && sudo usermod -aG wireshark $USER`          |

> **Important**: Make sure tshark is in your system PATH after installation. You can verify by running `tshark --version` in your terminal or command prompt.

---

## Usage

### Basic Analysis
```
python packet_insight.py capture.pcap
```

### Interactive Mode (Recommended)
```
python packet_insight.py --interactive
```

### Key Features
```
# Automated troubleshooting
python packet_insight.py --troubleshoot

# Create/update baseline
python baseline_manager.py baseline_capture.pcap

# Clear existing baseline
python packet_insight.py --clear-baseline

# Focus on specific protocols
python packet_insight.py capture.pcap --filter "dns || dhcp || tls"

# Export as HTML report
python packet_insight.py capture.pcap --format html

# Live capture with rolling files
python packet_insight.py --live --interface eth0 --rolling-size 100 --rolling-interval 15

# Export configuration
python packet_insight.py --export-config my_config.yaml

# Import configuration
python packet_insight.py --config my_config.yaml
```

### Configuration File
Create a `packet_insight.yaml` file to set persistent preferences:

```yaml
# Analysis thresholds
retransmission_threshold: 0.05  # 5% retransmission rate threshold
high_jitter_threshold: 0.1     # 100ms jitter threshold
syn_delay_threshold: 0.5       # 500ms SYN delay threshold

# Live capture settings
rolling_capture_size_mb: 100   # Start new capture file after 100MB
rolling_capture_interval_min: 15  # Start new capture file every 15 minutes
enable_realtime_alerts: true   # Show alerts in real-time during live capture

# Output settings
default_output_format: "html"  # Default output format (text, json, csv, html)
```

---

## Building a Windows Executable

**Build on Windows for best results.**

1. [Install Python for Windows](https://www.python.org/downloads/windows/)
2. Install dependencies:
   ```cmd
   pip install pyinstaller pyshark tqdm pyyaml
   ```
3. Download and extract the [Wireshark Portable ZIP](https://www.wireshark.org/download.html) into a `tshark` folder in your project (for portable builds).
4. Build:
   ```cmd
   pyinstaller --onefile --add-data "tshark/*;tshark" packet_insight.py
   ```
5. Find `packet_insight.exe` in the `dist` folder.

---

## Platform-Specific Notes

### Windows
- **Run as Administrator** for live capture  
- Add `PacketInsight.exe` to antivirus exclusions if needed  

### macOS
- **Human-friendly interface names** (e.g., "Wi-Fi" instead of "en0")  
- **Wireless capture**: Disconnect from WiFi first  
- **Permissions**:  
  ```
  sudo chmod 777 /dev/bpf*  # Temporary fix if capture fails
  ```

### Linux
- **Non-root capture**: Ensure user is in `wireshark` group  
- **Interface names**: Use `ip link show` to identify adapters  

---


## Troubleshooting

### Common Issues
| Issue | Solution |
|-------|----------|
| **"tshark not found"** | Install Wireshark/tshark and ensure it's in your PATH. Run `tshark --version` to verify. |
| **Permission errors** | Run with `sudo` (macOS/Linux) or "Run as Administrator" (Windows) |
| **No interfaces found** | Check physical connections and run as admin |
| **Empty capture files** | Verify interface has traffic |
| **Spaces in interface names** | This is now handled automatically |

### Performance Tips
- **Large PCAPs**: Use `--filter "tcp"` to reduce data  
- **Slow analysis**: Add `--sample 100` to process every 100th packet  

---

## Workflow Guide

1. **Establish Baseline**  
   ```
   python packet_insight.py --interactive
   # Choose "Capture new baseline"
   ```
   
2. **Capture Issue**  
   ```
   sudo tcpdump -i en0 -w issue_capture.pcap
   ```
   
3. **Analyze**  
   ```
   python packet_insight.py issue_capture.pcap --format html
   ```
   
4. **Compare to Baseline**  
   ```
   python packet_insight.py --troubleshoot
   ```

---

## Support & Resources
maybe

**License**: [MIT License](LICENSE)  

---

**Happy packet analyzing!** 🚀

---