# Packet Insight 🕵️‍♂️📦

**Advanced PCAP Analysis for Support Engineers**  
Packet Insight turns complex packet captures into actionable, easy-to-understand insights. Designed for field and support teams, it highlights critical issues, performance metrics, and anomalies—no deep protocol expertise required.

---

## Features

### 🚀 Optimized Performance
- Header-only processing for fast analysis
- Memory-efficient streaming, handles large captures
- Real-time progress tracking

### 🔍 Advanced Diagnostics
- **Bandwidth Analysis:** Throughput, data volume, packet size distribution
- **Connection Quality:** TCP handshake delays, UDP jitter
- **Protocol Issues:** TCP retransmissions/resets, DNS failures, HTTP error codes
- **Top Talkers & Conversations:** Quickly identify heavy hitters and key flows

### ⚠️ Intelligent Alerts
- Warnings for high retransmission rates, excessive handshake delays, and HTTP errors
- Automated anomaly detection using customizable baselines

---

## Requirements

| OS       | Python | Packet Capture Tool | Additional Notes                          |
|----------|--------|--------------------|-------------------------------------------|
| Windows  | 3.6+   | [Npcap](https://npcap.com/) (via Wireshark) | Run as Administrator                      |
| macOS    | 3.6+   | [Wireshark](https://www.wireshark.org/)     | Install via Homebrew; use `sudo`          |
| Linux    | 3.6+   | `tshark` (`apt install tshark`)             | Use `sudo` or add user to `wireshark` group|

**Python dependencies:**  
```bash
pip install pyshark tqdm
```

---

## Installation

### 1. Install Python and Dependencies

- [Download Python](https://www.python.org/downloads/) (ensure "Add to PATH" is checked on Windows)
- Install required Python packages:
  ```bash
  pip install pyshark tqdm
  ```

### 2. Install Packet Capture Tools

- **Windows:**  
  Install [Wireshark](https://www.wireshark.org/) and ensure Npcap is selected during installation.

- **macOS:**  
  ```bash
  brew install wireshark
  ```

- **Linux (Debian/Ubuntu):**  
  ```bash
  sudo apt update
  sudo apt install tshark
  sudo usermod -aG wireshark $USER
  newgrp wireshark
  ```

---

## Usage

### Basic Analysis
```bash
python packet_insight.py path/to/capture.pcap
```

### Interactive Mode (Recommended for New Users)
```bash
python packet_insight.py --interactive
```

### Live Capture (Requires Admin)
```bash
sudo python packet_insight.py --interactive
# Then choose "Capture and analyze live traffic"
```

---

## Automated Troubleshooting Mode

Packet Insight includes a rapid diagnostics mode:

- **Checks for a baseline** (creates one if missing)
- **Captures a new sample** (default: 2 minutes)
- **Analyzes and compares** to the baseline
- **Highlights anomalies** in key metrics

**Usage:**

- **macOS/Linux:**  
  ```bash
  sudo python packet_insight.py --troubleshoot
  ```
- **Windows (as Administrator):**  
  ```cmd
  python packet_insight.py --troubleshoot
  ```

**Tip:**  
Clear the baseline at any time:
```bash
python packet_insight.py --clear-baseline
```

---

## Building a Windows Executable

**Build on Windows for best results.**

1. [Install Python for Windows](https://www.python.org/downloads/windows/)
2. Install dependencies:
   ```cmd
   pip install pyinstaller pyshark tqdm
   ```
3. Download and extract the [Wireshark Portable ZIP](https://www.wireshark.org/download.html) into a `tshark` folder in your project (for portable builds).
4. Build:
   ```cmd
   pyinstaller --onefile --add-data "tshark/*;tshark" packet_insight.py
   ```
5. Find `packet_insight.exe` in the `dist` folder.

---

## Troubleshooting

### Permission Errors
- **Linux/macOS:**  
  Ensure you run as root or your user is in the `wireshark` group.
- **Windows:**  
  Always "Run as Administrator" for live capture.

### Capture Issues
- **No interfaces found:** Run as admin/root.
- **Missing packets:** Try disabling firewall/antivirus during capture.
- **Slow processing:** Use protocol filters (e.g., `--filter "tcp"`).

### TShark Not Found
- **Windows:**  
  Ensure `tshark.exe` is in the `tshark` folder or that Wireshark is installed.
- **macOS/Linux:**  
  Ensure `tshark` is installed and in your PATH.

---

## Recommended Workflow

1. **Establish Baseline:**  
   ```bash
   sudo python baseline_manager.py baseline_capture.pcap
   ```
2. **Capture Issue:**  
   ```bash
   sudo tcpdump -i en0 -w issue_capture.pcap
   ```
3. **Analyze:**  
   ```bash
   python packet_insight.py issue_capture.pcap
   ```

---

## Platform Notes

- **macOS:**  
  - Use `brew install wireshark`
  - For wireless capture, disconnect from WiFi first
  - Interface names: `en0` (Ethernet), `en1` (WiFi)

- **Windows:**  
  - Ensure Npcap is installed (not WinPcap)
  - Add `PacketInsight.exe` to antivirus exclusions if flagged

- **Linux:**  
  - Add your user to `wireshark` group for non-root capture

---

## License

[MIT License](LICENSE) — Free for commercial and personal use

---


> "By analysts, for support teams" — someone somewhere probably

---

**Happy packet analyzing!** 🚀

