#!/usr/bin/env python3
"""
Report Generator - Generate reports in various formats
"""
import os
import json
import csv
import time
from datetime import datetime
from config import PacketInsightConfig

# Create default configuration instance
config = PacketInsightConfig()

def ensure_output_dir(output_dir=None):
    """Ensure the output directory exists"""
    if not output_dir:
        output_dir = config.get('default_output_dir', 'reports')
    
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def generate_filename(prefix, extension, output_dir=None):
    """Generate a timestamped filename"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = ensure_output_dir(output_dir)
    return os.path.join(output_dir, f"{prefix}_{timestamp}.{extension}")

def export_to_json(stats, output_file=None):
    """Export statistics to JSON format"""
    if not output_file:
        output_file = generate_filename("packet_insight", "json")
    
    # Convert defaultdicts to regular dicts for JSON serialization
    serializable_stats = {}
    for key, value in stats.items():
        if hasattr(value, 'items'):  # It's a dict-like object
            serializable_stats[key] = dict(value)
        else:
            serializable_stats[key] = value
    
    # Add metadata
    serializable_stats['metadata'] = {
        'generated_at': datetime.now().isoformat(),
        'version': '1.0.0'
    }
    
    with open(output_file, 'w') as f:
        json.dump(serializable_stats, f, indent=2)
    
    print(f"[✓] JSON report saved to {output_file}")
    return output_file

def export_to_csv(stats, output_file=None):
    """Export statistics to CSV format"""
    if not output_file:
        output_file = generate_filename("packet_insight", "csv")
    
    # Flatten the stats for CSV format
    flattened_stats = []
    
    # Basic metrics
    flattened_stats.append(["Metric", "Value"])
    flattened_stats.append(["Packet Count", stats['packet_count']])
    flattened_stats.append(["Total Bytes", stats['total_bytes']])
    flattened_stats.append(["Capture Duration (s)", stats['end_timestamp'] - stats['start_timestamp']])
    flattened_stats.append(["TCP Retransmissions", stats['retransmissions']])
    flattened_stats.append(["TCP Resets", stats['resets']])
    flattened_stats.append(["DNS Issues", stats['dns_issues']])
    flattened_stats.append(["Malformed Packets", stats['malformed_packets']])
    
    # Add empty row as separator
    flattened_stats.append([])
    
    # Protocol distribution
    flattened_stats.append(["Protocol", "Packet Count"])
    for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
        flattened_stats.append([proto, count])
    
    # Add empty row as separator
    flattened_stats.append([])
    
    # Top talkers
    flattened_stats.append(["IP Address", "Packet Count"])
    for ip, count in sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:15]:
        flattened_stats.append([ip, count])
    
    # Add empty row as separator
    flattened_stats.append([])
    
    # HTTP errors
    if stats['http_errors']:
        flattened_stats.append(["HTTP Error Code", "Count"])
        for code, count in stats['http_errors'].items():
            flattened_stats.append([code, count])
    
    # Write to CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(flattened_stats)
    
    print(f"[✓] CSV report saved to {output_file}")
    return output_file

def export_to_html(stats, output_file=None):
    """Export statistics to HTML format with charts"""
    if not output_file:
        output_file = generate_filename("packet_insight", "html")
    
    # Calculate some metrics for the report
    capture_duration = stats['end_timestamp'] - stats['start_timestamp']
    avg_packet_size = stats['total_bytes'] / stats['packet_count'] if stats['packet_count'] else 0
    throughput = stats['total_bytes'] * 8 / capture_duration if capture_duration > 0 else 0
    
    # Prepare data for charts
    protocol_labels = json.dumps([proto for proto, _ in sorted(stats['protocols'].items(), 
                                                            key=lambda x: x[1], reverse=True)[:10]])
    protocol_data = json.dumps([count for _, count in sorted(stats['protocols'].items(), 
                                                          key=lambda x: x[1], reverse=True)[:10]])
    
    talker_labels = json.dumps([ip for ip, _ in sorted(stats['top_talkers'].items(), 
                                                    key=lambda x: x[1], reverse=True)[:10]])
    talker_data = json.dumps([count for _, count in sorted(stats['top_talkers'].items(), 
                                                        key=lambda x: x[1], reverse=True)[:10]])
    
    # Generate HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Packet Insight Report</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .header h1 {{ margin: 0; }}
            .header p {{ margin: 5px 0 0; }}
            .card {{ background-color: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }}
            .card h2 {{ margin-top: 0; color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
            .metrics {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }}
            .metric-card {{ flex: 1; min-width: 200px; background-color: #f8f9fa; padding: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            .metric-card h3 {{ margin-top: 0; font-size: 16px; color: #666; }}
            .metric-card p {{ margin-bottom: 0; font-size: 24px; font-weight: bold; color: #2c3e50; }}
            .chart-container {{ display: flex; flex-wrap: wrap; gap: 20px; }}
            .chart {{ flex: 1; min-width: 45%; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .alert {{ background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin-bottom: 10px; }}
            .footer {{ text-align: center; margin-top: 30px; font-size: 14px; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Packet Insight Report</h1>
                <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
            
            <div class="card">
                <h2>Summary</h2>
                <div class="metrics">
                    <div class="metric-card">
                        <h3>Packets Analyzed</h3>
                        <p>{stats['packet_count']:,}</p>
                    </div>
                    <div class="metric-card">
                        <h3>Total Data</h3>
                        <p>{stats['total_bytes'] / 1e6:.2f} MB</p>
                    </div>
                    <div class="metric-card">
                        <h3>Duration</h3>
                        <p>{capture_duration:.2f} seconds</p>
                    </div>
                    <div class="metric-card">
                        <h3>Throughput</h3>
                        <p>{throughput / 1e6:.2f} Mbps</p>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>Network Issues</h2>
    """
    
    # Add alerts if there are issues
    if stats['retransmissions'] > stats['packet_count'] * config.get('retransmission_threshold', 0.05):
        rate = stats['retransmissions']/stats['packet_count']
        html_content += f"""
                <div class="alert">
                    <strong>Critical:</strong> High retransmission rate ({rate:.1%} > {config.get('retransmission_threshold', 0.05):.0%} threshold)
                </div>
        """
    
    if stats['tcp_syn_delays'] and sum(stats['tcp_syn_delays'])/len(stats['tcp_syn_delays']) > config.get('syn_delay_threshold', 0.5):
        avg_delay = sum(stats['tcp_syn_delays'])/len(stats['tcp_syn_delays'])
        html_content += f"""
                <div class="alert">
                    <strong>Warning:</strong> High TCP handshake delay ({avg_delay:.4f}s > {config.get('syn_delay_threshold', 0.5)}s threshold)
                </div>
        """
    
    # Add issue metrics
    html_content += f"""
                <div class="metrics">
                    <div class="metric-card">
                        <h3>TCP Retransmissions</h3>
                        <p>{stats['retransmissions']}</p>
                    </div>
                    <div class="metric-card">
                        <h3>TCP Resets</h3>
                        <p>{stats['resets']}</p>
                    </div>
                    <div class="metric-card">
                        <h3>DNS Issues</h3>
                        <p>{stats['dns_issues']}</p>
                    </div>
                    <div class="metric-card">
                        <h3>Malformed Packets</h3>
                        <p>{stats['malformed_packets']}</p>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>Protocol Distribution</h2>
                <div class="chart-container">
                    <div class="chart">
                        <canvas id="protocolChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>Top Talkers</h2>
                <div class="chart-container">
                    <div class="chart">
                        <canvas id="talkerChart"></canvas>
                    </div>
                </div>
            </div>
    """
    
    # Add HTTP errors if any
    if stats['http_errors']:
        html_content += f"""
            <div class="card">
                <h2>HTTP Errors</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Error Code</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for code, count in sorted(stats['http_errors'].items(), key=lambda x: x[1], reverse=True):
            html_content += f"""
                        <tr>
                            <td>{code}</td>
                            <td>{count}</td>
                        </tr>
            """
        
        html_content += f"""
                    </tbody>
                </table>
            </div>
        """
    
    # Add TLS/SSL section if applicable
    if stats['tls_handshakes'] > 0:
        html_content += f"""
            <div class="card">
                <h2>TLS/SSL Analysis</h2>
                <div class="metrics">
                    <div class="metric-card">
                        <h3>TLS Handshakes</h3>
                        <p>{stats['tls_handshakes']}</p>
                    </div>
                    <div class="metric-card">
                        <h3>TLS Alerts</h3>
                        <p>{stats['tls_alerts']}</p>
                    </div>
                </div>
        """
        
        # Add TLS version information
        if stats['tls_versions']:
            html_content += f"""
                <h3>TLS Versions</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Version</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            version_map = {
                '0x0301': 'TLS 1.0', '0x0302': 'TLS 1.1',
                '0x0303': 'TLS 1.2', '0x0304': 'TLS 1.3'
            }
            
            for version, count in stats['tls_versions'].items():
                version_name = version_map.get(version, f"Unknown ({version})")
                warning = " (Insecure)" if version in ['0x0301', '0x0302'] else ""
                html_content += f"""
                        <tr>
                            <td>{version_name}{warning}</td>
                            <td>{count}</td>
                        </tr>
                """
            
            html_content += f"""
                    </tbody>
                </table>
            """
        
        html_content += f"""
            </div>
        """
    
    # Add JavaScript for charts
    html_content += f"""
            <div class="footer">
                <p>Generated by Packet Insight v1.0.0</p>
            </div>
        </div>
        
        <script>
            // Protocol distribution chart
            const protocolCtx = document.getElementById('protocolChart').getContext('2d');
            new Chart(protocolCtx, {{
                type: 'bar',
                data: {{
                    labels: {protocol_labels},
                    datasets: [{{
                        label: 'Packet Count',
                        data: {protocol_data},
                        backgroundColor: 'rgba(54, 162, 235, 0.5)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Protocol Distribution'
                        }},
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
            
            // Top talkers chart
            const talkerCtx = document.getElementById('talkerChart').getContext('2d');
            new Chart(talkerCtx, {{
                type: 'bar',
                data: {{
                    labels: {talker_labels},
                    datasets: [{{
                        label: 'Packet Count',
                        data: {talker_data},
                        backgroundColor: 'rgba(75, 192, 192, 0.5)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Top Talkers'
                        }},
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"[✓] HTML report saved to {output_file}")
    return output_file

def export_report(stats, output_format="text", output_file=None):
    """Export report in the specified format"""
    if output_format == "json":
        return export_to_json(stats, output_file)
    elif output_format == "csv":
        return export_to_csv(stats, output_file)
    elif output_format == "html":
        return export_to_html(stats, output_file)
    else:
        # Text format is handled by generate_report in packet_utils.py
        return None