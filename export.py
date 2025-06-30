#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import csv
import datetime
from config import PacketInsightConfig

# Create default configuration instance
config = PacketInsightConfig()

def export_report(stats, format_type, output_path=None):
    """Export analysis results in the specified format"""
    if format_type == 'json':
        return export_json(stats, output_path)
    elif format_type == 'csv':
        return export_csv(stats, output_path)
    elif format_type == 'html':
        return export_html(stats, output_path)
    else:
        print(f"Unsupported export format: {format_type}")
        return False

def export_json(stats, output_path=None):
    """Export analysis results as JSON"""
    # Generate default filename if not provided
    if not output_path:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"packet_insight_report_{timestamp}.json"
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # Convert any non-serializable objects
        serializable_stats = prepare_for_serialization(stats)
        
        # Write JSON file
        with open(output_path, 'w') as f:
            json.dump(serializable_stats, f, indent=2)
        
        print(f"\nReport exported to {output_path}")
        return True
    except Exception as e:
        print(f"Error exporting JSON: {e}")
        return False

def export_csv(stats, output_path=None):
    """Export analysis results as CSV"""
    # Generate default filename if not provided
    if not output_path:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"packet_insight_report_{timestamp}.csv"
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # Flatten the stats dictionary for CSV format
        flat_stats = flatten_dict(stats)
        
        # Write CSV file
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            for key, value in flat_stats.items():
                writer.writerow([key, value])
        
        print(f"\nReport exported to {output_path}")
        return True
    except Exception as e:
        print(f"Error exporting CSV: {e}")
        return False

def export_html(stats, output_path=None):
    """Export analysis results as HTML"""
    # Generate default filename if not provided
    if not output_path:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"packet_insight_report_{timestamp}.html"
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # Generate HTML content
        html_content = generate_html_report(stats)
        
        # Write HTML file
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        print(f"\nReport exported to {output_path}")
        return True
    except Exception as e:
        print(f"Error exporting HTML: {e}")
        return False

def prepare_for_serialization(obj):
    """Convert non-serializable objects to serializable format"""
    if isinstance(obj, dict):
        # Convert dictionary with special handling for tuple keys
        result = {}
        for k, v in obj.items():
            # Convert tuple keys to strings
            if isinstance(k, tuple):
                new_key = "_".join(str(item) for item in k)
            else:
                new_key = k
            result[new_key] = prepare_for_serialization(v)
        return result
    elif isinstance(obj, list):
        return [prepare_for_serialization(item) for item in obj]
    elif isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    elif hasattr(obj, '__dict__'):
        return prepare_for_serialization(obj.__dict__)
    else:
        return obj

def flatten_dict(d, parent_key='', sep='_'):
    """Flatten a nested dictionary for CSV export"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Handle lists specially
            if all(isinstance(x, dict) for x in v):
                # List of dictionaries - flatten each one with an index
                for i, item in enumerate(v):
                    items.extend(flatten_dict(item, f"{new_key}{sep}{i}", sep=sep).items())
            else:
                # Simple list - join with commas
                items.append((new_key, ', '.join(str(x) for x in v)))
        else:
            items.append((new_key, v))
    return dict(items)

def generate_html_report(stats):
    """Generate an HTML report from the analysis results"""
    # Get timestamp for the report
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate derived metrics
    capture_duration = stats['end_timestamp'] - stats['start_timestamp'] if 'end_timestamp' in stats and 'start_timestamp' in stats else 0
    avg_packet_size = stats['total_bytes'] / stats['packet_count'] if stats['packet_count'] > 0 else 0
    
    # Start building HTML content
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Packet Insight Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
            h1, h2, h3 {{ color: #2c3e50; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ background-color: #34495e; color: white; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; padding: 15px; background-color: #f9f9f9; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .metric {{ display: flex; margin: 10px 0; }}
            .metric-name {{ font-weight: bold; width: 300px; }}
            .metric-value {{ flex-grow: 1; }}
            .alert {{ background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0; }}
            table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #34495e; color: white; }}
            tr:hover {{ background-color: #f5f5f5; }}
            .footer {{ margin-top: 30px; text-align: center; font-size: 0.8em; color: #7f8c8d; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Packet Insight Report</h1>
                <p>Generated on {timestamp}</p>
            </div>
    """
    
    # Summary section
    html += f"""
            <div class="section">
                <h2>Summary</h2>
                <div class="metric">
                    <div class="metric-name">Packets Analyzed:</div>
                    <div class="metric-value">{stats['packet_count']:,}</div>
                </div>
                <div class="metric">
                    <div class="metric-name">Total Data Volume:</div>
                    <div class="metric-value">{format_bytes(stats['total_bytes'])}</div>
                </div>
                <div class="metric">
                    <div class="metric-name">Average Packet Size:</div>
                    <div class="metric-value">{avg_packet_size:.2f} bytes</div>
                </div>
                <div class="metric">
                    <div class="metric-name">Duration:</div>
                    <div class="metric-value">{format_duration(capture_duration)}</div>
                </div>
                <div class="metric">
                    <div class="metric-name">Average Throughput:</div>
                    <div class="metric-value">{format_throughput(stats['total_bytes'], capture_duration)}</div>
                </div>
            </div>
    """
    
    # Protocol Distribution
    html += f"""
            <div class="section">
                <h2>Protocol Distribution</h2>
                <table>
                    <tr>
                        <th>Protocol</th>
                        <th>Packets</th>
                        <th>Percentage</th>
                    </tr>
    """
    
    for protocol, count in stats['protocols'].items():
        percentage = (count / stats['packet_count']) * 100 if stats['packet_count'] > 0 else 0
        html += f"""
                    <tr>
                        <td>{protocol}</td>
                        <td>{count:,}</td>
                        <td>{percentage:.2f}%</td>
                    </tr>
        """
    
    html += "</table></div>"
    
    # TCP Analysis
    html += f"""
            <div class="section">
                <h2>TCP Analysis</h2>
                <div class="metric">
                    <div class="metric-name">TCP Connections:</div>
                    <div class="metric-value">{stats.get('tcp_connections', 0):,}</div>
                </div>
                <div class="metric">
                    <div class="metric-name">Retransmissions:</div>
                    <div class="metric-value">{stats.get('retransmissions', 0):,}</div>
                </div>
                <div class="metric">
                    <div class="metric-name">Retransmission Rate:</div>
                    <div class="metric-value">{(stats.get('retransmissions', 0) / stats['packet_count']) * 100:.2f}% of packets</div>
                </div>
                <div class="metric">
                    <div class="metric-name">TCP Resets:</div>
                    <div class="metric-value">{stats.get('resets', 0):,}</div>
                </div>
                <div class="metric">
                    <div class="metric-name">Average TCP Handshake Delay:</div>
                    <div class="metric-value">{(sum(stats.get('tcp_syn_delays', [])) / len(stats.get('tcp_syn_delays', [1])) * 1000) if stats.get('tcp_syn_delays') else 0:.2f} ms</div>
                </div>
            </div>
    """
    
    # HTTP Analysis if available
    if 'http_errors' in stats and stats['http_errors']:
        html += f"""
            <div class="section">
                <h2>HTTP Analysis</h2>
                <h3>HTTP Errors</h3>
                <table>
                    <tr>
                        <th>Error Code</th>
                        <th>Count</th>
                    </tr>
        """
        
        for code, count in stats['http_errors'].items():
            html += f"""
                    <tr>
                        <td>{code}</td>
                        <td>{count:,}</td>
                    </tr>
            """
        
        html += "</table></div>"
    
    # DNS Analysis if available
    if 'dns_queries' in stats and stats['dns_queries']:
        html += f"""
            <div class="section">
                <h2>DNS Analysis</h2>
                <div class="metric">
                    <div class="metric-name">DNS Queries:</div>
                    <div class="metric-value">{sum(stats['dns_queries'].values()):,}</div>
                </div>
                <div class="metric">
                    <div class="metric-name">DNS Issues:</div>
                    <div class="metric-value">{stats.get('dns_issues', 0):,}</div>
                </div>
        """
        
        # Average DNS response time
        if 'dns_response_times' in stats and stats['dns_response_times']:
            avg_response_time = sum(stats['dns_response_times']) / len(stats['dns_response_times'])
            html += f"""
                <div class="metric">
                    <div class="metric-name">Average Response Time:</div>
                    <div class="metric-value">{avg_response_time * 1000:.2f} ms</div>
                </div>
            """
        
        # Top DNS Queries
        if stats['dns_queries']:
            html += f"""
                <h3>Top DNS Queries</h3>
                <table>
                    <tr>
                        <th>Domain</th>
                        <th>Count</th>
                    </tr>
            """
            
            # Sort and limit to top 10 queries
            sorted_queries = sorted(stats['dns_queries'].items(), key=lambda x: x[1], reverse=True)[:10]
            for domain, count in sorted_queries:
                html += f"""
                    <tr>
                        <td>{domain}</td>
                        <td>{count:,}</td>
                    </tr>
                """
            
            html += "</table>"
        
        html += "</div>"
    
    # Top Talkers
    if 'top_talkers' in stats and stats['top_talkers']:
        html += f"""
            <div class="section">
                <h2>Top Talkers</h2>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Packets</th>
                        <th>Percentage</th>
                    </tr>
        """
        
        # Sort top talkers by packet count
        sorted_talkers = sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:15]
        
        for ip, count in sorted_talkers:
            percentage = (count / stats['packet_count']) * 100 if stats['packet_count'] > 0 else 0
            html += f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{count:,}</td>
                        <td>{percentage:.2f}%</td>
                    </tr>
            """
        
        html += "</table></div>"
    
    # Alerts section
    if 'alerts' in stats and stats['alerts']:
        html += f"""
            <div class="section">
                <h2>Alerts</h2>
        """
        
        for alert in stats['alerts']:
            html += f"""
                <div class="alert">
                    <strong>{alert['severity']}:</strong> {alert['message']}
                </div>
            """
        
        html += "</div>"
    
    # Close HTML
    html += f"""
            <div class="footer">
                <p>Generated by Packet Insight</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html

def format_bytes(bytes_value):
    """Format bytes into human-readable format"""
    if bytes_value < 1024:
        return f"{bytes_value} bytes"
    elif bytes_value < 1024 * 1024:
        return f"{bytes_value / 1024:.2f} KB"
    elif bytes_value < 1024 * 1024 * 1024:
        return f"{bytes_value / (1024 * 1024):.2f} MB"
    else:
        return f"{bytes_value / (1024 * 1024 * 1024):.2f} GB"

def format_duration(seconds):
    """Format duration in seconds to human-readable format"""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.2f} hours"

def format_throughput(bytes_value, seconds):
    """Calculate and format throughput"""
    if seconds <= 0:
        return "N/A"
    
    bits_per_second = (bytes_value * 8) / seconds
    
    if bits_per_second < 1000:
        return f"{bits_per_second:.2f} bps"
    elif bits_per_second < 1000 * 1000:
        return f"{bits_per_second / 1000:.2f} Kbps"
    elif bits_per_second < 1000 * 1000 * 1000:
        return f"{bits_per_second / (1000 * 1000):.2f} Mbps"
    else:
        return f"{bits_per_second / (1000 * 1000 * 1000):.2f} Gbps"

def get_http_status_description(code):
    """Get description for HTTP status code"""
    descriptions = {
        # 1xx Informational
        '100': 'Continue',
        '101': 'Switching Protocols',
        '102': 'Processing',
        '103': 'Early Hints',
        
        # 2xx Success
        '200': 'OK',
        '201': 'Created',
        '202': 'Accepted',
        '203': 'Non-Authoritative Information',
        '204': 'No Content',
        '205': 'Reset Content',
        '206': 'Partial Content',
        '207': 'Multi-Status',
        '208': 'Already Reported',
        '226': 'IM Used',
        
        # 3xx Redirection
        '300': 'Multiple Choices',
        '301': 'Moved Permanently',
        '302': 'Found',
        '303': 'See Other',
        '304': 'Not Modified',
        '305': 'Use Proxy',
        '307': 'Temporary Redirect',
        '308': 'Permanent Redirect',
        
        # 4xx Client Errors
        '400': 'Bad Request',
        '401': 'Unauthorized',
        '402': 'Payment Required',
        '403': 'Forbidden',
        '404': 'Not Found',
        '405': 'Method Not Allowed',
        '406': 'Not Acceptable',
        '407': 'Proxy Authentication Required',
        '408': 'Request Timeout',
        '409': 'Conflict',
        '410': 'Gone',
        '411': 'Length Required',
        '412': 'Precondition Failed',
        '413': 'Payload Too Large',
        '414': 'URI Too Long',
        '415': 'Unsupported Media Type',
        '416': 'Range Not Satisfiable',
        '417': 'Expectation Failed',
        '418': "I'm a teapot",
        '421': 'Misdirected Request',
        '422': 'Unprocessable Entity',
        '423': 'Locked',
        '424': 'Failed Dependency',
        '425': 'Too Early',
        '426': 'Upgrade Required',
        '428': 'Precondition Required',
        '429': 'Too Many Requests',
        '431': 'Request Header Fields Too Large',
        '451': 'Unavailable For Legal Reasons',
        
        # 5xx Server Errors
        '500': 'Internal Server Error',
        '501': 'Not Implemented',
        '502': 'Bad Gateway',
        '503': 'Service Unavailable',
        '504': 'Gateway Timeout',
        '505': 'HTTP Version Not Supported',
        '506': 'Variant Also Negotiates',
        '507': 'Insufficient Storage',
        '508': 'Loop Detected',
        '510': 'Not Extended',
        '511': 'Network Authentication Required'
    }
    
    # Convert code to string if it's an integer
    code_str = str(code)
    
    return descriptions.get(code_str, 'Unknown Status Code')

# Example usage
if __name__ == "__main__":
    # Test with sample data
    sample_stats = {
        'packet_count': 1000,
        'total_bytes': 1024 * 1024 * 5,  # 5 MB
        'avg_packet_size': 5120,
        'duration': 120,  # 2 minutes
        'protocols': {'TCP': 700, 'UDP': 200, 'ICMP': 50, 'Other': 50},
        'tcp_connections': 50,
        'retransmissions': 25,
        'resets': 5,
        'avg_tcp_handshake_delay': 0.05,  # 50ms
        'http_methods': {'GET': 300, 'POST': 150, 'PUT': 50, 'DELETE': 10},
        'http_status_codes': {'200': 400, '404': 50, '500': 10},
        'http_errors': {'client_errors': 60, 'server_errors': 15},
        'dns_queries': 100,
        'dns_responses': 95,
        'avg_dns_response_time': 0.02,  # 20ms
        'dns_failures': 5,
        'top_dns_queries': {'example.com': 20, 'google.com': 15, 'microsoft.com': 10},
        'top_talkers': {
            '192.168.1.100': {'packets': 500, 'bytes': 2 * 1024 * 1024},
            '10.0.0.1': {'packets': 300, 'bytes': 1.5 * 1024 * 1024}
        },
        'alerts': [
            {'severity': 'Warning', 'message': 'High retransmission rate detected (2.5%)'},
            {'severity': 'Error', 'message': 'Multiple DNS failures for domain example.com'}
        ]
    }
    
    # Test export functions
    export_json(sample_stats, 'sample_report.json')
    export_csv(sample_stats, 'sample_report.csv')
    export_html(sample_stats, 'sample_report.html')