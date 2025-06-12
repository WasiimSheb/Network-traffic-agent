# generate_report.py
from datetime import datetime

def create_html_report(all_flows, malicious_flows, summary_text, output_file="report.html"):
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI Cyber Agent Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #2c3e50;
        }}
        .summary, .llm-section {{
            background-color: #ffffff;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 0 8px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
        }}
        th {{
            background-color: #2c3e50;
            color: white;
        }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>AI Cyber Agent Report</h1>
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Generated:</strong> {datetime.now()}</p>
        <p><strong>Total flows analyzed:</strong> {len(all_flows)}</p>
        <p><strong>Flows flagged as malicious:</strong> {len(malicious_flows)}</p>
    </div>

    <div class="summary">
        <h2>⚠️ Sample Malicious Flows</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Length</th>
                <th>Timestamp</th>
            </tr>
    """

    for i, flow in enumerate(malicious_flows[:10]):
        html += f"""
            <tr>
                <td>{i+1}</td>
                <td>{flow['src_ip']}:{flow['src_port']}</td>
                <td>{flow['dst_ip']}:{flow['dst_port']}</td>
                <td>{flow['protocol']}</td>
                <td>{flow['length']}</td>
                <td>{flow['timestamp']}</td>
            </tr>
        """

    html += f"""
        </table>
    </div>

    <div class="llm-section">
        <h2>🤖 LLM Threat Explanation</h2>
        <p>{summary_text.replace('\n', '<br>')}</p>
    </div>
</body>
</html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML report saved to {output_file}")
