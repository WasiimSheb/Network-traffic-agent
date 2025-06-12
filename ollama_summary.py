# ollama_summary.py
import ollama

def summarize_malicious_flows(flows):
    if not flows:
        return "The agent did not detect any suspicious activity in the network traffic."

    # Extract sample flows (up to 7)
    examples = ""
    for i, flow in enumerate(flows[:7]):
        examples += (
            f"Flow {i+1}:\n"
            f"- Source: {flow['src_ip']}:{flow['src_port']}\n"
            f"- Destination: {flow['dst_ip']}:{flow['dst_port']}\n"
            f"- Protocol: {flow['protocol']}\n"
            f"- Length: {flow['length']}\n"
            f"- Timestamp: {flow['timestamp']}\n\n"
        )

    prompt = f"""
You are a network traffic analysis agent.

Below are a few network flows that have been flagged as potentially malicious:

{examples}

Please write a professional summary of the suspicious activity observed. Your summary should:
- Discretely point out any destination IPs or ports that stand out (e.g., repeated use, suspicious destinations)
- Mention possible attack types such as scanning, data exfiltration, or malware C2
- Highlight any broader behavioral patterns across the flows
- Be written in clear, report-style language for cybersecurity analysts
- Avoid vague language like "might be malicious" and be confidently analytical

Limit your response to 6–8 sentences. Do not refer to yourself or to an LLM.
"""

    response = ollama.chat(
        model='tinyllama',
        messages=[{"role": "user", "content": prompt}]
    )
    return response['message']['content']
