# classify_flows.py
import joblib
from parse_pcap import extract_flows_from_pcap
from extract_features import flow_to_features
from ollama_summary import summarize_malicious_flows

def classify_flows(pcap_path, model_path="model.pkl"):
    print("[*] Loading PCAP...")
    flows = extract_flows_from_pcap(pcap_path)
    
    print(f"[*] {len(flows)} flows extracted.")
    df_features = flow_to_features(flows)

    print("[*] Loading model...")
    clf = joblib.load(model_path)

    print("[*] Classifying flows...")
    predictions = clf.predict(df_features)

    malicious_flows = []
    for i, flow in enumerate(flows):
        result = "MALICIOUS" if predictions[i] == 1 else "BENIGN"
        print(f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} | {result}")
        if predictions[i] == 1:
            malicious_flows.append(flow)

    # Print summary
    print("\n============================")
    print(f" Total Flows Analyzed: {len(flows)}")
    print(f" Malicious Flows Detected: {len(malicious_flows)}")
    print("============================\n")

    # Show top 5 malicious flows
    if malicious_flows:
        print("🔎 Sample Suspicious Flows:")
        for i, flow in enumerate(malicious_flows[:5]):
            print(f"{i+1}. {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} | {flow['protocol']} | Length: {flow['length']}")

        print("\n Agent's Threat Summary:\n")
        summary_text = summarize_malicious_flows(malicious_flows)
        print("=== Agent Report ===")
        print(summary_text)
        print("=========================\n")
    else:
        print("The agent did not detect any suspicious activity.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python classify_flows.py <pcap_file>")
        sys.exit(1)
    
    classify_flows(sys.argv[1])
