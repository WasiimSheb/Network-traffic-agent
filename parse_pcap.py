# parse_pcap.py
import pyshark
from collections import defaultdict

def extract_flows_from_pcap(pcap_path):
    capture = pyshark.FileCapture(pcap_path, use_json=True)
    flows = defaultdict(list)

    # Group packets by 5-tuple
    for packet in capture:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
            length = int(packet.length)
            timestamp = float(packet.sniff_timestamp)
            # Use 5-tuple as key
            flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
            flows[flow_key].append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": length,
                "timestamp": timestamp
            })
        except AttributeError:
            continue  # Skip malformed packets

    flow_summaries = []
    for key, packets in flows.items():
        src_ip, src_port, dst_ip, dst_port, protocol = key
        timestamps = [pkt["timestamp"] for pkt in packets]
        lengths = [pkt["length"] for pkt in packets]
        # src_bytes: bytes sent from src_ip to dst_ip
        src_bytes = sum(pkt["length"] for pkt in packets if pkt["src_ip"] == src_ip)
        # dst_bytes: bytes sent from dst_ip to src_ip
        dst_bytes = sum(pkt["length"] for pkt in packets if pkt["src_ip"] == dst_ip)
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
        flow_summaries.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": sum(lengths),  # total bytes in flow
            "timestamp": min(timestamps),  # start time
            "duration": duration,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes
        })

    capture.close()
    return flow_summaries
