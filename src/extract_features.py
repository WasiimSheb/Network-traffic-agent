# extract_features.py
import pandas as pd

def flow_to_features(flows):
    # KDD feature columns (excluding 'label' and 'extra')
    kdd_columns = [
        "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent",
        "hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root",
        "num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
        "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
        "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
        "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
        "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
    ]
    feature_list = []

    for flow in flows:
        protocol = flow.get("protocol", "TCP")
        proto_encoded = {"TCP": 0, "UDP": 1, "ICMP": 2}.get(protocol, 0)
        features = {
            "duration": flow.get("duration", 0),
            "protocol_type": proto_encoded,
            "service": 0,  # Not available
            "flag": 0,     # Not available
            "src_bytes": flow.get("src_bytes", 0),
            "dst_bytes": flow.get("dst_bytes", 0),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 0,
            "srv_count": 0,
            "serror_rate": 0,
            "srv_serror_rate": 0,
            "rerror_rate": 0,
            "srv_rerror_rate": 0,
            "same_srv_rate": 0,
            "diff_srv_rate": 0,
            "srv_diff_host_rate": 0,
            "dst_host_count": 0,
            "dst_host_srv_count": 0,
            "dst_host_same_srv_rate": 0,
            "dst_host_diff_srv_rate": 0,
            "dst_host_same_src_port_rate": 0,
            "dst_host_srv_diff_host_rate": 0,
            "dst_host_serror_rate": 0,
            "dst_host_srv_serror_rate": 0,
            "dst_host_rerror_rate": 0,
            "dst_host_srv_rerror_rate": 0
        }
        feature_list.append(features)

    df = pd.DataFrame(feature_list, columns=kdd_columns)
    return df
