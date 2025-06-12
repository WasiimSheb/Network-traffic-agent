# train_classifier.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib

# Function to load the KDD Cup 99 dataset
def load_kdd_data(filepath):
    columns = [
        "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent",
        "hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root",
        "num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
        "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
        "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
        "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
        "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","extra"
    ]
    df = pd.read_csv(filepath, names=columns, delimiter=',', header=None)
    df = df.drop(columns=["extra"])
    print("[DEBUG] Data sample after loading:")
    print(df.head())
    return df

# Function to preprocess the data
def preprocess_data(df):
    # Encode categorical features
    for col in ["protocol_type", "service", "flag"]:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
    # Convert label to binary: normal=0, attack=1
    df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
    return df

def train_and_save_model():
    # Load and preprocess the real dataset
    df = load_kdd_data("kdd_train.csv")
    df = preprocess_data(df)
    # Debug: print first few rows and dtypes
    print("[DEBUG] Data sample after preprocessing:")
    print(df.head())
    print("[DEBUG] Data types:")
    print(df.dtypes)
    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

    joblib.dump(clf, "model.pkl")
    print("[+] Model saved to model.pkl")

if __name__ == "__main__":
    train_and_save_model()
