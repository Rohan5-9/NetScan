import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import pickle

# 🔹 Load CSV files
normal = pd.read_csv("C:\\Users\\Rohan\\OneDrive\\Documents\\normal_traffic.csv")
attack = pd.read_csv("C:\\Users\\Rohan\\OneDrive\\Documents\\attack_traffic.csv")

# 🔹 Clean column names
normal.columns = normal.columns.str.strip()
attack.columns = attack.columns.str.strip()

# 🔹 Feature Engineering
def create_features(df):
    df["Length"] = pd.to_numeric(df["Length"], errors="coerce")
    df["Time"] = pd.to_numeric(df["Time"], errors="coerce")

    df["is_mqtt"] = (df["Protocol"] == "MQTT").astype(int)
    df["is_attack_proto"] = df["Protocol"].isin(["ICMP", "ICMPv6"]).astype(int)

    # Keep consistent with real-time
    df["time_delta"] = 0  

    df["length_bucket"] = pd.cut(
        df["Length"],
        bins=[0, 100, 500, 1000, 2000],
        labels=[0, 1, 2, 3]
    ).astype(int)

    return df

normal = create_features(normal)
attack = create_features(attack)

# 🔹 Labeling
normal["label"] = 0
attack["label"] = 1

# 🔹 Merge
data = pd.concat([normal, attack], ignore_index=True)

print("Dataset distribution:\n", data["label"].value_counts())

# 🔹 Features
features = ["Length", "time_delta", "is_mqtt", "is_attack_proto", "length_bucket"]
X = data[features]
y = data["label"]

# 🔹 Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# 🔹 Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 🔹 Predict
y_pred = model.predict(X_test)

# 🔹 Evaluation
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# 🔹 Save model
model_bundle = {
    "model": model,
    "features": features
}

with open("iot_ids_model.pkl", "wb") as f:
    pickle.dump(model_bundle, f)

print("\n✅ Model saved successfully!")