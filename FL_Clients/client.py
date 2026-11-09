import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import warnings
warnings.filterwarnings("ignore")

import time
import argparse
import requests
import joblib
import numpy as np
from datetime import datetime
import tensorflow as tf
from tensorflow.keras.models import Sequential
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.utils.class_weight import compute_class_weight

# --- CONFIGURATION ---
SERVER_URL = "http://10.170.227.91:5000"  # Make sure this matches your Host IPv4
GLOBAL_MODEL_ENDPOINT = f"{SERVER_URL}/api/global_model"
CLIENT_UPDATE_ENDPOINT = f"{SERVER_URL}/api/client_update"
DETECTION_ENDPOINT = f"{SERVER_URL}/api/detection_report"

LABEL_ENCODER_PATH = "label_encoder.pkl"
LOCAL_MODEL_CACHE = "local_client_model.keras"

def receive_global_model(client_id):
    print(f"\n[1/6] Receiving Global Model from Central Server ({SERVER_URL})...")
    res = requests.get(GLOBAL_MODEL_ENDPOINT, params={"client_id": client_id}, timeout=10)
    res.raise_for_status()
    data = res.json()

    model = Sequential.from_config(data["model_config"])
    model.set_weights([np.array(w, dtype=np.float32) for w in data["weights"]])
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.002),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    print(f"      [+] Loaded Global Model {data['global_model_version']} ({model.count_params():,} parameters).")
    return model, data["global_model_version"]

def train_on_local_samples(model, X_train, y_train, epochs=5):
    print(f"[2/6] Training on {len(X_train)} local malware & benign samples ({epochs} Epochs with Balanced Class Weights)...")
    classes = np.unique(y_train)
    weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    class_weight_dict = {int(c): float(w) for c, w in zip(classes, weights)}

    model.fit(X_train, y_train, epochs=epochs, batch_size=64, class_weight=class_weight_dict, verbose=1)

def evaluate_local_accuracy(model, X_test, y_test):
    print(f"[3/6] Evaluating trained local model on {len(X_test)} local test samples...")
    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    probs = model.predict(X_test, verbose=0)
    preds = np.argmax(probs, axis=1)

    prec = precision_score(y_test, preds, average='weighted', zero_division=0)
    rec = recall_score(y_test, preds, average='weighted', zero_division=0)
    f1 = f1_score(y_test, preds, average='weighted', zero_division=0)

    print(f"      [+] Local Evaluation -> Accuracy: {accuracy*100:.2f}% | Loss: {loss:.4f} | F1: {f1*100:.2f}%")
    return float(loss), float(accuracy), float(prec), float(rec), float(f1)

def send_weights_and_receive_updated_model(model, client_id, num_samples, loss, accuracy, prec, rec, f1):
    print(f"[4/6] Sending trained model weights to Central Server for FedAvg aggregation...")
    payload = {
        "client_id": client_id,
        "weights": [w.tolist() for w in model.get_weights()],
        "num_samples": int(num_samples),
        "local_loss": loss,
        "local_accuracy": accuracy * 100.0,
        "local_precision": prec * 100.0,
        "local_recall": rec * 100.0,
        "local_f1": f1 * 100.0
    }

    res = requests.post(CLIENT_UPDATE_ENDPOINT, json=payload, timeout=20)
    res.raise_for_status()
    resp = res.json()

    updated_version = resp["global_model_version"]
    updated_weights = [np.array(w, dtype=np.float32) for w in resp["global_weights"]]
    model.set_weights(updated_weights)
    model.save(LOCAL_MODEL_CACHE)

    print(f"[5/6] Received Updated Global Model {updated_version} (Global Acc: {resp['global_accuracy']}%, Loss: {resp['global_loss']})")
    return updated_version

def continue_detection(model, label_encoder, X_detect, client_id, num_detections=6, delay=1.0):
    print(f"[6/6] Continuing real-time local malware detection using Updated Global Model...")
    indices = np.random.choice(len(X_detect), size=min(num_detections, len(X_detect)), replace=False)

    for idx in indices:
        sample = X_detect[idx : idx + 1]
        softmax_probs = model.predict(sample, verbose=0)[0]
        predicted_class_index = int(np.argmax(softmax_probs))
        prediction_confidence = round(float(np.max(softmax_probs)), 4)
        predicted_malware_type = str(label_encoder.inverse_transform([predicted_class_index])[0])

        detection_payload = {
            "client_id": client_id,
            "malware_type": predicted_malware_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d"),
            "prediction_confidence": prediction_confidence
        }
        print(f"      [DETECT] {detection_payload}")
        requests.post(DETECTION_ENDPOINT, json=detection_payload, timeout=5)
        time.sleep(delay)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", default="vm_1", help="Client ID (e.g., vm_1, vm_2)")
    parser.add_argument("--data", default="Client_03_data.npz", help="Path to local dataset")
    parser.add_argument("--epochs", type=int, default=5, help="Local training epochs per round")
    parser.add_argument("--rounds", type=int, default=3, help="Number of federated rounds to execute")
    parser.add_argument("--detections", type=int, default=5, help="Detections per round")
    args = parser.parse_args()

    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    dataset = np.load(args.data)
    X_train, y_train = dataset["X_train"], dataset["y_train"]
    X_test, y_test = dataset["X_test"], dataset["y_test"]
    X_detect = dataset["X_detect"]

    for r in range(1, args.rounds + 1):
        print("\n" + "=" * 72)
        print(f" 🔄 FEDERATED ROUND {r}/{args.rounds} | CLIENT: {args.client}")
        print("=" * 72)

        model, _ = receive_global_model(args.client)
        train_on_local_samples(model, X_train, y_train, epochs=args.epochs)
        loss, acc, prec, rec, f1 = evaluate_local_accuracy(model, X_test, y_test)
        send_weights_and_receive_updated_model(model, args.client, len(X_train), loss, acc, prec, rec, f1)
        continue_detection(model, label_encoder, X_detect, args.client, num_detections=args.detections)

if __name__ == "__main__":
    main()
