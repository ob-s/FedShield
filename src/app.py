import os
import json
import numpy as np
from collections import Counter
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from tensorflow.keras.models import load_model

app = Flask(__name__)
app.secret_key = "federated_malware_c2_secret_key"

GLOBAL_MODEL_PATH = "src/global_model.keras"
LOG_FILE = "security_audit.log"

ADMIN_CREDENTIALS = {
    "admin": "fedsec2026",
    "supervisor": "demo123"
}

# ==============================================================================
# 1. INITIALIZE GLOBAL MODEL
# ==============================================================================
print("[*] Initializing Global Multi-Class TensorFlow Model...")
global_model = load_model(GLOBAL_MODEL_PATH)
TOTAL_PARAMS = int(global_model.count_params())
print(f"[+] Global Model v1.0 Ready ({TOTAL_PARAMS:,} parameters).")

fl_overview = {
    "total_clients_connected": 0,
    "active_clients_this_round": 0,
    "current_round": 0,
    "global_model_version": "v1.0",
    "global_accuracy": 0.0,
    "global_loss": 0.0,
    "global_precision": 0.0,
    "global_recall": 0.0,
    "global_f1": 0.0,
    "last_weight_delta": 0.0,
    "last_aggregation_time": "Initialized (v1.0)",
    "total_params": TOTAL_PARAMS
}

client_registry = {}
round_history = []
detection_logs = []

def write_audit_log(entry):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()
        if u in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[u] == p:
            session['user'] = u
            return redirect(url_for('dashboard'))
        error = "Invalid operator credentials."
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# ==============================================================================
# 2. DISTRIBUTE GLOBAL MODEL TO CLIENTS (Step 1 of Client Pipeline)
# ==============================================================================
@app.route('/api/global_model', methods=['GET'])
def get_global_model():
    client_id = request.args.get("client_id", "Client_01")
    if client_id in client_registry:
        client_registry[client_id]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        client_registry[client_id]["model_version"] = fl_overview["global_model_version"]

    return jsonify({
        "global_model_version": fl_overview["global_model_version"],
        "current_round": fl_overview["current_round"],
        "model_config": global_model.get_config(),
        "weights": [w.tolist() for w in global_model.get_weights()]
    }), 200

# ==============================================================================
# 3. RECEIVE CLIENT WEIGHTS, AGGREGATE VIA FEDAVG & RETURN UPDATED GLOBAL MODEL
# ==============================================================================
@app.route('/api/client_update', methods=['POST'])
def receive_client_update():
    data = request.json or {}
    client_id = data.get("client_id", "Client_01")
    raw_weights = data.get("weights")
    num_samples = max(1, int(data.get("num_samples", 100)))
    local_acc = float(data.get("local_accuracy", 0.0))
    local_loss = float(data.get("local_loss", 0.0))
    local_prec = float(data.get("local_precision", local_acc))
    local_rec = float(data.get("local_recall", local_acc))
    local_f1 = float(data.get("local_f1", local_acc))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not raw_weights:
        return jsonify({"error": "No weights provided"}), 400

    np_weights = [np.array(w, dtype=np.float32) for w in raw_weights]
    payload_kb = round(len(json.dumps(raw_weights).encode("utf-8")) / 1024.0, 2)

    prev = client_registry.get(client_id, {})
    client_registry[client_id] = {
        "client_id": client_id,
        "ip": request.remote_addr,
        "status": "Online",
        "weights": np_weights,
        "num_samples": num_samples,
        "local_accuracy": round(local_acc, 2),
        "local_loss": round(local_loss, 4),
        "local_precision": round(local_prec, 2),
        "local_recall": round(local_rec, 2),
        "local_f1": round(local_f1, 2),
        "rounds_participated": prev.get("rounds_participated", 0) + 1,
        "detections_sent": prev.get("detections_sent", 0),
        "latest_prediction": prev.get("latest_prediction", "Model Synced"),
        "payload_kb": payload_kb,
        "contribution_pct": 0.0,
        "model_version": fl_overview["global_model_version"],
        "last_seen": datetime.now().strftime("%H:%M:%S")
    }

    # --- Mathematical Federated Averaging (FedAvg): W_global = sum( (n_k / N) * W_k ) ---
    old_weights = [w.copy() for w in global_model.get_weights()]
    total_samples = sum(c["num_samples"] for c in client_registry.values())

    fedavg_weights = [np.zeros_like(w, dtype=np.float32) for w in old_weights]
    agg_acc, agg_loss, agg_prec, agg_rec, agg_f1 = 0.0, 0.0, 0.0, 0.0, 0.0

    for cid, cdata in client_registry.items():
        factor = cdata["num_samples"] / total_samples
        cdata["contribution_pct"] = round(factor * 100.0, 1)

        agg_acc += cdata["local_accuracy"] * factor
        agg_loss += cdata["local_loss"] * factor
        agg_prec += cdata["local_precision"] * factor
        agg_rec += cdata["local_recall"] * factor
        agg_f1 += cdata["local_f1"] * factor

        for i, lw in enumerate(cdata["weights"]):
            fedavg_weights[i] += lw * factor

    weight_delta = round(float(np.sqrt(sum(np.sum((nw - ow) ** 2) for nw, ow in zip(fedavg_weights, old_weights)))), 4)

    # Generate Updated Global Model
    global_model.set_weights(fedavg_weights)
    global_model.save(GLOBAL_MODEL_PATH)

    fl_overview["current_round"] += 1
    curr_round = fl_overview["current_round"]
    new_version = f"v1.{curr_round}"

    fl_overview.update({
        "total_clients_connected": len(client_registry),
        "active_clients_this_round": len(client_registry),
        "global_model_version": new_version,
        "global_accuracy": round(agg_acc, 2),
        "global_loss": round(agg_loss, 4),
        "global_precision": round(agg_prec, 2),
        "global_recall": round(agg_rec, 2),
        "global_f1": round(agg_f1, 2),
        "last_weight_delta": weight_delta,
        "last_aggregation_time": datetime.now().strftime("%H:%M:%S")
    })

    for cid in client_registry:
        client_registry[cid]["model_version"] = new_version

    participants = ", ".join(client_registry.keys())
    round_history.append({
        "round": curr_round,
        "version": new_version,
        "accuracy": fl_overview["global_accuracy"],
        "loss": fl_overview["global_loss"],
        "active_clients": f"{len(client_registry)}/{len(client_registry)}",
        "participants": participants,
        "total_samples": total_samples,
        "weight_delta": weight_delta,
        "timestamp": fl_overview["last_aggregation_time"]
    })

    write_audit_log(
        f"[{timestamp}] [FEDAVG_ROUND_{curr_round}] Model: {new_version} | "
        f"Clients: {participants} | Global Acc: {fl_overview['global_accuracy']}% | Loss: {fl_overview['global_loss']}"
    )

    # Return Updated Global Model back to Client (Step 5 of Client Pipeline)
    return jsonify({
        "message": f"FedAvg Round {curr_round} complete",
        "global_model_version": new_version,
        "round": curr_round,
        "global_accuracy": fl_overview["global_accuracy"],
        "global_loss": fl_overview["global_loss"],
        "global_weights": [w.tolist() for w in global_model.get_weights()]
    }), 200

# ==============================================================================
# 4. RECEIVE PRIVACY-PRESERVING DETECTION TELEMETRY (Step 6 of Client Pipeline)
#    Expects Exact Format:
#    {
#        "client_id": "Client_01",
#        "malware_type": "Trojan",
#        "timestamp": "2026-10-28",
#        "prediction_confidence": 0.96
#    }
# ==============================================================================
@app.route('/api/detection_report', methods=['POST'])
def receive_detection_report():
    data = request.json or {}
    client_id = data.get("client_id", "Client_01")
    malware_type = str(data.get("malware_type", "Unknown")).strip()
    date_str = data.get("timestamp", datetime.now().strftime("%Y-%m-%d"))
    confidence = float(data.get("prediction_confidence", 0.0))
    time_now = datetime.now().strftime("%H:%M:%S")

    if client_id in client_registry:
        client_registry[client_id]["detections_sent"] += 1
        client_registry[client_id]["latest_prediction"] = f"{malware_type} ({confidence*100:.1f}%)"
        client_registry[client_id]["last_seen"] = time_now

    detection_logs.insert(0, {
        "client_id": client_id,
        "malware_type": malware_type,
        "timestamp": f"{date_str} {time_now}",
        "prediction_confidence": round(confidence, 4),
        "confidence_pct": f"{confidence * 100:.1f}%",
        "model_version": fl_overview["global_model_version"]
    })

    write_audit_log(
        f"[{date_str} {time_now}] [{client_id}] malware_type: {malware_type} | prediction_confidence: {confidence}"
    )
    return jsonify({"status": "logged"}), 200

# ==============================================================================
# 5. DASHBOARD WITH DYNAMICALLY AGGREGATED MALWARE STATISTICS
# ==============================================================================
@app.route('/')
@login_required
def dashboard():
    total_scans = len(detection_logs)
    benign_logs = [d for d in detection_logs if d["malware_type"].lower() == "benign"]
    malware_logs = [d for d in detection_logs if d["malware_type"].lower() != "benign"]
    malware_total = len(malware_logs)
    benign_total = len(benign_logs)

    # Dynamically count whatever malware_type classes the Neural Network predicted!
    malware_counter = Counter(d["malware_type"] for d in malware_logs)
    sorted_types = malware_counter.most_common()

    dynamic_malware_stats = []
    for mtype, count in sorted_types:
        pct = round((count / malware_total) * 100.0, 1) if malware_total > 0 else 0.0
        dynamic_malware_stats.append({
            "type": mtype,
            "count": count,
            "percentage": pct
        })

    client_list = [
        {k: v for k, v in c.items() if k != "weights"}
        for c in client_registry.values()
    ]

    return render_template(
        'index.html',
        user=session.get('user'),
        overview=fl_overview,
        clients=client_list,
        rounds=list(reversed(round_history)),
        logs=detection_logs,
        total_scans=total_scans,
        malware_total=malware_total,
        benign_total=benign_total,
        malware_stats=dynamic_malware_stats,
        malware_labels=[m["type"] for m in dynamic_malware_stats],
        malware_counts=[m["count"] for m in dynamic_malware_stats],
        round_labels=[f"Round {r['round']}" for r in round_history],
        round_accuracies=[r["accuracy"] for r in round_history],
        round_losses=[r["loss"] for r in round_history],
        contrib_labels=[c["client_id"] for c in client_list],
        contrib_samples=[c["num_samples"] for c in client_list],
        contrib_accs=[c["local_accuracy"] for c in client_list]
    )

@app.route('/api/export_logs')
@login_required
def export_logs():
    if not os.path.exists(LOG_FILE):
        write_audit_log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INIT] Log initialized.")
    return send_file(LOG_FILE, as_attachment=True, download_name="federated_security_audit.log")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)