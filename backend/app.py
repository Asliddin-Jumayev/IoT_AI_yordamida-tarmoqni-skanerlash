"""AIoT REAL monitoring - Flask API + IPS (Block/Unblock). Ishga tushirish: sudo venv/bin/python app.py"""
import os, json
from flask import Flask, jsonify, request
from monitor import Monitor, default_cidr

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = os.getenv("AIOT_TOKEN", "")
app = Flask(__name__)
mon = Monitor()


@app.after_request
def cors(r):
    r.headers.update({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type,X-Token",
                      "Access-Control-Allow-Methods": "GET,POST,OPTIONS"})
    return r


def denied():
    return TOKEN and request.headers.get("X-Token") != TOKEN


@app.get("/api/health")
def health():
    return jsonify(status="ok", sniffing=mon.sniffing)


@app.get("/api/tick")
def tick():
    return jsonify(mon.snapshot())


@app.get("/api/model")
def model():
    p = os.path.join(HERE, "real_results.json")
    return jsonify(json.load(open(p)) if os.path.exists(p) else {})


@app.post("/api/scan")
def scan():
    if denied():
        return jsonify(error="Token noto'g'ri"), 403
    try:
        n = mon.scan((request.get_json(silent=True) or {}).get("cidr") or None)
        return jsonify(found=n, method=mon.scan_info["method"])
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.post("/api/add_device")
def add_device():
    if denied():
        return jsonify(error="Token noto'g'ri"), 403
    ip = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    if not mon.add_manual(ip):
        return jsonify(error="Noto'g'ri IP manzil"), 400
    return jsonify(ok=True, ip=ip)


@app.post("/api/ingest")
def ingest():
    if denied():
        return jsonify(error="Token noto'g'ri"), 403
    d = request.get_json(silent=True) or {}
    ip = d.get("ip") or request.remote_addr
    mon.add_agent(ip, d.get("device"), d.get("cpu"), d.get("mem"))
    return jsonify(ok=True, ip=ip)


@app.post("/api/block")
def block_ip():
    if denied():
        return jsonify(error="Token noto'g'ri"), 403
    ip = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    ok, msg = mon.block(ip)
    return jsonify(ok=ok, message=msg)


@app.post("/api/unblock")
def unblock_ip():
    if denied():
        return jsonify(error="Token noto'g'ri"), 403
    ip = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    ok, msg = mon.unblock(ip)
    return jsonify(ok=ok, message=msg)


if __name__ == "__main__":
    mon.start()
    print(f"[+] Model: {mon.model_file} | tarmoq: {default_cidr()} | oyna: {mon.snapshot()['info']['window']}s")
    app.run(host=os.getenv("AIOT_HOST", "127.0.0.1"), port=5000, debug=False, threaded=True)