"""
AIoT REAL monitoring - Flask API + IPS (Block/Unblock) + SSE Real-Time Stream + Security Audit Report.
Ishga tushirish: sudo venv/bin/python app.py
"""
import os, json, time
from flask import Flask, jsonify, request, Response
from monitor import Monitor, default_cidr

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = os.getenv("AIOT_TOKEN", "")
app = Flask(__name__)
mon = Monitor()


@app.after_request
def cors(r):
    r.headers.update({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type,X-Token",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
    })
    return r


def denied():
    return TOKEN and request.headers.get("X-Token") != TOKEN


@app.get("/api/health")
def health():
    return jsonify(status="ok", sniffing=mon.sniffing, zero_day=mon.model_iso is not None)


@app.get("/api/tick")
def tick():
    return jsonify(mon.snapshot())


@app.get("/api/stream")
def sse_stream():
    """Server-Sent Events (SSE) orqali real vaqtda hodisalar va ma'lumotlarni oqim (stream) sifatida uzatish"""
    def event_stream():
        q = mon.subscribe()
        try:
            # Dastlabki holatni yuborish
            initial_data = json.dumps(mon.snapshot())
            yield f"event: tick\ndata: {initial_data}\n\n"
            while True:
                if q:
                    event_type, payload = q.popleft()
                    data_str = json.dumps(payload)
                    yield f"event: {event_type}\ndata: {data_str}\n\n"
                else:
                    time.sleep(0.5)
        except GeneratorExit:
            mon.unsubscribe(q)
        except Exception:
            mon.unsubscribe(q)

    return Response(event_stream(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no"
    })


@app.get("/api/model")
def model():
    p = os.path.join(HERE, "real_results.json")
    return jsonify(json.load(open(p)) if os.path.exists(p) else {})


@app.get("/api/report")
def report():
    fmt = request.args.get("format", "json").lower()
    rep = mon.generate_report()
    if fmt == "html":
        attacks_html = "".join(f"<li><b>{k.upper()}:</b> {v} ta</li>" for k, v in rep["attack_summary"].items()) or "<li>Hujumlar qayd etilmadi</li>"
        devs_html = "".join(f"<tr><td>{d['ip']}</td><td>{d['mac']}</td><td>{d['vendor'] or '—'}</td><td>{d['status']}</td><td>{d['pkts_s']} p/s</td></tr>" for d in rep["devices"])
        html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>{rep['title']}</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 30px; }}
.card {{ background: #131b2e; border: 1px solid #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
h1, h2 {{ color: #00f2fe; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ border: 1px solid #1e293b; padding: 10px; text-align: left; }}
th {{ background: #1a243b; color: #00f59b; }}
</style>
</head>
<body>
<h1>🛡️ {rep['title']}</h1>
<div class="card">
  <p><b>Hosil qilingan vaqt:</b> {rep['generated_at']}</p>
  <p><b>Server IP:</b> {rep['server_ip']} | <b>Tarmoq interfeysi:</b> {rep['interface'] or 'avto'}</p>
  <p><b>Jami qurilmalar:</b> {rep['total_devices']} ta (Online: {rep['online_devices']} ta) | <b>Anomaliyalar:</b> {rep['anomalous_devices']} ta</p>
  <p><b>Bloklangan IP manzillar:</b> {', '.join(rep['blocked_ips']) if rep['blocked_ips'] else "Yo'q"}</p>
</div>
<div class="card">
  <h2>⚔️ Aniqlangan Hujumlar Taqsimoti</h2>
  <ul>{attacks_html}</ul>
</div>
<div class="card">
  <h2>💻 Tarmoqdagi Qurilmalar Ro'yxati</h2>
  <table>
    <thead><tr><th>IP Manzil</th><th>MAC Manzil</th><th>Ishlab Chiqaruvchi</th><th>Holati</th><th>Trafik Tezligi</th></tr></thead>
    <tbody>{devs_html}</tbody>
  </table>
</div>
</body>
</html>"""
        return Response(html, mimetype="text/html")
    return jsonify(rep)


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
    port = int(os.getenv("AIOT_PORT", 5000))
    host = os.getenv("AIOT_HOST", "127.0.0.1")
    print(f"[+] AIoT NIDS Server ishga tushdi: http://{host}:{port}")
    print(f"[+] Model: {mon.model_file} | Zero-Day: {'Faol' if mon.model_iso else 'Ochiq'} | Tarmoq: {default_cidr()}")
    app.run(host=host, port=port, debug=False, threaded=True)
