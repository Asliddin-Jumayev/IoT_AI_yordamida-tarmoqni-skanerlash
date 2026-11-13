"""
monitor.py - REAL tarmoq monitoringi
  1) Qurilmalarni topish (ARP scan, zaxira: ping sweep + ARP jadvali)
  2) Ping orqali online/latency
  3) Paketlarni tutish (scapy) -> oqimlarga (flow) yig'ish -> xususiyatlar -> Random Forest
Faqat O'ZINGIZNING tarmog'ingizda ishlating.
"""
import os, re, time, socket, platform, subprocess, threading, ipaddress, collections
from concurrent.futures import ThreadPoolExecutor
import joblib, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOW = float(os.getenv("AIOT_WINDOW", 5))          # oqimlarni tahlil qilish oralig'i (soniya)
THRESH = float(os.getenv("AIOT_THRESHOLD", 0.8))     # 1 - P(normal) shu qiymatdan katta bo'lsa oqim gumonli
MIN_FLOWS = int(os.getenv("AIOT_MIN_FLOWS", 3))      # qurilma "anomaliya" bo'lishi uchun oynada kamida shuncha gumonli oqim
SCAN_PORTS = int(os.getenv("AIOT_SCAN_PORTS", 20))   # bitta manba oynada kamida shuncha TURLI portga murojaat qilsa -> skanerlash
FLOOD_PPS = float(os.getenv("AIOT_FLOOD_PPS", 200))  # bitta manbadan paket/soniya shundan oshsa -> DoS (ko'p manba bo'lsa DDoS)
SERVICE = {53: "dns", 80: "http", 443: "ssl", 21: "ftp", 67: "dhcp", 68: "dhcp", 445: "smb"}
ACTION = {"ddos": "Paket tezligini cheklang (rate-limit), manba IP larni bloklang.",
          "dos": "Manba IP ni bloklang, qurilma servisini tekshiring.",
          "scanning": "Port skanerlash: manba IP ni bloklang, keraksiz portlarni yoping.",
          "backdoor": "Qurilmani tarmoqdan ajrating, firmware va parolni yangilang.",
          "password": "Parol tanlash (brute-force): parolni almashtiring, kirishni cheklang.",
          "injection": "Veb-interfeysni yangilang, tashqi kirishni yoping.",
          "xss": "Veb-interfeysni yangilang, tashqi kirishni yoping.",
          "ransomware": "Qurilmani zudlik bilan ajrating, zaxira nusxadan tiklang.",
          "mitm": "ARP jadvalini tekshiring, shubhali qurilmani toping."}


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))   # paket yuborilmaydi, faqat marshrut aniqlanadi
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def default_cidr():
    return str(ipaddress.ip_network(local_ip() + "/24", strict=False))


def ping(ip):
    sysname = platform.system()
    cmd = (["ping", "-n", "1", "-w", "1000", ip] if sysname == "Windows" else
           ["ping", "-c", "1", "-W", "1000" if sysname == "Darwin" else "1", ip])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=4).stdout
    except Exception:
        return None
    m = re.search(r"time[=<]\s*([\d.]+)", out)
    return float(m.group(1)) if m else None


def default_iface():
    try:
        from scapy.all import conf
        return conf.iface
    except Exception:
        return None


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def arp_scan(cidr):
    """{ip: mac}. Avval scapy ARP (root/Admin kerak), bo'lmasa ping sweep + `arp -a`."""
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr), timeout=3, retry=1, verbose=0)
        return {r.psrc: r.hwsrc for _, r in ans}, "scapy-ARP"
    except Exception:
        hosts = [str(h) for h in ipaddress.ip_network(cidr, strict=False).hosts()]
        with ThreadPoolExecutor(64) as ex:
            list(ex.map(ping, hosts))
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
        found = {}
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+).*?((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})", out):
            if ipaddress.ip_address(m.group(1)) in ipaddress.ip_network(cidr, strict=False):
                found[m.group(1)] = m.group(2).replace("-", ":").lower()
        return found, "ping+arp-jadvali"


class Monitor:
    def __init__(self):
        path = next((p for p in (os.getenv("AIOT_MODEL"), os.path.join(HERE, "model_live.joblib"),
                                 os.path.join(HERE, "model_real.joblib")) if p and os.path.exists(p)), None)
        if not path:
            raise SystemExit("Model topilmadi. Avval: python train_real.py")
        b = joblib.load(path)
        self.model, self.features, self.cats = b["model"], b["features"], b["categories"]
        self.classes = list(self.model.classes_)
        self.ni = self.classes.index("normal")
        self.model_file = os.path.basename(path)
        self.devices, self.flows, self.events = {}, {}, collections.deque(maxlen=60)
        self.stats = {"packets": 0, "flows": 0, "suspicious": 0}
        self.lock = threading.RLock()
        self.sniffing, self.sniff_error, self.scan_info = False, None, {"method": None, "cidr": default_cidr(), "at": None}
        self.me = local_ip()

    # ---------- 1. Qurilmalarni topish ----------
    def _dev(self, ip, mac="", **kw):
        d = self.devices.setdefault(ip, dict(ip=ip, mac=mac, name="", vendor="", online=None, rtt=None, pkts_s=0, bytes_s=0,
                                             flows=0, remotes=0, avg_size=0, cpu=None, mem=None, status="Normal", score=0.0,
                                             src="scan", last_attack="", action="", seen=time.time()))
        if mac:
            d["mac"] = mac
        d.update(kw)
        return d

    def scan(self, cidr=None):
        cidr = cidr or self.scan_info["cidr"]
        self.me = local_ip()   # tarmoq o'zgargan bo'lsa, o'z IP'ni ham yangilaymiz
        net = ipaddress.ip_network(cidr, strict=False)
        with self.lock:
            # Boshqa (eski) tarmoqqa tegishli, ARP skanerdan qo'shilgan qurilmalarni tozalaymiz.
            # Agentdan (haqiqiy telemetriya yuborgan qurilma) kelganlarga tegmaymiz.
            stale = [ip for ip, d in self.devices.items()
                     if d["src"] == "scan" and ipaddress.ip_address(ip) not in net]
            for ip in stale:
                del self.devices[ip]
        found, method = arp_scan(cidr)
        found.setdefault(self.me, "")
        with ThreadPoolExecutor(16) as ex:
            names = dict(zip(found, ex.map(hostname, found)))
        for ip, mac in found.items():
            vendor = ""
            try:
                from scapy.all import conf
                vendor = conf.manufdb._get_manuf(mac) if mac else ""
            except Exception:
                pass
            with self.lock:
                self._dev(ip, mac, name=names.get(ip) or ("Shu kompyuter" if ip == self.me else ""), vendor=vendor or "")
        self.scan_info = {"method": method, "cidr": cidr, "at": time.strftime("%H:%M:%S")}
        return len(found)

    # ---------- 2. Ping ----------
    def _ping_loop(self):
        while True:
            ips = list(self.devices)
            with ThreadPoolExecutor(16) as ex:
                for ip, rtt in zip(ips, ex.map(ping, ips)):
                    with self.lock:
                        if ip in self.devices and self.devices[ip]["src"] == "scan":
                            self.devices[ip].update(rtt=rtt, online=rtt is not None)
            time.sleep(WINDOW)

    # ---------- 3. Paketlar -> oqimlar ----------
    def _packet(self, p):
        from scapy.all import IP, TCP, UDP, ICMP
        if IP not in p:
            return
        l4 = p[TCP] if TCP in p else p[UDP] if UDP in p else p[ICMP] if ICMP in p else None
        if l4 is None:
            return
        proto = "tcp" if TCP in p else "udp" if UDP in p else "icmp"
        sp, dp = (l4.sport, l4.dport) if proto != "icmp" else (0, 0)
        src, dst = p[IP].src, p[IP].dst
        if src not in self.devices and dst not in self.devices:
            return
        now, plen, pay = time.time(), len(p[IP]), len(l4.payload)
        flags = int(l4.flags) if proto == "tcp" else 0
        key = (proto,) + tuple(sorted([(src, sp), (dst, dp)]))
        with self.lock:
            f = self.flows.get(key)
            if f is None:
                f = self.flows[key] = dict(orig=src, resp=dst, odport=dp, proto=proto, t0=now, t1=now, sb=0, rb=0, sp=0, rp=0,
                                           sib=0, rib=0, fo=0, fr=0)
            f["t1"] = now
            side = "o" if src == f["orig"] else "r"
            f["sp" if side == "o" else "rp"] += 1
            f["sb" if side == "o" else "rb"] += pay
            f["sib" if side == "o" else "rib"] += plen
            f["f" + side] |= flags
            self.stats["packets"] += 1

    @staticmethod
    def _conn_state(f):
        if f["proto"] != "tcp":
            return "SF" if f["rp"] else "S0"
        if f["fr"] & 4:
            return "REJ" if f["sb"] == 0 else "RSTR"
        if f["fo"] & 4:
            return "RSTO"
        if not f["rp"]:
            return "S0"
        return "SF" if (f["fo"] | f["fr"]) & 1 else "S1"

    def _code(self, col, val):
        c = self.cats[col]
        return c.index(val) if val in c else -1

    def _row(self, f):
        dur, sp = max(f["t1"] - f["t0"], 0.0), max(f["sp"], 1)
        r = dict(duration=dur, bytes_sent=f["sb"], bytes_received=f["rb"], packets_sent=f["sp"], packets_received=f["rp"],
                 packet_size=f["sib"] / sp, packet_rate=f["sp"] / max(dur, 1e-3), missed_bytes=0, dst_port=f["odport"],
                 proto=self._code("proto", f["proto"]),
                 service=self._code("service", SERVICE.get(f["odport"], "-")),
                 conn_state=self._code("conn_state", f.get("conn_state") or self._conn_state(f)))
        return [r[c] for c in self.features]

    def _flush_loop(self):
        while True:
            time.sleep(WINDOW)
            with self.lock:
                flows, self.flows = list(self.flows.values()), {}
            try:
                self.analyze(flows)
            except Exception as e:
                self.events.appendleft(dict(t=time.strftime("%H:%M:%S"), level=0, text=f"Tahlil xatosi: {e}", action=""))

    # ---------- 4. Model ----------
    def analyze(self, flows):
        acc = collections.defaultdict(lambda: dict(pk=0, by=0, fl=0, rem=set(), bad=[]))
        inb = collections.defaultdict(lambda: collections.defaultdict(lambda: dict(ports=set(), pk=0)))  # qoidalar uchun
        if flows:
            P = self.model.predict_proba(pd.DataFrame([self._row(f) for f in flows], columns=self.features))
            for f, pr in zip(flows, P):
                label, score = self.classes[pr.argmax()], 1 - pr[self.ni]
                bad = label != "normal" and score >= THRESH
                self.stats["flows"] += 1
                self.stats["suspicious"] += int(bad)
                for dev, other in ((f["orig"], f["resp"]), (f["resp"], f["orig"])):
                    if dev in self.devices:
                        a = acc[dev]
                        a["pk"] += f["sp"] + f["rp"]; a["by"] += f["sib"] + f["rib"]; a["fl"] += 1; a["rem"].add(other)
                        if bad:
                            a["bad"].append((score, label, other, f["odport"]))
                        if dev == f["resp"]:                      # qurilmaga KIRUVCHI trafik
                            inb[dev][other]["ports"].add(f["odport"]); inb[dev][other]["pk"] += f["sp"]
        t = time.strftime("%H:%M:%S")
        with self.lock:
            for ip, d in self.devices.items():
                a = acc.get(ip)
                prev = d["status"]
                if a:
                    d.update(pkts_s=round(a["pk"] / WINDOW, 1), bytes_s=round(a["by"] / WINDOW), flows=a["fl"], remotes=len(a["rem"]),
                             avg_size=round(a["by"] / max(a["pk"], 1)))
                else:
                    d.update(pkts_s=0, bytes_s=0, flows=0, remotes=0, avg_size=0)
                verdict, rr = None, inb.get(ip)
                if rr:
                    src_scan, v = max(rr.items(), key=lambda kv: len(kv[1]["ports"]))
                    top_src, tv = max(rr.items(), key=lambda kv: kv[1]["pk"])
                    total = sum(x["pk"] for x in rr.values()) / WINDOW
                    if len(v["ports"]) >= SCAN_PORTS:
                        verdict = ("scanning", 1.0, f"{src_scan} {len(v['ports'])} ta turli portga murojaat qildi [qoida]")
                    elif tv["pk"] / WINDOW >= FLOOD_PPS:
                        verdict = ("dos", 1.0, f"{top_src} dan {tv['pk']/WINDOW:.0f} paket/s [qoida]")
                    elif total >= FLOOD_PPS and len(rr) >= 5:
                        verdict = ("ddos", 1.0, f"{len(rr)} ta manbadan jami {total:.0f} paket/s [qoida]")
                if not verdict and a and len(a["bad"]) >= MIN_FLOWS:
                    cnt = collections.Counter(x[1] for x in a["bad"])
                    lab = cnt.most_common(1)[0][0]
                    top = max(a["bad"], key=lambda x: x[0])
                    verdict = (lab, max(x[0] for x in a["bad"] if x[1] == lab),
                               f"{len(a['bad'])} ta gumonli oqim, masalan {top[2]}:{top[3]} [model]")
                if verdict:
                    lab, sc, det = verdict
                    d.update(status=lab, score=round(float(sc), 3), action=ACTION.get(lab, ""))
                    if prev != lab:
                        self.events.appendleft(dict(t=t, level=1, action=ACTION.get(lab, ""),
                                                    text=f"{d['name'] or ip} ({ip}): {lab} gumon, ishonch {sc*100:.0f}%, {det}"))
                else:
                    d.update(status="Normal", score=0.0, action="")
                    if prev != "Normal":
                        self.events.appendleft(dict(t=t, level=0, text=f"{d['name'] or ip} ({ip}): normal holatga qaytdi.", action=""))

    def add_manual(self, ip):
        """ARP ishlamagan holatlarda (masalan AP isolation), qo'lda, IP bo'yicha qurilma qo'shish."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
        with self.lock:
            self._dev(ip, "", name="", src="manual")
        return True

    # ---------- Agent telemetriyasi (CPU/RAM) ----------
    def add_agent(self, ip, name, cpu, mem):
        with self.lock:
            self._dev(ip, name=name or ip, cpu=cpu, mem=mem, online=True, src="agent" if ip not in self.devices else self.devices[ip]["src"])

    # ---------- Ishga tushirish ----------
    def _sniff_loop(self):
        from scapy.all import sniff
        iface = os.getenv("AIOT_IFACE") or None
        for flt in ("ip", None):
            try:
                self.sniffing, self.sniff_error = True, None
                sniff(prn=self._packet, store=False, filter=flt, iface=iface)
                return
            except Exception as e:
                self.sniffing, self.sniff_error = False, f"{type(e).__name__}: {e}"

    def start(self):
        threading.Thread(target=self.scan, daemon=True).start()
        for fn in (self._ping_loop, self._flush_loop, self._sniff_loop):
            threading.Thread(target=fn, daemon=True).start()

    def snapshot(self):
        with self.lock:
            devs = sorted(self.devices.values(), key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
            return dict(devices=[dict(d) for d in devs], events=list(self.events), stats=dict(self.stats),
                        info=dict(sniffing=self.sniffing, sniff_error=self.sniff_error, window=WINDOW, threshold=THRESH,
                                  min_flows=MIN_FLOWS, scan_ports=SCAN_PORTS, flood_pps=FLOOD_PPS, model=self.model_file, scan=self.scan_info, me=self.me))
