"""
monitor.py - Tshark (Wireshark CLI) + IEEE OUI Vendor + Rich Telegram SOC Bot + Random Forest AI
Faqat O'ZINGIZNING tarmog'ingizda ishlating.
"""
import os, re, time, socket, platform, subprocess, threading, ipaddress, collections, sqlite3, urllib.request, urllib.error, json
from concurrent.futures import ThreadPoolExecutor
import joblib, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))

# ==============================================================================
# TELEGRAM BOT SOZLAMALARI (Token va Chat ID ni shu yerga yozib qo'ying)
# ==============================================================================
DEFAULT_BOT_TOKEN = ""
DEFAULT_CHAT_ID = ""

TELEGRAM_BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or DEFAULT_BOT_TOKEN).strip()
TELEGRAM_CHAT_ID = (os.getenv("TELEGRAM_CHAT_ID") or DEFAULT_CHAT_ID).strip()
# ==============================================================================

WINDOW = float(os.getenv("AIOT_WINDOW", 5))          # Oqimlarni tahlil qilish oralig'i (soniya)
THRESH = float(os.getenv("AIOT_THRESHOLD", 0.91))    # Model ishonch chegarasi
MIN_FLOWS = int(os.getenv("AIOT_MIN_FLOWS", 4))      # Anomaliya uchun minimal oqimlar
SCAN_PORTS = int(os.getenv("AIOT_SCAN_PORTS", 20))   # Port skanerlash chegarasi
FLOOD_PPS = float(os.getenv("AIOT_FLOOD_PPS", 200))  # DoS paket tezligi chegarasi

SERVICE = {
    53: "dns", 80: "http", 443: "ssl", 21: "ftp", 22: "ssh", 67: "dhcp", 68: "dhcp", 445: "smb",
    1883: "mqtt", 8883: "ssl", 5683: "coap", 554: "rtsp", 5353: "mdns"
}

ACTION = {
    "ddos": "Paket tezligini cheklang (rate-limit), manba IP larni bloklang.",
    "dos": "Manba IP ni bloklang, qurilma servisini tekshiring.",
    "scanning": "Port skanerlash: manba IP ni bloklang, keraksiz portlarni yoping.",
    "backdoor": "Qurilmani tarmoqdan ajrating, firmware va parolni yangilang.",
    "password": "Parol tanlash (brute-force): parolni almashtiring, kirishni cheklang.",
    "injection": "Veb-interfeysni yangilang, tashqi kirishni yoping.",
    "xss": "Veb-interfeysni yangilang, tashqi kirishni yoping.",
    "ransomware": "Qurilmani zudlik bilan ajrating, zaxira nusxadan tiklang.",
    "mitm": "ARP jadvalini tekshiring, shubhali qurilmani toping."
}

ATTACK_META = {
    "ddos":       ("🔴 O'TA XAVFLI (CRITICAL)", "🌊 DDoS (Distributed Flood)"),
    "dos":        ("🔴 O'TA XAVFLI (CRITICAL)", "💥 DoS (Oqim To'ldirish Hujumi)"),
    "ransomware": ("🔴 O'TA XAVFLI (CRITICAL)", "☣️ Ransomware (Shifrlovchi Zararkunanda)"),
    "backdoor":   ("🔴 O'TA XAVFLI (CRITICAL)", "🚪 Backdoor (Yashirin Kirish)"),
    "mitm":       ("🟠 YUQORI XAVF (HIGH)",     "🕵️ MITM (Trafikni Tutib Olish)"),
    "injection":  ("🟠 YUQORI XAVF (HIGH)",     "💉 Kod / SQL Injection"),
    "xss":        ("🟠 YUQORI XAVF (HIGH)",     "🌐 Cross-Site Scripting (XSS)"),
    "password":   ("🟠 YUQORI XAVF (HIGH)",     "🔑 Parol Tanlash (Brute-Force)"),
    "scanning":   ("🟡 O'RTA XAVF (RECON)",     "🔍 Port va Xizmatlarni Skanerlash"),
}

DEVICE_TYPE_HINTS = [
    (["apple"], "📱 Apple (iPhone/Mac)"),
    (["samsung"], "📱 Samsung Galaxy"),
    (["xiaomi", "redmi", "poco"], "📱 Xiaomi / Redmi"),
    (["huawei", "honor"], "📱 Huawei / Honor"),
    (["oneplus", "oppo", "realme", "vivo", "bbk"], "📱 Smartfon (BBK)"),
    (["google", "pixel"], "📱 Google Pixel"),
    (["raspberry"], "🍓 Raspberry Pi"),
    (["espressif"], "🔌 IoT (ESP32/ESP8266)"),
    (["tuya", "sonoff", "shelly"], "🏠 Aqlli Uy (IoT)"),
    (["hikvision", "dahua", "axis", "ezviz"], "📹 IP Kamera"),
    (["tp-link", "routerboard", "netgear", "d-link", "ubiquiti", "cisco", "mikrotik", "zyxel", "tenda", "asus", "huawei tech"], "📡 Router / Tarmoq uskunasi"),
    (["intel", "realtek", "qualcomm", "broadcom", "atheros", "dell", "lenovo", "hewlett", "hp", "asustek", "acer", "msi", "gigabyte", "microsoft", "liteon", "azurewave", "mediatek"], "💻 Noutbuk / Kompyuter"),
]

OUI_DB = {}
def _load_oui_db():
    paths = ["/usr/share/wireshark/manuf", "/usr/share/ieee-data/oui.txt", "/etc/manuf"]
    for p in paths:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            prefix = parts[0].strip().lower().replace("-", ":")[:8]
                            vendor = parts[-1].strip() or parts[1].strip()
                            if len(prefix) == 8:
                                OUI_DB[prefix] = vendor
                if OUI_DB:
                    break
            except Exception:
                pass

_load_oui_db()

def is_randomized_mac(mac):
    if not mac or len(mac) < 2:
        return False
    return mac[1].lower() in ("2", "6", "a", "e")

def resolve_vendor(mac):
    if not mac or len(mac) < 8:
        return ""
    m = mac.lower().replace("-", ":")
    prefix = m[:8]
    if prefix in OUI_DB:
        return OUI_DB[prefix]
    try:
        from scapy.all import conf
        v = conf.manufdb._get_manuf(m)
        if v and v != m:
            return v
    except Exception:
        pass
    if is_randomized_mac(m):
        return "Maxfiy (Random MAC)"
    return ""

def guess_device_type(vendor, mac="", is_me=False):
    if is_me:
        return "💻 Shu kompyuter (Server)"
    v = (vendor or "").lower()
    for keys, label in DEVICE_TYPE_HINTS:
        if any(k in v for k in keys):
            return label
    if is_randomized_mac(mac):
        return "📱 Smartfon / Noutbuk (Random MAC)"
    return "❓ Noma'lum qurilma" if vendor else "—"

def confidence_bar(score):
    pct = max(0, min(100, int(round(score * 100))))
    filled = pct // 10
    return f"{'▓' * filled}{'░' * (10 - filled)} {pct}%"

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def local_mac_and_iface(target_ip):
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, timeout=2).stdout
        iface = None
        for line in out.splitlines():
            if target_ip in line:
                iface = line.split()[1]
                break
        if iface:
            mac_path = f"/sys/class/net/{iface}/address"
            if os.path.exists(mac_path):
                return open(mac_path).read().strip().lower(), iface
    except Exception:
        pass
    return "", None

def local_cpu_mem():
    try:
        import psutil
        return round(psutil.cpu_percent(interval=None), 1), round(psutil.virtual_memory().percent, 1)
    except Exception:
        try:
            mem_total, mem_avail = 1, 0
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_total = int(line.split()[1])
                    elif line.startswith("MemAvailable:"):
                        mem_avail = int(line.split()[1])
            mem_pct = round((1 - mem_avail / max(mem_total, 1)) * 100, 1)
            load1 = os.getloadavg()[0]
            cpus = os.cpu_count() or 1
            cpu_pct = min(100.0, round((load1 / cpus) * 100, 1))
            return cpu_pct, mem_pct
        except Exception:
            return None, None

def default_cidr():
    return str(ipaddress.ip_network(local_ip() + "/24", strict=False))

def ping(ip):
    sysname = platform.system()
    cmd = (["ping", "-n", "1", "-w", "1000", ip] if sysname == "Windows" else
           ["ping", "-c", "1", "-W", "1000" if sysname == "Darwin" else "1", ip])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return None
    m = re.search(r"time[=<]\s*([\d.]+)", out)
    return float(m.group(1)) if m else None

def hostname(ip):
    try:
        h = socket.gethostbyaddr(ip)[0]
        if h and h != ip:
            return h.split(".")[0]
    except Exception:
        pass
    try:
        out = subprocess.run(["avahi-resolve-address", ip], capture_output=True, text=True, timeout=1.0).stdout
        if out and "\t" in out:
            return out.strip().split("\t")[-1].replace(".local", "")
    except Exception:
        pass
    try:
        out = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=1.0).stdout
        m = re.search(r"^\s*([A-Za-z0-9_-]+)\s+<00>\s+-\s+B", out, re.M)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""

def arp_scan(cidr):
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr), timeout=2, retry=1, verbose=0)
        return {r.psrc: r.hwsrc.lower() for _, r in ans}, "scapy-ARP"
    except Exception:
        hosts = [str(h) for h in ipaddress.ip_network(cidr, strict=False).hosts()]
        with ThreadPoolExecutor(32) as ex:
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
        self.devices, self.flows, self.events = {}, {}, collections.deque(maxlen=80)
        self.packet_buffer = collections.deque(maxlen=150)
        self.stats = {"packets": 0, "flows": 0, "suspicious": 0}
        self.lock = threading.RLock()
        self.sniffing, self.sniff_error, self.scan_info = False, None, {"method": None, "cidr": default_cidr(), "at": None}
        self.me = local_ip()
        self.my_mac, self.my_iface = local_mac_and_iface(self.me)
        self.blocked = set()
        self.tg_offset = 0
        self.db_path = os.path.join(HERE, "aiot_events.db")
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT, level INTEGER, ip TEXT, label TEXT, text TEXT, action TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _save_event_db(self, ev):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("INSERT INTO events (time, level, ip, label, text, action) VALUES (?, ?, ?, ?, ?, ?)",
                         (ev.get("t"), ev.get("level", 0), ev.get("ip", ""), ev.get("label", ""), ev.get("text", ""), ev.get("action", "")))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _tg_configured(self):
        return bool(
            TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
            and "BU_YERGA" not in TELEGRAM_BOT_TOKEN
            and "BU_YERGA" not in TELEGRAM_CHAT_ID
        )

    def _tg_api(self, method, payload):
        if not self._tg_configured():
            return None
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _ip_keyboard(self, ip):
        if ip in self.blocked:
            return {"inline_keyboard": [[{"text": f"🔓 Blokdan chiqarish ({ip})", "callback_data": f"unblock:{ip}"}]]}
        return {"inline_keyboard": [[{"text": f"🛑 Bloklash ({ip})", "callback_data": f"block:{ip}"}]]}

    def _format_status_card(self):
        with self.lock:
            devs = list(self.devices.values())
            n_dev = len(devs)
            n_online = sum(1 for d in devs if d.get("online"))
            n_anom = sum(1 for d in devs if d.get("status") != "Normal")
            n_blk = len(self.blocked)
            pkts = self.stats["packets"]
            flows = self.stats["flows"]
            susp = self.stats["suspicious"]
            blk_list = ", ".join(self.blocked) if self.blocked else "Yo'q"

        health_icon = "🔴 XAVF MAVJUD" if n_anom > 0 else "🟢 BARQAROR (TINCH)"
        lines = [
            f"🛡️ <b>AIoT NIDS — MARKAZIY HOLAT PANELI</b>",
            f"━━━━━━━━━━━━━━━━━━━━",
            f"📡 <b>Tizim holati:</b> {health_icon}",
            f"💻 <b>Jami qurilmalar:</b> <b>{n_dev} ta</b> (Online: {n_online} ta)",
            f"⚠️ <b>Faol anomaliyalar:</b> <b>{n_anom} ta</b>",
            f"📦 <b>Tutilgan paketlar:</b> <code>{pkts:,}</code>",
            f"🔬 <b>Tahlil qilingan oqim:</b> <code>{flows:,}</code> (Gumonli: {susp:,})",
            f"🛑 <b>Bloklangan IP ({n_blk} ta):</b> <code>{blk_list}</code>",
            f"🕒 <b>Yangilangan vaqt:</b> <code>{time.strftime('%H:%M:%S')}</code>",
            f"━━━━━━━━━━━━━━━━━━━━"
        ]
        return "\n".join(lines)

    def _send_telegram_attack(self, dev, lab, sc, det, target_ip=None):
        """Hujum boshlanganda xavf darajasiga mos boyitilgan ogohlantirish kartochkasini yuborish"""
        if not self._tg_configured():
            return
        try:
            sev_badge, attack_title = ATTACK_META.get(lab, ("🟠 YUQORI XAVF", f"⚡ {lab.upper()} Anomaliyasi"))
            dev_name = dev.get("name") or dev.get("dtype") or "Tarmoq qurilmasi"
            ip = dev["ip"]
            pps = dev.get("pkts_s", 0)
            bps = dev.get("bytes_s", 0)
            bar = confidence_bar(sc)
            rec = ACTION.get(lab, "Tarmoq oqimini tekshiring va shubhali IP manzilni bloklang.")
            is_blk = (target_ip in self.blocked) if target_ip else False
            status_str = "🛑 Bloklangan (iptables DROP)" if is_blk else "🟡 Faol (Bloklanmagan)"

            msg_lines = [
                f"🚨 <b>AIoT NIDS — XAVFSIZLIK OGOHLANTIRISHI!</b>",
                f"━━━━━━━━━━━━━━━━━━━━",
                f"⚠️ <b>Daraja:</b> {sev_badge}",
                f"⚔️ <b>Hujum turi:</b> <b>{attack_title}</b>",
                f"🎯 <b>Qurilma:</b> {dev_name} (<code>{ip}</code>)",
                f"📊 <b>Oqim tezligi:</b> <code>{pps} paket/s</code> | <code>{bps:,} bayt/s</code>",
                f"🧠 <b>AI Ishonchi:</b> <code>{bar}</code>",
                f"🔍 <b>Tahlil:</b> {det}",
                f"🛡️ <b>Tavsiya:</b> <i>{rec}</i>",
                f"🕒 <b>Vaqt:</b> <code>{time.strftime('%H:%M:%S')}</code>",
                f"━━━━━━━━━━━━━━━━━━━━",
                f"📌 <b>Holati:</b> {status_str}"
            ]
            payload = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": "\n".join(msg_lines),
                "parse_mode": "HTML"
            }
            if target_ip and self._blockable(target_ip):
                payload["reply_markup"] = self._ip_keyboard(target_ip)
            self._tg_api("sendMessage", payload)
        except Exception as e:
            print(f"[!] Telegram attack xabar xatosi: {e}")

    def _send_telegram_resolved(self, dev, prev_attack, target_ip=None):
        """Hujum to'xtab, qurilma normal holatga qaytganda yuboriladigan xabar"""
        if not self._tg_configured():
            return
        try:
            _, attack_title = ATTACK_META.get(prev_attack, ("", prev_attack.upper()))
            dev_name = dev.get("name") or dev.get("dtype") or "Tarmoq qurilmasi"
            ip = dev["ip"]
            pps = dev.get("pkts_s", 0)
            is_blk = (target_ip in self.blocked) if target_ip else False
            status_str = "🛑 Bloklangan (iptables DROP)" if is_blk else "🟢 Tinch / Himoyalangan"

            msg_lines = [
                f"🟢 <b>AIoT NIDS — XAVF TO'XTATILDI (TINCH HOLAT)</b>",
                f"━━━━━━━━━━━━━━━━━━━━",
                f"✅ <b>Holat:</b> Qurilma normal ish rejimiga qaytdi",
                f"💻 <b>Qurilma:</b> {dev_name} (<code>{ip}</code>)",
                f"🛡️ <b>Bartaraf etilgan xavf:</b> {attack_title}",
                f"📊 <b>Joriy trafik:</b> <code>{pps} paket/s</code> (Me'yorda)",
                f"🕒 <b>Vaqt:</b> <code>{time.strftime('%H:%M:%S')}</code>",
                f"━━━━━━━━━━━━━━━━━━━━",
                f"📌 <b>Holati:</b> {status_str}"
            ]
            payload = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": "\n".join(msg_lines),
                "parse_mode": "HTML"
            }
            if target_ip and self._blockable(target_ip) and is_blk:
                payload["reply_markup"] = self._ip_keyboard(target_ip)
            self._tg_api("sendMessage", payload)
        except Exception as e:
            print(f"[!] Telegram resolved xabar xatosi: {e}")

    def _telegram_poll_loop(self):
        while True:
            if not self._tg_configured():
                time.sleep(5)
                continue
            try:
                url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates?offset={self.tg_offset}&timeout=10"
                with urllib.request.urlopen(url, timeout=15) as resp:
                    res = json.loads(resp.read().decode("utf-8"))

                for upd in res.get("result", []):
                    self.tg_offset = upd["update_id"] + 1

                    # 1. Inline tugma bosilganda
                    cb = upd.get("callback_query")
                    if cb:
                        data = cb.get("data", "")
                        cb_id = cb.get("id")
                        msg = cb.get("message", {})
                        chat_id = msg.get("chat", {}).get("id")
                        msg_id = msg.get("message_id")

                        if data == "refresh_status" and chat_id and msg_id:
                            try:
                                self._tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": "🔄 Ma'lumotlar yangilandi!"})
                                self._tg_api("editMessageText", {
                                    "chat_id": chat_id,
                                    "message_id": msg_id,
                                    "text": self._format_status_card(),
                                    "parse_mode": "HTML",
                                    "reply_markup": {"inline_keyboard": [[{"text": "🔄 Holatni yangilash", "callback_data": "refresh_status"}]]}
                                })
                            except Exception:
                                pass
                            continue

                        if ":" in data:
                            act, ip = data.split(":", 1)
                            orig_text = msg.get("text", "").split("\n📌")[0].split("\n\n✅")[0]

                            if act == "block":
                                ok, info = self.block(ip)
                                toast_txt = f"🛑 {ip} muvaffaqiyatli bloklandi!" if ok else f"⚠️ Xato: {info}"
                                status_footer = (
                                    f"\n📌 <b>Holati:</b> 🛑 Bloklangan (<code>{ip}</code>)\n"
                                    f"✅ <b>IPS Qoidasi:</b> <code>iptables DROP</code> faol"
                                )
                                confirm_card = (
                                    f"🛑 <b>IPS HIMOYA — QURILMA BLOKLANDI!</b>\n"
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"🎯 <b>Bloklangan manzil:</b> <code>{ip}</code>\n"
                                    f"⚙️ <b>Qo'llanilgan chora:</b> <code>iptables INPUT DROP</code>\n"
                                    f"🕒 <b>Vaqt:</b> <code>{time.strftime('%H:%M:%S')}</code>\n"
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"📌 <b>Holati:</b> 🛑 Bloklangan (Trafik to'xtatilgan)"
                                )
                            else:
                                ok, info = self.unblock(ip)
                                toast_txt = f"🔓 {ip} blokdan chiqarildi!" if ok else f"⚠️ Xato: {info}"
                                status_footer = (
                                    f"\n📌 <b>Holati:</b> 🟢 Faol / Blokdan chiqarilgan (<code>{ip}</code>)"
                                )
                                confirm_card = (
                                    f"🔓 <b>IPS HIMOYA — BLOKDAN CHIQARILDI!</b>\n"
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"🎯 <b>Qurilma manzili:</b> <code>{ip}</code>\n"
                                    f"⚙️ <b>Holat:</b> Cheklov olindi (<code>iptables ACCEPT</code>)\n"
                                    f"🕒 <b>Vaqt:</b> <code>{time.strftime('%H:%M:%S')}</code>\n"
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"📌 <b>Holati:</b> 🟢 Faol (Bloklanmagan)"
                                )

                            try:
                                self._tg_api("answerCallbackQuery", {"callback_query_id": cb_id, "text": toast_txt})
                            except Exception:
                                pass

                            if chat_id and msg_id:
                                try:
                                    self._tg_api("editMessageText", {
                                        "chat_id": chat_id,
                                        "message_id": msg_id,
                                        "text": f"{orig_text}{status_footer}",
                                        "parse_mode": "HTML",
                                        "reply_markup": self._ip_keyboard(ip)
                                    })
                                except Exception:
                                    pass

                                try:
                                    self._tg_api("sendMessage", {
                                        "chat_id": chat_id,
                                        "text": confirm_card,
                                        "parse_mode": "HTML",
                                        "reply_markup": self._ip_keyboard(ip)
                                    })
                                except Exception:
                                    pass

                    # 2. /start va /status buyruqlari
                    m = upd.get("message")
                    if m:
                        txt = m.get("text", "").strip()
                        c_id = m["chat"]["id"]
                        if txt.startswith("/status") or txt.startswith("/start"):
                            self._tg_api("sendMessage", {
                                "chat_id": c_id,
                                "text": self._format_status_card(),
                                "parse_mode": "HTML",
                                "reply_markup": {"inline_keyboard": [[{"text": "🔄 Holatni yangilash", "callback_data": "refresh_status"}]]}
                            })
            except Exception:
                time.sleep(3)

    def _dev(self, ip, mac="", **kw):
        d = self.devices.setdefault(ip, dict(ip=ip, mac=mac, name="", vendor="", dtype="", online=None, rtt=None, pkts_s=0, bytes_s=0,
                                             flows=0, remotes=0, avg_size=0, cpu=None, mem=None, status="Normal", score=0.0,
                                             src="scan", last_attack="", action="", seen=time.time()))
        if mac:
            d["mac"] = mac
        d.update(kw)
        return d

    def scan(self, cidr=None):
        cidr = cidr or self.scan_info["cidr"]
        self.me = local_ip()
        self.my_mac, self.my_iface = local_mac_and_iface(self.me)
        cidr_list = [c.strip() for c in cidr.split(",") if c.strip()]
        nets = [ipaddress.ip_network(c, strict=False) for c in cidr_list]

        with self.lock:
            stale = [ip for ip, d in self.devices.items()
                     if d["src"] == "scan" and not any(ipaddress.ip_address(ip) in n for n in nets)]
            for ip in stale:
                del self.devices[ip]

        found, methods = {}, []
        for c in cidr_list:
            f, method = arp_scan(c)
            found.update(f)
            methods.append(method)
        found[self.me] = self.my_mac or found.get(self.me, "")

        with ThreadPoolExecutor(16) as ex:
            names = dict(zip(found, ex.map(hostname, found)))
        for ip, mac in found.items():
            is_me = (ip == self.me)
            vendor = resolve_vendor(mac)
            dtype = guess_device_type(vendor, mac, is_me=is_me)
            with self.lock:
                existing_name = self.devices.get(ip, {}).get("name", "")
                resolved_name = "Shu kompyuter" if is_me else (names.get(ip) or existing_name or "")
                self._dev(ip, mac, name=resolved_name, vendor=vendor, dtype=dtype)
        self.scan_info = {"method": "+".join(dict.fromkeys(methods)), "cidr": cidr, "at": time.strftime("%H:%M:%S")}
        return len(found)

    def _ping_loop(self):
        while True:
            ips = list(self.devices)
            cpu_me, mem_me = local_cpu_mem()
            with ThreadPoolExecutor(16) as ex:
                for ip, rtt in zip(ips, ex.map(ping, ips)):
                    with self.lock:
                        if ip in self.devices:
                            if self.devices[ip]["src"] == "scan":
                                self.devices[ip].update(rtt=rtt, online=rtt is not None)
                            if ip == self.me and cpu_me is not None:
                                self.devices[ip].update(cpu=cpu_me, mem=mem_me, online=True)
            time.sleep(WINDOW)

    def _tshark_loop(self):
        iface = os.getenv("AIOT_IFACE") or self.my_iface or None
        cmd = [
            "tshark", "-l", "-n",
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.proto",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "frame.len",
            "-e", "tcp.flags",
            "-e", "_ws.col.Protocol",
            "-e", "tcp.payload",
            "-e", "udp.payload",
            "-e", "eth.src"
        ]
        if iface:
            cmd.extend(["-i", iface])

        try:
            self.sniffing = True
            self.sniff_error = None
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

            for line in proc.stdout:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 10:
                    continue
                src = parts[0].split(",")[0]
                dst = parts[1].split(",")[0]
                proto_num = parts[2].split(",")[0]
                tcp_sp, udp_sp, tcp_dp, udp_dp = parts[3], parts[4], parts[5], parts[6]
                length_str, flags_str, proto_name = parts[7], parts[8], parts[9]
                tcp_pay = parts[10] if len(parts) > 10 else ""
                udp_pay = parts[11] if len(parts) > 11 else ""
                eth_src = parts[12].split(",")[0].lower() if len(parts) > 12 else ""

                if not src or not dst:
                    continue

                if src in self.devices and eth_src and not self.devices[src].get("mac"):
                    v = resolve_vendor(eth_src)
                    self.devices[src].update(mac=eth_src, vendor=v, dtype=guess_device_type(v, eth_src, src == self.me))

                try:
                    length = int(length_str.split(",")[0])
                except ValueError:
                    length = 0

                sp = int((tcp_sp or udp_sp or "0").split(",")[0] or 0)
                dp = int((tcp_dp or udp_dp or "0").split(",")[0] or 0)
                proto = "tcp" if proto_num == "6" else ("udp" if proto_num == "17" else "icmp")

                raw_hex_str = (tcp_pay or udp_pay or "").replace(":", "").strip()[:64]
                if raw_hex_str:
                    try:
                        raw_bytes = bytes.fromhex(raw_hex_str)
                        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in raw_bytes)
                        if (sp == 5353 or dp == 5353) and src in self.devices and not self.devices[src].get("name"):
                            m_name = re.search(r"([A-Za-z0-9_-]{3,25})\.local", ascii_str)
                            if m_name:
                                self.devices[src]["name"] = m_name.group(1)
                    except Exception:
                        ascii_str = proto_name
                else:
                    raw_hex_str = "—"
                    ascii_str = proto_name or proto.upper()

                svc = SERVICE.get(dp) or SERVICE.get(sp) or (proto_name.lower() if proto_name else "-")
                self.packet_buffer.append(dict(
                    time=time.strftime("%H:%M:%S"),
                    src=src, dst=dst, proto=proto, sport=sp, dport=dp,
                    service=svc, len=length, flags=flags_str or "-",
                    payload=raw_hex_str, ascii=ascii_str
                ))

                if src not in self.devices and dst not in self.devices:
                    continue

                now, pay = time.time(), max(0, length - 20)
                flags = int(flags_str.split(",")[0], 16) if flags_str.startswith("0x") else 0
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
                    f["sib" if side == "o" else "rib"] += length
                    f["f" + side] |= flags
                    self.stats["packets"] += 1

        except Exception as e:
            self.sniffing = False
            self.sniff_error = f"Tshark xatosi: {e}"

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
            except Exception:
                pass

    def analyze(self, flows):
        acc = collections.defaultdict(lambda: dict(pk=0, by=0, fl=0, rem=set(), bad=[]))
        inb = collections.defaultdict(lambda: collections.defaultdict(lambda: dict(ports=set(), pk=0)))
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
                        if dev == f["resp"]:
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
                verdict, rr, attacker_ip = None, inb.get(ip), ip
                if rr:
                    src_scan, v = max(rr.items(), key=lambda kv: len(kv[1]["ports"]))
                    top_src, tv = max(rr.items(), key=lambda kv: kv[1]["pk"])
                    total = sum(x["pk"] for x in rr.values()) / WINDOW
                    if len(v["ports"]) >= SCAN_PORTS:
                        verdict = ("scanning", 1.0, f"{src_scan} manzili {len(v['ports'])} ta turli portni skanerladi [Qoida]")
                        attacker_ip = src_scan
                    elif tv["pk"] / WINDOW >= FLOOD_PPS:
                        verdict = ("dos", 1.0, f"{top_src} manzilidan {tv['pk']/WINDOW:.0f} paket/s oqim keldi [Qoida]")
                        attacker_ip = top_src
                    elif total >= FLOOD_PPS and len(rr) >= 5:
                        verdict = ("ddos", 1.0, f"{len(rr)} ta manbadan jami {total:.0f} paket/s oqim [Qoida]")
                if not verdict and a and len(a["bad"]) >= MIN_FLOWS:
                    cnt = collections.Counter(x[1] for x in a["bad"])
                    lab = cnt.most_common(1)[0][0]
                    top = max(a["bad"], key=lambda x: x[0])
                    verdict = (lab, max(x[0] for x in a["bad"] if x[1] == lab),
                               f"{len(a['bad'])} ta shubhali oqim ({top[2]}:{top[3]}) [Random Forest AI]")
                    if top[2] in self.devices and top[2] != self.me:
                        attacker_ip = top[2]

                target_for_btn = attacker_ip if self._blockable(attacker_ip) else (ip if self._blockable(ip) else None)
                cpu_load = d.get("cpu")
                if verdict:
                    lab, sc, det = verdict
                    if cpu_load is not None and cpu_load > 85.0:
                        sc = min(1.0, sc + 0.15)
                        det += f" [⚠️ Yuqori CPU: {cpu_load}%]"
                    d.update(status=lab, score=round(float(sc), 3), action=ACTION.get(lab, ""), last_attack=lab, last_target_ip=target_for_btn)
                    if prev != lab:
                        ev = dict(t=t, level=1, action=ACTION.get(lab, ""), ip=ip, label=lab,
                                  text=f"{d['name'] or ip} ({ip}): {lab} gumon, ishonch {sc*100:.0f}%, {det}")
                        self.events.appendleft(ev)
                        self._save_event_db(ev)
                        self._send_telegram_attack(d, lab, sc, det, target_ip=target_for_btn)
                else:
                    d.update(status="Normal", score=0.0, action="")
                    if prev != "Normal":
                        ev = dict(t=t, level=0, ip=ip, label="normal",
                                  text=f"{d['name'] or ip} ({ip}): normal holatga qaytdi.", action="")
                        self.events.appendleft(ev)
                        self._save_event_db(ev)
                        self._send_telegram_resolved(d, prev, target_ip=d.get("last_target_ip"))

    def _blockable(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ip == self.me:
            return False
        return a.is_private and not a.is_loopback

    def block(self, ip):
        if not self._blockable(ip):
            return False, "Bu manzilni bloklab bo'lmaydi (lokal emas yoki o'z IP manzilingiz)."
        try:
            res = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"],
                check=False, capture_output=True
            )
            if res.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-p", "tcp", "--syn", "-j", "DROP"], check=True, capture_output=True)
            self.blocked.add(ip)
            ev = dict(t=time.strftime("%H:%M:%S"), level=1, ip=ip, label="bloklandi",
                      text=f"{ip} BLOKLANDI (iptables DROP qoidasi yoqildi).", action="IPS Himoya")
            self.events.appendleft(ev)
            self._save_event_db(ev)
            return True, "Bloklandi (iptables DROP)"
        except Exception as e:
            return False, str(e)

    def unblock(self, ip):
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"], check=False, capture_output=True)
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--syn", "-j", "DROP"], check=False, capture_output=True)
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False, capture_output=True)
            subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=False, capture_output=True)
            self.blocked.discard(ip)
            ev = dict(t=time.strftime("%H:%M:%S"), level=0, ip=ip, label="ochildi",
                      text=f"{ip} blokdan chiqarildi.", action="")
            self.events.appendleft(ev)
            self._save_event_db(ev)
            return True, "Blokdan chiqarildi"
        except Exception as e:
            return False, str(e)

    def add_manual(self, ip):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
        with self.lock:
            self._dev(ip, "", name="", src="manual")
        return True

    def add_agent(self, ip, name, cpu, mem):
        with self.lock:
            self._dev(ip, name=name or ip, cpu=cpu, mem=mem, online=True, src="agent" if ip not in self.devices else self.devices[ip]["src"])

    def start(self):
        subprocess.run(["iptables", "-F", "INPUT"], check=False, capture_output=True)
        threading.Thread(target=self.scan, daemon=True).start()
        for fn in (self._ping_loop, self._flush_loop, self._tshark_loop, self._telegram_poll_loop):
            threading.Thread(target=fn, daemon=True).start()

    def snapshot(self):
        with self.lock:
            devs = sorted(self.devices.values(), key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
            out = [dict(d, blocked=d["ip"] in self.blocked) for d in devs]
            return dict(devices=out, events=list(self.events), stats=dict(self.stats),
                        packets=list(self.packet_buffer),
                        info=dict(sniffing=self.sniffing, sniff_error=self.sniff_error, window=WINDOW, threshold=THRESH,
                                  min_flows=MIN_FLOWS, scan_ports=SCAN_PORTS, flood_pps=FLOOD_PPS, model=self.model_file,
                                  scan=self.scan_info, me=self.me, telegram=self._tg_configured()))
