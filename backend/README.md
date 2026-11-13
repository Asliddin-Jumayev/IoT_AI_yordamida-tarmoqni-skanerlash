# AIoT real monitoring: qurilmalarni topish, trafikni tahlil qilish, anomaliyani aniqlash

```
aiot_project/
├── backend/
│   ├── train_real.py   haqiqiy dataset (TON_IoT) bilan model o'qitish -> model_real.joblib, model_live.joblib
│   ├── monitor.py      ARP scan, ping, paket tutish, oqimlar, model + qoidalar
│   ├── app.py          Flask API (real monitoring)
│   ├── agent.py        qurilmadan CPU/RAM yuboruvchi agent (ixtiyoriy)
│   ├── app_sim.py      eski simulyatsiya versiyasi (zaxira)
│   └── requirements.txt
└── frontend/index.html
```

## Ishga tushirish (Parrot OS / Debian asosidagi Linux)

Parrot OS'da scapy va root huquqi tayyor, shuning uchun Windows'dagidek Npcap kerak emas.

1. Virtual muhit yaratish (tizim paketlari bilan aralashmasligi uchun tavsiya etiladi):
   ```
   cd backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Modelni o'qitish (bir marta, ~1-2 daqiqa, internet kerak):
   ```
   python train_real.py
   ```
3. O'z tarmoq interfeysingizni toping (odatda `eth0` simli, `wlan0` Wi-Fi):
   ```
   ip a
   ```
4. Backendni **root** huquqi bilan ishga tushiring (paket tutish uchun shart). `sudo` venv ichidagi python'ni emas,
   tizim python'ini chaqiradi, shuning uchun to'g'ridan-to'g'ri yo'lni ko'rsating:
   ```
   sudo venv/bin/python app.py
   ```
   Kerak bo'lsa interfeysni qat'iy belgilang (masalan noutbuk bir nechta interfeysga ega bo'lsa):
   ```
   sudo AIOT_IFACE=wlan0 venv/bin/python app.py
   ```
   **root'siz ishlatish** (sudo bo'lmasa ham mumkin, lekin faqat bitta marta, har ishga tushirishda):
   ```
   sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f venv/bin/python3)
   venv/bin/python app.py
   ```
5. `frontend/index.html` ni Parrot OS'dagi brauzerda (Firefox) oching va "Qurilmalarni topish" ni bosing.
   Ikkalasi bitta kompyuterda ishlagani uchun backend manzili `http://127.0.0.1:5000` o'zgarmaydi.

### Tezkor sinov (bitta terminalda)
Yangi terminalda (root shart emas) o'z IP manzilingizga portlarni skanerlang va jadvalda "scanning" chiqishini kuzating:
```
nmap -sS -p 1-300 <o'z-kompyuteringiz-IP-manzili>
```
`ip a` buyrug'idan o'z IP manzilingizni ko'rasiz.

## Ishga tushirish (Windows / PowerShell)
PowerShell'da `&&` va `sudo` ishlamaydi. Buyruqlarni alohida-alohida yozing.
1. Terminalni `backend` papkasida oching va: `pip install -r requirements.txt`
2. `python train_real.py` (bir marta, ~2-3 daqiqa; datasetni o'zi yuklaydi. Yuklanmasa skript qo'lda yuklash havolasini ko'rsatadi)
3. Paket tutish uchun **Administrator** huquqi va **Npcap** kerak (https://npcap.com, o'rnatishda "WinPcap API-compatible mode" ni belgilang):
   PowerShell'ni o'ng tugma > "Run as administrator" bilan oching, `cd` bilan `backend` ga kiring va `python app.py`
   (PyCharm terminalida bo'lmaydi, PyCharm'ni o'zini Administrator sifatida ishga tushiring).
   Linux/macOS: `sudo python app.py`
4. `frontend/index.html` ni brauzerda oching, "Qurilmalarni topish" ni bosing.
   Administratorsiz ham ishlaydi, lekin faqat qurilmalar ro'yxati va ping bo'ladi (paket tutish o'chiq).

## Hujum simulyatori (attacker/) — demo uchun

Tizimni jonli ko'rsatish uchun ikkinchi, mustaqil dastur qo'shildi: `attacker/` papkasi. U interfeys orqali IP kiritib, **haqiqiy** tarmoq trafigini (port skanerlash, SYN/UDP flood) shu manzilga yuboradi, shunda asosiy monitoring (`backend/` + `frontend/`) buni jonli aniqlaydi.

**Xavfsizlik:** faqat lokal (192.168.x.x, 10.x.x.x, 172.16-31.x.x) manzillarga ruxsat beriladi, davomiylik 60 soniyadan, intensivlik 2000 paket/s dan oshmaydi. Ommaviy internet manzillariga yuborish kodda bloklangan. Faqat o'zingiz nazorat qiladigan qurilmaga (masalan o'z routeringiz) ishlating.

### Ishga tushirish (asosiy backend va frontend allaqachon ishlab turgan holda, alohida terminalda)
```bash
cd ~/aiot_project/attacker
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python app.py          # port 5001 da ishga tushadi
```
So'ng `attacker/index.html` ni brauzerda oching (ikkinchi tab sifatida, asosiy monitoring ochiq qolgan holda):
1. Nishon IP: masalan o'z routeringiz `192.168.0.1`
2. Hujum turi: Port skanerlash / SYN flood / UDP flood
3. "Hujumni boshlash" ni bosing
4. Asosiy monitoring sahifasiga (birinchi tab) o'ting — bir necha soniyada jadvalda shu qurilma qatorida hujum turi va ogohlantirish jurnalida qizil yozuv paydo bo'lishini kuzating.

Demo uchun tavsiya: ikkala sahifani ekranni bo'lib (split-screen) yonma-yon oching — chapda hujum simulyatori, o'ngda monitoring.

## Muhim cheklovlar
- **Boshqa qurilmalar trafigini ko'rish.** Oddiy Wi-Fi/switch tarmoqda kompyuter faqat o'zining trafigini ko'radi. Boshqa qurilmalar
  trafigini tahlil qilish uchun dasturni router/shlyuz o'rnida ishlatish (masalan Raspberry Pi hotspot), yoki routerda port mirroring (SPAN) kerak.
  Mirroring bo'lmasa, boshqa qurilmalar uchun faqat online/ping ko'rinadi.
- **Masofaviy CPU/RAM** tarmoq orqali olinmaydi. Qurilmada `python agent.py http://<backend-ip>:5000` ishlating (backendni `AIOT_HOST=0.0.0.0` bilan ishga tushiring, `AIOT_TOKEN` o'rnating).
- **Model laboratoriya ma'lumotida o'qitilgan.** Uy tarmog'idagi oddiy trafik ba'zan gumonli chiqishi mumkin. Shuning uchun `model_live.joblib` (portga bog'liq emas),
  `AIOT_THRESHOLD` (0.8) va `AIOT_MIN_FLOWS` (3) bor. Yolg'on signal ko'p bo'lsa chegarani 0.9 ga ko'taring.
- **Qoidalar qatlami:** model oqimlarni alohida ko'radi, shuning uchun port skanerlash va flood qoidalar bilan ham aniqlanadi
  (`AIOT_SCAN_PORTS`=20, `AIOT_FLOOD_PPS`=200).
- Faqat o'zingizning tarmog'ingizda ishlating. Skanerlash va trafikni tutish ruxsatsiz tarmoqlarda noqonuniy.

## Xavfsiz sinash (o'z tarmog'ingizda)
Boshqa kompyuterdan o'z qurilmangizga `nmap -sS -p 1-200 <qurilma-ip>` ishga tushiring: jadvalda "scanning" paydo bo'lishi kerak.

## Sozlamalar (muhit o'zgaruvchilari)
AIOT_WINDOW, AIOT_THRESHOLD, AIOT_MIN_FLOWS, AIOT_SCAN_PORTS, AIOT_FLOOD_PPS, AIOT_IFACE (tarmoq interfeysi), AIOT_MODEL, AIOT_HOST, AIOT_TOKEN.
