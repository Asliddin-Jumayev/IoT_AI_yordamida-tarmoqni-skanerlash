"""Qurilmada ishlatiladigan yengil agent: CPU/RAM ni X-Token bilan backendga yuboradi.
Ishlatish: python agent.py http://<backend-ip>:5000 [qurilma-nomi]"""
import sys, os, json, time, socket, urllib.request
import psutil

if len(sys.argv) < 2:
    print("Ishlatish: python agent.py http://<backend-ip>:5000 [qurilma-nomi]")
    sys.exit(1)

url = sys.argv[1].rstrip("/") + "/api/ingest"
name = sys.argv[2] if len(sys.argv) > 2 else socket.gethostname()
token = os.getenv("AIOT_TOKEN", "")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("10.255.255.255", 1))
ip = s.getsockname()[0]
s.close()

headers = {"Content-Type": "application/json"}
if token:
    headers["X-Token"] = token

while True:
    body = json.dumps({
        "device": name,
        "ip": ip,
        "cpu": psutil.cpu_percent(interval=1),
        "mem": psutil.virtual_memory().percent
    }).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(url, body, headers), timeout=3)
    except Exception as e:
        print("yuborilmadi:", e)
    time.sleep(4)