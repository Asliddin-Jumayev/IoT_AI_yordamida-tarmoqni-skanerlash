FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Tizim paketlarini o'rnatish: tshark, iptables, iproute2
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    iptables \
    iproute2 \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Tarmoq paketlarini to'liq tutish va iptables ishlashi uchun host tarmog'i kerak
CMD ["python", "app.py"]
