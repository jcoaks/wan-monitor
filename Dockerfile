FROM python:3.12-slim

WORKDIR /app

# iputils-ping: needed for the power-outage sentinel (pings a device with no
# battery backup, e.g. the fridge, to detect when home power goes out/comes back).
# tzdata: so the TZ env var gives the AI-written alerts the correct local time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wan_monitor.py .

CMD ["python", "-u", "wan_monitor.py"]
