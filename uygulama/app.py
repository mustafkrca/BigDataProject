# ── Kurulum & Bağımlılıklar ────────────────────────────────────────────
# 1) Virtualenv'i aktifleştir
#    source /opt/firewall-sentinel/venv/bin/activate
# 2) Gerekli paketleri yükle
#    pip install flask scapy pandas joblib flask-socketio eventlet
#    pip uninstall scapy-python3 && pip install scapy
# 3) UFW veya iptables ile portu aç
#    ufw allow 5000:5010/tcp
#    iptables -I INPUT -p tcp --dport 5000:5010 -j ACCEPT
#    firewall-cmd --add-port=5000-5010/tcp --permanent && firewall-cmd --reload
# 4) Ortam değişkenlerini ayarla (örneğin systemd unit içinde)
#    LOCAL_IP, SMTP_SERVER, SMTP_USER, SMTP_PASS, MAIL_TO,
#    FLOW_TIMEOUT_SECONDS, MAIL_COOLDOWN_SECONDS, DASHBOARD_PORT, WARN_COOLDOWN_SEC

#!/opt/firewall-sentinel/venv/bin/python3
"""
Sentinel v2.6 – Web Arayüzlü, Gerçek Zamanlı Firewall Sentinel
"""

import os
import re
import joblib
import pandas as pd
import logging
import socket
import smtplib
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, render_template_string, request, redirect, url_for, jsonify
from dotenv import load_dotenv
load_dotenv("/opt/firewall-sentinel/.env")   

from flask_socketio import SocketIO

# ── Ortam & Ayarlar ──────────────────────────────────────────────────────────
SMTP_SERVER         = os.getenv("SMTP_SERVER")
SMTP_PORT           = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER           = os.getenv("SMTP_USER")
SMTP_PASS           = os.getenv("SMTP_PASS")
MAIL_TO             = os.getenv("MAIL_TO")
IFACE               = os.getenv("IFACE", "ens160")
MODEL_PATH          = os.getenv("MODEL_PATH", "/opt/firewall-sentinel/randomforest_firewall_clf.pkl")
FLOW_TIMEOUT        = timedelta(seconds=int(os.getenv("FLOW_TIMEOUT_SECONDS", "1")))
THRESH_P_ALLOW_MIN  = float(os.getenv("THRESH_P_ALLOW_MIN", "0.75"))
MAIL_COOLDOWN_SEC    = int(os.getenv("MAIL_COOLDOWN_SECONDS", "300"))
DASHBOARD_PORT      = int(os.getenv("DASHBOARD_PORT", "5001"))
WARN_COOLDOWN_SEC   = int(os.getenv("WARN_COOLDOWN_SEC", "5"))
IGNORE_LIST         = {int(p) for p in os.getenv("IGNORE_PORTS", "").split(",") if p}
LOG_FILE            = os.getenv("LOG_FILE_PATH", "/var/log/sentinel.log")

# Email toggle flag
email_enabled = True

# ── Logger yapılandırması ─────────────────────────────────────────────────────
LOG_FMT  = "%(asctime)s %(levelname)-8s %(message)s"
DATE_FMT = "%Y-%m-%d %H:%M:%S"
logger = logging.getLogger("sentinel")
logger.setLevel(logging.INFO)
# File handler
fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(logging.Formatter(LOG_FMT, DATE_FMT))
# Console handler
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter(LOG_FMT, DATE_FMT))
# In-memory buffer handler
LOG_BUFFER = deque(maxlen=200)
bh = logging.Handler()
bh.emit = lambda record: LOG_BUFFER.append(logging.Formatter(LOG_FMT, DATE_FMT).format(record))
logger.addHandler(fh)
logger.addHandler(ch)
logger.addHandler(bh)

LEVEL_MAP = {"Allow": logging.INFO, "Deny": logging.WARNING,
             "Drop": logging.ERROR, "Reset": logging.ERROR}

# ── Model yükle ──────────────────────────────────────────────────────────────
try:
    pipe = joblib.load(MODEL_PATH)
    IDX_ALLOW = 0
    LABEL_MAP = {0: "Allow", 1: "Deny", 2: "Drop", 3: "Reset"}
except Exception as e:
    logger.critical(f"Model yüklenemedi: {e}")
    raise SystemExit(1)

# ── LOCAL_IP bul ──────────────────────────────────────────────────────────────
LOCAL_IP = os.getenv("LOCAL_IP")
if not LOCAL_IP:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        LOCAL_IP = s.getsockname()[0]
        s.close()
        logger.info(f"Algılanan LOCAL_IP: {LOCAL_IP}")
    except Exception:
        LOCAL_IP = None
        logger.warning("LOCAL_IP ayarlanmadı ve otomatik bulunamadı.")

# ── Mail fonksiyonu ──────────────────────────────────────────────────────────
last_mail = defaultdict(lambda: datetime.min)
mail_lock = threading.Lock()
def send_alert(subject, html, key):
    global email_enabled
    with mail_lock:
        if not email_enabled:
            logger.info(f"E-posta devre dışı: {subject}")
            return
        now = datetime.now()
        if now - last_mail[key] < timedelta(seconds=MAIL_COOLDOWN_SEC):
            return
        if not all([SMTP_SERVER, SMTP_USER, SMTP_PASS, MAIL_TO]):
            return
        msg = MIMEMultipart('alternative')
        msg['Subject'], msg['From'], msg['To'] = subject, SMTP_USER, MAIL_TO
        plain = re.sub(r'<[^>]+>', '', html)
        msg.attach(MIMEText(plain, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as s:
                s.starttls(); s.login(SMTP_USER, SMTP_PASS); s.send_message(msg)
            last_mail[key] = now
            logger.info(f"Mail gönderildi: {subject}")
        except Exception as e:
            logger.error(f"Mail hatası: {e}")

# ── Paket işleme ─────────────────────────────────────────────────────────────
flows = {}
COLS = ["source_port","destination_port","nat_source_port","nat_destination_port",
        "bytes","bytes_sent","bytes_received","packets",
        "elapsed_time_(sec)","pkts_sent","pkts_received"]
warn_times = defaultdict(lambda: datetime.min)

# Initialize Flask and SocketIO
app = Flask(__name__, template_folder='templates')

socketio = SocketIO(app, cors_allowed_origins='*')

def handle_pkt(pkt):
    # Sadece IP paketleri
    if IP not in pkt:
        return

    # L4 katmanını al
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if not l4:
        return

    sp, dp = l4.sport, l4.dport
    if sp in IGNORE_LIST or dp in IGNORE_LIST:
        return

    # Akış anahtarı
    proto = pkt[IP].proto
    key = (pkt[IP].src, sp, pkt[IP].dst, dp, proto)
    now = datetime.now()

    # FIN+ACK taraması tespiti (flags == 0x10)
    flags = pkt[TCP].flags if TCP in pkt else 0
    if flags == 0x10:
        # Tek bir log girişi formatı içinde üret
        scan_msg = (
            f"{now} | Scan  | P(allow)=0.00 | 0B/0pkt | "
            f"{pkt[IP].src}:{sp} ➔ {pkt[IP].dst}:{dp}"
        )
        # Debounce
        if now - warn_times[key] > timedelta(seconds=WARN_COOLDOWN_SEC):
            logger.warning(scan_msg)
            socketio.emit('new_log', {'line': scan_msg})
            send_alert("⚠️ Port Scan Detected", f"<p>{scan_msg}</p>", key)
            warn_times[key] = now
        return

    # Akış bilgilerini oluştur veya güncelle
    f = flows.setdefault(key, {
        'start': now, 'bytes_sent': 0, 'bytes_received': 0,
        'packets': 0, 'pkts_sent': 0, 'pkts_received': 0
    })

    length = len(pkt)
    f['packets'] += 1
    if pkt[IP].src == LOCAL_IP:
        f['bytes_sent'] += length
        f['pkts_sent']  += 1
    else:
        f['bytes_received'] += length
        f['pkts_received']  += 1

    # Akış sonu mu?
    done = ((flags & 0x01) != 0) or (now - f['start'] > FLOW_TIMEOUT)
    if not done:
        return

    # Model ile tahmin
    elapsed = (now - f['start']).total_seconds()
    row = {
        'source_port': sp, 'destination_port': dp,
        'nat_source_port': 0, 'nat_destination_port': 0,
        'bytes': f['bytes_sent'] + f['bytes_received'],
        'bytes_sent': f['bytes_sent'], 'bytes_received': f['bytes_received'],
        'packets': f['packets'], 'elapsed_time_(sec)': elapsed,
        'pkts_sent': f['pkts_sent'], 'pkts_received': f['pkts_received']
    }
    df = pd.DataFrame([row], columns=COLS)
    proba = pipe.predict_proba(df)[0]
    pred  = pipe.predict(df)[0]
    label = LABEL_MAP.get(pred, str(pred))
    level = LEVEL_MAP.get(label, logging.INFO)
    p_allow = proba[IDX_ALLOW]

    # Tutarlı log formatı
    msg = (
        f"{now} | {label:<5s} | P(allow)={p_allow:.2f} | "
        f"{row['bytes']}B/{row['packets']}pkt | "
        f"{pkt[IP].src}:{sp} ➔ {pkt[IP].dst}:{dp}"
    )

    # Log ve emit
    if level == logging.INFO:
        logger.info(msg)
    else:
        if now - warn_times[key] > timedelta(seconds=WARN_COOLDOWN_SEC):
            logger.log(level, msg)
            send_alert(f"⚠️ Sentinel Alert: {label}", f"<p>{msg}</p>", key)
            warn_times[key] = now

    socketio.emit('new_log', {'line': msg})
    del flows[key]


# ── Flask Routes ────────────────────────────────────────────────────────────
@app.route('/')
def index():
    with mail_lock:
        email_status = email_enabled
    logs = list(LOG_BUFFER)[-200:]
    return render_template('index.html',
                           logs=logs,
                           email_enabled=email_status)

@app.route('/logs')
def get_logs():
    logs = list(LOG_BUFFER)[-200:]
    # EN YENİ LOG EN ÜSTTE OLSUN
    return jsonify(list(reversed(logs)))

@app.route('/toggle', methods=['POST'])
def toggle():
    global email_enabled
    with mail_lock:
        email_enabled = not email_enabled
        logger.info(f"E-posta {'aktif' if email_enabled else 'pasif'}")
    return redirect(url_for('index'))

# ── Başlat ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    threading.Thread(target=lambda: sniff(iface=IFACE, prn=handle_pkt, store=False), daemon=True).start()
    logger.info(f"Web arayüzü dinleniyor: 0.0.0.0:{DASHBOARD_PORT}")
    socketio.run(app, host='0.0.0.0', port=DASHBOARD_PORT, use_reloader=False)
