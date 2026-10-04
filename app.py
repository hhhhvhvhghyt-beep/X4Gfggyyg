import os, sys, subprocess, importlib

# ---- نصب خودکار پکیج‌ها (بار اول اجرا) ----
_BASE = os.path.dirname(os.path.abspath(__file__))
_LIBS = os.path.join(_BASE, "libs")
os.makedirs(_LIBS, exist_ok=True)
sys.path.insert(0, _LIBS)
_REQ = {"flask": "flask", "cryptography": "cryptography", "qrcode": "qrcode", "PIL": "pillow"}

def _ensure():
    missing = []
    for mod, pkg in _REQ.items():
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(pkg)
    if not missing:
        return
    print("[setup] installing:", ", ".join(missing), flush=True)
    base = [sys.executable, "-m", "pip", "install", "--no-input", "--disable-pip-version-check", "--target", _LIBS]
    for extra in ([], ["--break-system-packages"]):
        r = subprocess.run(base + extra + missing)
        if r.returncode == 0:
            break
    else:
        # اگر pip نبود، ensurepip را امتحان کن و دوباره تلاش کن
        subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"])
        subprocess.run(base + missing)
    importlib.invalidate_caches()

_ensure()
import json, base64, io, threading, time, subprocess, shutil, secrets
from flask import Flask, request, jsonify, send_file, Response, abort
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import qrcode

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB = os.path.join(DATA_DIR, "data.json")
LOCK = threading.Lock()

# ---- تنظیمات (با متغیر محیطی یا Startup پنل تغییر بدید) ----
PANEL_PORT = int(os.getenv("SERVER_PORT", os.getenv("PORT", "8000")))
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD", "")          # خالی = بدون رمز
WG_ENDPOINT = os.getenv("WG_ENDPOINT", "")                # مثال: 1.2.3.4:51820 (خالی = آی‌پی عمومی خودکار)
WG_PORT = int(os.getenv("WG_PORT", "51820"))              # پورت UDP وایرگارد
WG_IFACE = os.getenv("WG_IFACE", "wg0")
WG_SUBNET = os.getenv("WG_SUBNET", "10.8.0")              # 10.8.0.x
WG_DNS = os.getenv("WG_DNS", "1.1.1.1")
WG_MTU = os.getenv("WG_MTU", "1280")

app = Flask(__name__)

def genkey():
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()

def load():
    if os.path.exists(DB):
        with open(DB) as f:
            return json.load(f)
    priv, pub = genkey()
    d = {"server_priv": priv, "server_pub": pub, "clients": []}
    save(d)
    return d

def save(d):
    with open(DB, "w") as f:
        json.dump(d, f, indent=1)

STATUS = {"up": False, "log": []}
_PUBIP = {"v": None}

def sh(cmd, log=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if log and r.returncode != 0:
        STATUS["log"].append(f"$ {cmd} -> {(r.stderr or r.stdout).strip()[:300]}")
    return r

def has_wg():
    return STATUS["up"]

def public_ip():
    if _PUBIP["v"]:
        return _PUBIP["v"]
    import urllib.request
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            _PUBIP["v"] = urllib.request.urlopen(u, timeout=5).read().decode().strip()
            return _PUBIP["v"]
        except Exception:
            pass
    return None

def setup_wg():
    """وایرگارد واقعی را روی همین ماشین/کانتینر بالا می‌آورد"""
    STATUS["log"].clear()
    if not shutil.which("wg-quick"):
        STATUS["log"].append("wireguard-tools نصب نیست")
        return
    d = load()
    conf = f"""[Interface]
PrivateKey = {d['server_priv']}
Address = {WG_SUBNET}.1/24
ListenPort = {WG_PORT}
"""
    path = f"/etc/wireguard/{WG_IFACE}.conf"
    try:
        os.makedirs("/etc/wireguard", exist_ok=True)
        with open(path, "w") as f:
            f.write(conf)
        os.chmod(path, 0o600)
    except Exception as e:
        STATUS["log"].append(f"نوشتن {path} ناموفق: {e}")
        return
    if shutil.which("wireguard-go"):
        os.environ["WG_QUICK_USERSPACE_IMPLEMENTATION"] = "wireguard-go"
    sh(f"wg-quick down {WG_IFACE}", log=False)
    r = sh(f"wg-quick up {WG_IFACE}")
    if r.returncode != 0 and "WG_QUICK_USERSPACE_IMPLEMENTATION" not in os.environ and shutil.which("wireguard-go"):
        pass
    if sh(f"wg show {WG_IFACE}", log=False).returncode != 0:
        STATUS["log"].append("اینترفیس وایرگارد بالا نیامد (احتمالاً NET_ADMIN / TUN در دسترس نیست)")
        return
    try:
        open("/proc/sys/net/ipv4/ip_forward", "w").write("1")
    except Exception:
        sh("sysctl -w net.ipv4.ip_forward=1")
    dev = None
    r = sh("ip route show default", log=False)
    if "dev " in r.stdout:
        dev = r.stdout.split("dev ")[1].split()[0]
    if dev:
        sub = f"{WG_SUBNET}.0/24"
        sh(f"iptables -t nat -C POSTROUTING -s {sub} -o {dev} -j MASQUERADE || iptables -t nat -A POSTROUTING -s {sub} -o {dev} -j MASQUERADE")
        sh(f"iptables -C FORWARD -i {WG_IFACE} -j ACCEPT || iptables -A FORWARD -i {WG_IFACE} -j ACCEPT")
        sh(f"iptables -C FORWARD -o {WG_IFACE} -j ACCEPT || iptables -A FORWARD -o {WG_IFACE} -j ACCEPT")
    else:
        STATUS["log"].append("اینترفیس شبکه پیش‌فرض پیدا نشد (NAT انجام نشد)")
    STATUS["up"] = True
    for c in d["clients"]:
        if not c.get("disabled"):
            wg_add(c["pub"], c["ip"])

def wg_add(pub, ip):
    if has_wg():
        sh(f"wg set {WG_IFACE} peer {pub} allowed-ips {ip}/32")

def wg_remove(pub):
    if has_wg():
        sh(f"wg set {WG_IFACE} peer {pub} remove")

def monitor():
    """مصرف هر کاربر را می‌خواند و بعد از اتمام حجم قطعش می‌کند (فقط وقتی wg روی سرور هست)"""
    while True:
        time.sleep(30)
        if not has_wg():
            continue
        try:
            out = subprocess.run(["wg", "show", WG_IFACE, "transfer"], capture_output=True, text=True).stdout
            seen = {}
            for line in out.strip().splitlines():
                p, rx, tx = line.split()
                seen[p] = int(rx) + int(tx)
            with LOCK:
                d = load()
                for c in d["clients"]:
                    if c["pub"] in seen:
                        cur = seen[c["pub"]]
                        # شمارنده wg با ری‌استارت صفر می‌شود
                        if cur < c.get("last", 0):
                            c["used"] = c.get("used", 0) + c.get("last", 0)
                        c["last"] = cur
                    total = c.get("used", 0) + c.get("last", 0)
                    if c["limit"] > 0 and total >= c["limit"] and not c.get("disabled"):
                        c["disabled"] = True
                        wg_remove(c["pub"])
                save(d)
        except Exception as e:
            print("monitor error:", e)

def check_auth():
    if not PANEL_PASSWORD:
        return True
    a = request.authorization
    return bool(a and secrets.compare_digest(a.password or "", PANEL_PASSWORD))

@app.before_request
def guard():
    if not check_auth():
        return Response("Login", 401, {"WWW-Authenticate": 'Basic realm="WG Panel"'})

def build_conf(d, c):
    endpoint = WG_ENDPOINT or f"{public_ip() or request.host.split(':')[0]}:{WG_PORT}"
    return f"""[Interface]
PrivateKey = {c['priv']}
Address = {c['ip']}/32
DNS = {WG_DNS}
MTU = {WG_MTU}

[Peer]
PublicKey = {d['server_pub']}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint}
PersistentKeepalive = 25
"""

PAGE = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل وایرگارد</title>
<style>
body{font-family:Tahoma,sans-serif;background:#0d1020;color:#e8e8f0;margin:0;display:flex;justify-content:center;padding:24px}
.card{background:#161a30;border-radius:16px;padding:24px;width:100%;max-width:420px}
h2{margin-top:0;text-align:center}
label{display:block;margin:12px 0 6px;color:#aab}
select,input{width:100%;padding:12px;border-radius:10px;border:1px solid #2c3158;background:#0d1020;color:#fff;font-size:16px;box-sizing:border-box}
button,a.btn{display:block;width:100%;margin-top:14px;padding:13px;border:0;border-radius:10px;background:#6c4ff0;color:#fff;font-size:16px;cursor:pointer;text-align:center;text-decoration:none;box-sizing:border-box}
a.btn.alt{background:#2a2f55}
#res{display:none;text-align:center;margin-top:18px}
#res img{background:#fff;padding:10px;border-radius:12px;max-width:100%}
</style></head><body><div class="card">
<h2>🔐 پنل وایرگارد</h2><div id="st" style="text-align:center;font-size:13px;margin-bottom:8px">...</div>
<label>حجم</label>
<select id="vol" onchange="document.getElementById('c').style.display=this.value=='custom'?'block':'none'">
<option value="1">1 گیگ</option><option value="2">2 گیگ</option><option value="5">5 گیگ</option>
<option value="10" selected>10 گیگ</option><option value="20">20 گیگ</option><option value="50">50 گیگ</option>
<option value="100">100 گیگ</option><option value="0">نامحدود</option><option value="custom">دلخواه...</option></select>
<input id="c" type="number" min="0.1" step="0.1" placeholder="حجم به گیگابایت" style="display:none;margin-top:8px">
<button onclick="make()">ساخت کانفیگ</button>
<div id="res"><img id="qr"><a id="dq" class="btn">دانلود عکس QR</a><a id="dc" class="btn alt">دانلود فایل کانفیگ</a></div>
<div id="list" style="margin-top:22px;font-size:13px"></div></div><script>
async function make(){
 let v=document.getElementById('vol').value; if(v=='custom') v=document.getElementById('c').value||'1';
 const r=await fetch('/api/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({gb:parseFloat(v)})});
 const j=await r.json(); if(!j.ok){alert(j.error);return}
 document.getElementById('qr').src='/qr/'+j.id+'.png';
 document.getElementById('dq').href='/qr/'+j.id+'.png?dl=1';
 document.getElementById('dc').href='/conf/'+j.id+'.conf';
 document.getElementById('res').style.display='block'; load();
}
async function load(){
 const j=await (await fetch('/api/clients')).json();
 const st=document.getElementById('st');
 st.innerHTML=j.up?'<span style="color:#4ade80">● وایرگارد فعال</span>':'<span style="color:#f87171">● وایرگارد غیرفعال</span><br><small>'+j.log.join('<br>')+'</small>';
 const gb=b=>(b/1073741824).toFixed(2);
 document.getElementById('list').innerHTML=j.clients.map(c=>`<div style="display:flex;justify-content:space-between;padding:8px 0;border-top:1px solid #2c3158"><span>${c.ip} ${c.disabled?'⛔':''}</span><span>${gb(c.used)} / ${c.limit?gb(c.limit):'∞'} GB</span><span><a href="/qr/${c.id}.png" style="color:#8af">QR</a> <a href="#" onclick="del('${c.id}');return false" style="color:#f87171">حذف</a></span></div>`).join('');
}
async function del(id){ if(confirm('حذف شود؟')){await fetch('/api/delete/'+id,{method:'POST'});load();} }
load();
</script></body></html>"""

@app.route("/")
def index():
    return PAGE

@app.route("/api/create", methods=["POST"])
def create():
    gb = float((request.get_json(silent=True) or {}).get("gb", 0))
    with LOCK:
        d = load()
        used_ips = {c["ip"] for c in d["clients"]}
        ip = next((f"{WG_SUBNET}.{i}" for i in range(2, 255) if f"{WG_SUBNET}.{i}" not in used_ips), None)
        if not ip:
            return jsonify(ok=False, error="ظرفیت پر است")
        priv, pub = genkey()
        c = {"id": secrets.token_urlsafe(8), "priv": priv, "pub": pub, "ip": ip,
             "limit": int(gb * 1024**3), "used": 0, "last": 0, "disabled": False,
             "created": int(time.time())}
        d["clients"].append(c)
        save(d)
        wg_add(pub, ip)
    return jsonify(ok=True, id=c["id"])

@app.route("/api/clients")
def clients():
    d = load()
    return jsonify(up=STATUS["up"], log=STATUS["log"], clients=[
        {"id": c["id"], "ip": c["ip"], "limit": c["limit"], "used": c.get("used", 0) + c.get("last", 0),
         "disabled": c.get("disabled", False)} for c in d["clients"]])

@app.route("/api/delete/<cid>", methods=["POST"])
def delete(cid):
    with LOCK:
        d = load()
        for c in d["clients"]:
            if c["id"] == cid:
                wg_remove(c["pub"])
        d["clients"] = [c for c in d["clients"] if c["id"] != cid]
        save(d)
    return jsonify(ok=True)

def find(cid):
    d = load()
    for c in d["clients"]:
        if c["id"] == cid:
            return d, c
    abort(404)

@app.route("/conf/<cid>.conf")
def conf(cid):
    d, c = find(cid)
    return Response(build_conf(d, c), mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename=wg-{c['ip'].split('.')[-1]}.conf"})

@app.route("/qr/<cid>.png")
def qr(cid):
    d, c = find(cid)
    img = qrcode.make(build_conf(d, c), box_size=8, border=3)
    buf = io.BytesIO(); img.save(buf, "PNG"); buf.seek(0)
    return send_file(buf, mimetype="image/png", as_attachment=bool(request.args.get("dl")),
                     download_name=f"wg-qr-{c['ip'].split('.')[-1]}.png")

if __name__ == "__main__":
    load()
    setup_wg()
    print("[wg] up:", STATUS["up"], STATUS["log"], flush=True)
    threading.Thread(target=monitor, daemon=True).start()
    app.run(host="0.0.0.0", port=PANEL_PORT)
