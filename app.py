"""
Phone Tracker Server - personal anti-theft backend for YOUR OWN devices.

Phones send location pings and intruder photos here whenever they have any
connection (mobile data, Wi-Fi, in-flight Wi-Fi). You see them on a private
dashboard and queue commands (locate, alarm, message, lock request) that the
phone picks up on its next ping.

Environment variables:
  ADMIN_PASSWORD  (required) dashboard password - make it long
  SECRET_KEY      (recommended) random string so logins survive restarts
  DATA_DIR        where the database and photos live (default ./data)
  TZ_NAME         display timezone (default Africa/Lagos)
  COOKIE_SECURE   "1" when served over https (default 1)
"""
import hmac
import hashlib
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (Flask, abort, g, jsonify, redirect, render_template_string,
                   request, send_from_directory, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

def _pick_data_dir():
    """Use DATA_DIR if writable, else fall back to ./data (data is lost on restart
    when the host has no persistent disk, e.g. Render's free plan)."""
    wanted = os.environ.get("DATA_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    for path in (wanted, os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")):
        try:
            os.makedirs(os.path.join(path, "photos"), exist_ok=True)
            return path
        except OSError:
            print(f"WARNING: cannot write to {path}", flush=True)
    raise SystemExit("No writable data directory")


DATA_DIR = _pick_data_dir()
PHOTO_DIR = os.path.join(DATA_DIR, "photos")
DB_PATH = os.path.join(DATA_DIR, "tracker.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
TZ = ZoneInfo(os.environ.get("TZ_NAME", "Africa/Lagos"))
COMMAND_TYPES = {"locate", "alarm", "message", "lock"}
MAX_PHOTO_BYTES = 5 * 1024 * 1024

app = Flask(__name__)
_sk = os.environ.get("SECRET_KEY", "")
# Reject obviously weak keys (e.g. the literal "true"); fall back to a random one.
app.secret_key = _sk if len(_sk) >= 24 else secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    MAX_CONTENT_LENGTH=MAX_PHOTO_BYTES + 100_000,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_seen TEXT,
  lost_mode INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS locations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL,
  ts TEXT NOT NULL,
  lat REAL, lon REAL, acc REAL,
  battery INTEGER, charging TEXT, network TEXT, note TEXT
);
CREATE INDEX IF NOT EXISTS idx_loc_dev ON locations(device_id, id DESC);
CREATE TABLE IF NOT EXISTS commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  payload TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  result TEXT
);
CREATE TABLE IF NOT EXISTS intruders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL,
  ts TEXT NOT NULL,
  filename TEXT NOT NULL,
  lat REAL, lon REAL, note TEXT
);
"""


# ---------------------------------------------------------------- helpers
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


init_db()


@app.template_filter("localtime")
def localtime(value):
    if not value:
        return "never"
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.astimezone(TZ).strftime("%d %b %Y, %H:%M")
    except ValueError:
        return value


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def to_float(value, lo, hi):
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if lo <= f <= hi else None


def clip(value, n=120):
    return (str(value)[:n]) if value not in (None, "") else None


def payload_of():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else request.form.to_dict()


# ---------------------------------------------------------- device auth
def device_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Device-Token", "")
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if not token:
            return jsonify(error="missing token"), 401
        row = db().execute("SELECT * FROM devices WHERE token_hash=?",
                           (hash_token(token),)).fetchone()
        if not row:
            time.sleep(1)  # slow down token guessing
            return jsonify(error="invalid token"), 401
        g.device = row
        return fn(*args, **kwargs)
    return wrapper


def pull_commands(device_id):
    rows = db().execute(
        "SELECT id, type, payload FROM commands WHERE device_id=? AND status='pending' ORDER BY id",
        (device_id,)).fetchall()
    if rows:
        ids = [r["id"] for r in rows]
        db().execute(
            f"UPDATE commands SET status='delivered', delivered_at=? WHERE id IN ({','.join('?' * len(ids))})",
            [now_iso(), *ids])
    return [dict(r) for r in rows]


def device_reply(device_id):
    dev = db().execute("SELECT lost_mode FROM devices WHERE id=?", (device_id,)).fetchone()
    lost = bool(dev["lost_mode"])
    cmds = pull_commands(device_id)
    db().commit()
    return jsonify(ok=True, lost=lost, interval=60 if lost else 300, commands=cmds)


@app.post("/api/ping")
@device_required
def api_ping():
    d = payload_of()
    db().execute(
        "INSERT INTO locations (device_id, ts, lat, lon, acc, battery, charging, network, note) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (g.device["id"], now_iso(),
         to_float(d.get("lat"), -90, 90), to_float(d.get("lon"), -180, 180),
         to_float(d.get("acc"), 0, 100000),
         int(to_float(d.get("battery"), 0, 100) or 0) if d.get("battery") not in (None, "") else None,
         clip(d.get("charging"), 20), clip(d.get("network")), clip(d.get("note"), 200)))
    db().execute("UPDATE devices SET last_seen=? WHERE id=?", (now_iso(), g.device["id"]))
    return device_reply(g.device["id"])


@app.get("/api/commands")
@device_required
def api_commands():
    db().execute("UPDATE devices SET last_seen=? WHERE id=?", (now_iso(), g.device["id"]))
    return device_reply(g.device["id"])


@app.post("/api/commands/<int:cid>/ack")
@device_required
def api_ack(cid):
    d = payload_of()
    status = "done" if d.get("status", "done") == "done" else "unsupported"
    db().execute("UPDATE commands SET status=?, result=? WHERE id=? AND device_id=?",
                 (status, clip(d.get("result"), 200), cid, g.device["id"]))
    db().commit()
    return jsonify(ok=True)


@app.post("/api/intruder")
@device_required
def api_intruder():
    f = request.files.get("photo")
    if not f:
        return jsonify(error="photo required"), 400
    blob = f.read(MAX_PHOTO_BYTES + 1)
    if len(blob) > MAX_PHOTO_BYTES:
        return jsonify(error="too large"), 413
    if blob[:3] == b"\xff\xd8\xff":
        ext = "jpg"
    elif blob[:8] == b"\x89PNG\r\n\x1a\n":
        ext = "png"
    else:
        return jsonify(error="only jpg or png"), 400
    name = f"{g.device['id']}_{int(time.time())}_{secrets.token_hex(4)}.{ext}"
    with open(os.path.join(PHOTO_DIR, name), "wb") as out:
        out.write(blob)
    d = request.form
    db().execute(
        "INSERT INTO intruders (device_id, ts, filename, lat, lon, note) VALUES (?,?,?,?,?,?)",
        (g.device["id"], now_iso(), name, to_float(d.get("lat"), -90, 90),
         to_float(d.get("lon"), -180, 180), clip(d.get("note"), 200)))
    db().execute("UPDATE devices SET last_seen=? WHERE id=?", (now_iso(), g.device["id"]))
    db().commit()
    return device_reply(g.device["id"])


# ---------------------------------------------------------- admin auth
_attempts = {}


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def csrf_protect():
    if request.method == "POST" and not request.path.startswith("/api/") and request.path != "/login":
        token = session.get("csrf", "")
        if not token or not hmac.compare_digest(token, request.form.get("csrf", "")):
            abort(400, "bad csrf token")


@app.context_processor
def inject_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return {"csrf": session["csrf"]}


BASE = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{{ title or 'Phone Tracker' }}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
 :root{--bg:#0f1115;--card:#181b22;--ink:#e8eaf0;--mute:#9aa3b2;--acc:#4f9dff;--bad:#ff5d5d;--ok:#3ecf8e}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
 main{max-width:900px;margin:0 auto;padding:16px} a{color:var(--acc)}
 .card{background:var(--card);border-radius:12px;padding:14px;margin:12px 0}
 h1,h2{margin:.2em 0} .mute{color:var(--mute)} .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
 button,input,select{font:inherit;padding:9px 12px;border-radius:8px;border:1px solid #2c313c;background:#0f1115;color:var(--ink)}
 button{background:var(--acc);color:#04111f;border:0;font-weight:600;cursor:pointer}
 button.bad{background:var(--bad);color:#fff} button.ghost{background:#2c313c;color:var(--ink)}
 #map{height:320px;border-radius:10px} table{width:100%;border-collapse:collapse;font-size:13px}
 td,th{padding:6px 4px;text-align:left;border-bottom:1px solid #232834}
 .tag{padding:2px 8px;border-radius:99px;font-size:12px;background:#2c313c}
 .tag.lost{background:var(--bad);color:#fff} .photos{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px}
 .photos img{width:100%;border-radius:8px}
</style></head><body><main>{% block body %}{% endblock %}</main></body></html>
"""

LOGIN = """{% extends base %}{% block body %}
<div class="card"><h1>Phone Tracker</h1>
{% if error %}<p style="color:var(--bad)">{{ error }}</p>{% endif %}
<form method="post" class="row"><input type="password" name="password" placeholder="Admin password" autofocus required>
<button>Sign in</button></form></div>{% endblock %}"""

HOME = """{% extends base %}{% block body %}
<div class="row" style="justify-content:space-between"><h1>My devices</h1>
<form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="ghost">Sign out</button></form></div>
{% if new_token %}<div class="card" style="border:1px solid var(--ok)"><b>Device token for {{ new_name }} (shown once, copy it now):</b>
<p><code style="word-break:break-all">{{ new_token }}</code></p></div>{% endif %}
{% for d in devices %}
<div class="card"><div class="row" style="justify-content:space-between">
 <div><h2><a href="{{ url_for('device', did=d.id) }}">{{ d.name }}</a>
 {% if d.lost_mode %}<span class="tag lost">LOST MODE</span>{% endif %}</h2>
 <div class="mute">Last seen: {{ d.last_seen|localtime }}</div></div></div></div>
{% else %}<div class="card mute">No devices yet. Add one below.</div>{% endfor %}
<div class="card"><h2>Add a device</h2>
<form method="post" action="{{ url_for('new_device') }}" class="row">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input name="name" placeholder="e.g. Redmi 13" maxlength="40" required><button>Create</button></form></div>
{% endblock %}"""

DEVICE = """{% extends base %}{% block body %}
<p><a href="{{ url_for('home') }}">&larr; All devices</a></p>
<div class="row" style="justify-content:space-between"><h1>{{ dev.name }}
{% if dev.lost_mode %}<span class="tag lost">LOST MODE</span>{% endif %}</h1>
<span class="mute">Last seen: {{ dev.last_seen|localtime }}</span></div>

<div class="card"><div id="map"></div>
{% if last and last.lat is not none %}
<p>Last fix: <b>{{ last.ts|localtime }}</b>, accuracy {{ last.acc|round|int if last.acc else '?' }} m,
battery {{ last.battery if last.battery is not none else '?' }}% {{ last.charging or '' }}, {{ last.network or 'network unknown' }}.
<a href="https://www.google.com/maps?q={{ last.lat }},{{ last.lon }}" target="_blank" rel="noopener">Open in Google Maps</a></p>
{% else %}<p class="mute">No location received yet.</p>{% endif %}</div>

<div class="card"><h2>Commands</h2>
<p class="mute">Delivered the next time the phone contacts the server (every 1 to 5 minutes while it has a connection).</p>
<div class="row">
 <form method="post" action="{{ url_for('send_command', did=dev.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="type" value="locate"><button>Locate now</button></form>
 <form method="post" action="{{ url_for('send_command', did=dev.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="type" value="alarm"><button>Sound alarm</button></form>
 <form method="post" action="{{ url_for('send_command', did=dev.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="type" value="lock"><button class="ghost">Request lock</button></form>
 <form method="post" action="{{ url_for('toggle_lost', did=dev.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
 <button class="{{ 'ghost' if dev.lost_mode else 'bad' }}">{{ 'Turn off lost mode' if dev.lost_mode else 'Turn on lost mode' }}</button></form>
</div>
<form method="post" action="{{ url_for('send_command', did=dev.id) }}" class="row" style="margin-top:10px">
 <input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="type" value="message">
 <input name="payload" placeholder="Message to show on the phone, e.g. call 080..." maxlength="200" style="flex:1;min-width:220px" required><button>Show message</button></form>
{% if cmds %}<table style="margin-top:10px"><tr><th>When</th><th>Command</th><th>Status</th></tr>
{% for c in cmds %}<tr><td>{{ c.created_at|localtime }}</td><td>{{ c.type }}{% if c.payload %}: {{ c.payload }}{% endif %}</td>
<td>{{ c.status }}{% if c.result %} ({{ c.result }}){% endif %}</td></tr>{% endfor %}</table>{% endif %}</div>

<div class="card"><h2>Intruder photos</h2>
{% if photos %}<div class="photos">{% for p in photos %}
<a href="{{ url_for('photo', name=p.filename) }}" target="_blank"><img loading="lazy" src="{{ url_for('photo', name=p.filename) }}" alt="Intruder photo"></a>
{% endfor %}</div>{% else %}<p class="mute">None yet.</p>{% endif %}</div>

<div class="card"><h2>Location history</h2>
<table><tr><th>When</th><th>Position</th><th>Acc</th><th>Batt</th><th>Net</th></tr>
{% for l in history %}<tr><td>{{ l.ts|localtime }}</td>
<td>{% if l.lat is not none %}<a href="https://www.google.com/maps?q={{ l.lat }},{{ l.lon }}" target="_blank" rel="noopener">{{ '%.5f'|format(l.lat) }}, {{ '%.5f'|format(l.lon) }}</a>{% else %}no fix{% endif %}</td>
<td>{{ l.acc|round|int if l.acc else '' }}</td><td>{{ l.battery if l.battery is not none else '' }}</td><td>{{ l.network or '' }}</td></tr>{% endfor %}</table></div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
 const pts = {{ points|tojson }};
 const map = L.map('map').setView(pts.length ? [pts[0][0], pts[0][1]] : [9.08, 8.67], pts.length ? 15 : 5);
 L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19, attribution: '&copy; OpenStreetMap'}).addTo(map);
 if (pts.length) { L.marker([pts[0][0], pts[0][1]]).addTo(map).bindPopup('Last known position');
   if (pts.length > 1) L.polyline(pts.map(p => [p[0], p[1]]), {color: '#4f9dff'}).addTo(map); }
</script>{% endblock %}"""


def render(tpl, **ctx):
    return render_template_string(tpl, base=app.jinja_env.from_string(BASE), **ctx)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not ADMIN_PASSWORD:
        return "ADMIN_PASSWORD is not set on the server.", 500
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        count, first = _attempts.get(ip, (0, time.time()))
        if time.time() - first > 900:
            count, first = 0, time.time()
        if count >= 5:
            return render(LOGIN, error="Too many attempts. Try again in 15 minutes."), 429
        if hmac.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            _attempts.pop(ip, None)
            session.clear()
            session["admin"] = True
            session["csrf"] = secrets.token_hex(16)
            return redirect(url_for("home"))
        _attempts[ip] = (count + 1, first)
        time.sleep(1)
        error = "Wrong password."
    return render(LOGIN, error=error)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@admin_required
def home():
    devices = db().execute("SELECT * FROM devices ORDER BY id").fetchall()
    return render(HOME, devices=devices, new_token=session.pop("new_token", None),
                  new_name=session.pop("new_name", None))


@app.post("/devices/new")
@admin_required
def new_device():
    name = (request.form.get("name") or "").strip()[:40]
    if not name:
        abort(400)
    token = secrets.token_urlsafe(32)
    db().execute("INSERT INTO devices (name, token_hash, created_at) VALUES (?,?,?)",
                 (name, hash_token(token), now_iso()))
    db().commit()
    session["new_token"], session["new_name"] = token, name
    return redirect(url_for("home"))


@app.get("/device/<int:did>")
@admin_required
def device(did):
    dev = db().execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone() or abort(404)
    history = db().execute("SELECT * FROM locations WHERE device_id=? ORDER BY id DESC LIMIT 100",
                           (did,)).fetchall()
    fixes = [l for l in history if l["lat"] is not None]
    cmds = db().execute("SELECT * FROM commands WHERE device_id=? ORDER BY id DESC LIMIT 10",
                        (did,)).fetchall()
    photos = db().execute("SELECT * FROM intruders WHERE device_id=? ORDER BY id DESC LIMIT 24",
                          (did,)).fetchall()
    return render(DEVICE, dev=dev, last=fixes[0] if fixes else None, history=history[:50],
                  points=[[l["lat"], l["lon"]] for l in fixes[:50]], cmds=cmds, photos=photos)


@app.post("/device/<int:did>/command")
@admin_required
def send_command(did):
    ctype = request.form.get("type", "")
    if ctype not in COMMAND_TYPES:
        abort(400)
    db().execute("SELECT 1 FROM devices WHERE id=?", (did,)).fetchone() or abort(404)
    db().execute("INSERT INTO commands (device_id, type, payload, created_at) VALUES (?,?,?,?)",
                 (did, ctype, clip(request.form.get("payload"), 200), now_iso()))
    db().commit()
    return redirect(url_for("device", did=did))


@app.post("/device/<int:did>/lost")
@admin_required
def toggle_lost(did):
    db().execute("UPDATE devices SET lost_mode = 1 - lost_mode WHERE id=?", (did,))
    db().commit()
    return redirect(url_for("device", did=did))


@app.get("/photos/<path:name>")
@admin_required
def photo(name):
    return send_from_directory(PHOTO_DIR, name)


@app.get("/healthz")
def healthz():
    return "ok"


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


if __name__ == "__main__":
    os.environ.setdefault("COOKIE_SECURE", "0")
    app.config["SESSION_COOKIE_SECURE"] = False
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
