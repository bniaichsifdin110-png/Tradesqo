"""
إشارة - الخادم (Flask + SQLite)
التشغيل:  pip install flask   ثم   python server.py   وافتح  http://localhost:5000
"""
import os, re, json, time, sqlite3, urllib.request, urllib.parse
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", BASE)  # على الاستضافة: مجلد القرص الدائم
os.makedirs(DATA, exist_ok=True)
DB = os.path.join(DATA, "isharah.db")
KF = os.path.join(DATA, ".secret")
if not os.path.exists(KF):
    with open(KF, "w") as fh:
        fh.write(os.urandom(32).hex())
ser = URLSafeTimedSerializer(os.environ.get("SECRET_KEY") or open(KF).read())
app = Flask(__name__)
if os.environ.get("PORT"):  # خلف وكيل الاستضافة: اقرأ IP الحقيقي
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE NOT NULL, pw TEXT NOT NULL, ts INT);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, uid INT, kind TEXT, text TEXT, mk TEXT, sym TEXT, side TEXT, en REAL, sl REAL, tp REAL, ts INT);
CREATE TABLE IF NOT EXISTS likes(pid INT, uid INT, PRIMARY KEY(pid, uid));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, pid INT, uid INT, text TEXT, ts INT);
CREATE TABLE IF NOT EXISTS follows(a INT, b INT, PRIMARY KEY(a, b));
CREATE TABLE IF NOT EXISTS journal(id INTEGER PRIMARY KEY, uid INT, strategy TEXT, sym TEXT, side TEXT, en REAL, sl REAL, ex REAL, qty REAL, fee REAL, note TEXT, ts INT);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, sender INT, rcpt INT, text TEXT, ts INT);
CREATE TABLE IF NOT EXISTS reports(pid INT, uid INT, PRIMARY KEY(pid, uid));
"""
with sqlite3.connect(DB) as _c:
    _c.executescript(SCHEMA)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_):
    c = g.pop("db", None)
    if c:
        c.close()


def q(sql, a=()):
    return db().execute(sql, a).fetchall()


def one(sql, a=()):
    r = q(sql, a)
    return r[0] if r else None


def run(sql, a=()):
    c = db().execute(sql, a)
    db().commit()
    return c.lastrowid


def err(m, c=400):
    return jsonify(error=m), c


def auth(f):
    @wraps(f)
    def w(*a, **k):
        try:
            g.uid = ser.loads(request.headers.get("Authorization", "").replace("Bearer ", ""), max_age=2592000)
        except BadSignature:
            return err("سجّل الدخول أولاً", 401)
        return f(*a, **k)
    return w


def pos(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if 0 < x < 1e12 else None


def body():
    return request.get_json(silent=True) or {}


hits = {}


def limited(key, n=10, per=60):
    now = time.time()
    L = [t for t in hits.get(key, []) if now - t < per]
    hits[key] = L
    if len(L) >= n:
        return True
    L.append(now)
    return False


@app.after_request
def hdr(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    return r


# ---------- الحسابات ----------
@app.post("/api/register")
def register():
    if limited(request.remote_addr):
        return err("محاولات كثيرة، انتظر دقيقة ثم أعد المحاولة", 429)
    d = body()
    u, p = (d.get("username") or "").strip(), d.get("password") or ""
    if not re.fullmatch(r"[A-Za-z0-9_\u0600-\u06FF]{3,20}", u):
        return err("اسم المستخدم من 3 إلى 20 حرفاً (حروف وأرقام و _)")
    if len(p) < 8:
        return err("كلمة المرور 8 أحرف على الأقل")
    try:
        uid = run("INSERT INTO users(username,pw,ts) VALUES(?,?,?)", (u, generate_password_hash(p), int(time.time())))
    except sqlite3.IntegrityError:
        return err("اسم المستخدم مستخدم، اختر غيره", 409)
    return jsonify(token=ser.dumps(uid), username=u), 201


@app.post("/api/login")
def login():
    if limited(request.remote_addr):
        return err("محاولات كثيرة، انتظر دقيقة ثم أعد المحاولة", 429)
    d = body()
    r = one("SELECT * FROM users WHERE username=?", ((d.get("username") or "").strip(),))
    if not r or not check_password_hash(r["pw"], d.get("password") or ""):
        return err("بيانات الدخول غير صحيحة", 401)
    return jsonify(token=ser.dumps(r["id"]), username=r["username"])


@app.get("/api/me")
@auth
def me():
    r = one("SELECT username FROM users WHERE id=?", (g.uid,))
    return jsonify(username=r["username"]) if r else err("سجّل الدخول أولاً", 401)


# ---------- المنشورات ----------
@app.get("/api/posts")
@auth
def posts():
    k = request.args.get("kind", "all")
    w, a = "1=1", [g.uid, g.uid]
    if k in ("trade", "free"):
        w, a = "p.kind=?", a + [k]
    elif k == "fol":
        w, a = "(p.uid=? OR p.uid IN (SELECT b FROM follows WHERE a=?))", a + [g.uid, g.uid]
    rows = q(f"""SELECT p.*, u.username u,
      (SELECT COUNT(*) FROM likes WHERE pid=p.id) lk,
      EXISTS(SELECT 1 FROM likes WHERE pid=p.id AND uid=?) ld,
      EXISTS(SELECT 1 FROM follows WHERE a=? AND b=p.uid) fl,
      (SELECT COUNT(*) FROM comments WHERE pid=p.id) cc
      FROM posts p JOIN users u ON u.id=p.uid WHERE {w} AND (SELECT COUNT(*) FROM reports WHERE pid=p.id)<3 ORDER BY p.id DESC LIMIT 60""", a)
    return jsonify([dict(r) for r in rows])


@app.post("/api/posts")
@auth
def new_post():
    d = body()
    kind, t = d.get("kind"), (d.get("text") or "").strip()[:500]
    f = dict(mk=None, sym=None, side=None, en=None, sl=None, tp=None)
    if kind == "trade":
        mk, side, sym = d.get("mk"), d.get("side"), (d.get("sym") or "").strip().upper()
        en, sl, tp = pos(d.get("en")), pos(d.get("sl")), pos(d.get("tp"))
        if mk not in ("futures", "spot") or side not in ("long", "short") \
                or not re.fullmatch(r"[A-Z0-9._-]{2,15}", sym) or not (en and sl and tp):
            return err("أكمل بيانات الصفقة (الرمز والدخول والوقف والهدف)")
        if not (sl < en < tp if side == "long" else tp < en < sl):
            return err("مستويات الدخول والوقف والهدف لا تناسب اتجاه الصفقة")
        f = dict(mk=mk, sym=sym, side=side, en=en, sl=sl, tp=tp)
    elif kind == "free":
        if not t:
            return err("اكتب نصاً قبل النشر")
    else:
        return err("نوع المنشور غير صحيح")
    run("INSERT INTO posts(uid,kind,text,mk,sym,side,en,sl,tp,ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (g.uid, kind, t, f["mk"], f["sym"], f["side"], f["en"], f["sl"], f["tp"], int(time.time())))
    return jsonify(ok=1), 201


@app.post("/api/posts/<int:i>/like")
@auth
def like(i):
    if one("SELECT 1 FROM likes WHERE pid=? AND uid=?", (i, g.uid)):
        run("DELETE FROM likes WHERE pid=? AND uid=?", (i, g.uid))
    else:
        run("INSERT INTO likes VALUES(?,?)", (i, g.uid))
    return jsonify(ok=1)


@app.get("/api/posts/<int:i>/comments")
@auth
def comments(i):
    rows = q("SELECT u.username u, c.text, c.ts FROM comments c JOIN users u ON u.id=c.uid WHERE c.pid=? ORDER BY c.id", (i,))
    return jsonify([dict(r) for r in rows])


@app.post("/api/posts/<int:i>/comments")
@auth
def add_comment(i):
    t = (body().get("text") or "").strip()[:300]
    if not t or not one("SELECT 1 FROM posts WHERE id=?", (i,)):
        return err("تعليق غير صالح")
    run("INSERT INTO comments(pid,uid,text,ts) VALUES(?,?,?,?)", (i, g.uid, t, int(time.time())))
    return jsonify(ok=1), 201


@app.post("/api/posts/<int:i>/report")
@auth
def report(i):
    run("INSERT OR IGNORE INTO reports VALUES(?,?)", (i, g.uid))
    return jsonify(ok=1)


@app.post("/api/follow/<n>")
@auth
def follow(n):
    u = one("SELECT id FROM users WHERE username=?", (n,))
    if not u or u["id"] == g.uid:
        return err("مستخدم غير صالح")
    if one("SELECT 1 FROM follows WHERE a=? AND b=?", (g.uid, u["id"])):
        run("DELETE FROM follows WHERE a=? AND b=?", (g.uid, u["id"]))
    else:
        run("INSERT INTO follows VALUES(?,?)", (g.uid, u["id"]))
    return jsonify(ok=1)


@app.delete("/api/posts/<int:i>")
@auth
def del_post(i):
    if one("SELECT 1 FROM posts WHERE id=? AND uid=?", (i, g.uid)):
        run("DELETE FROM likes WHERE pid=?", (i,))
        run("DELETE FROM comments WHERE pid=?", (i,))
        run("DELETE FROM posts WHERE id=?", (i,))
    return jsonify(ok=1)


# ---------- الجورنال ----------
def calc(r):
    d = 1 if r["side"] == "long" else -1
    pnl = (r["ex"] - r["en"]) * d * r["qty"] - r["fee"]
    risk = abs(r["en"] - r["sl"]) * r["qty"]
    return pnl, (pnl / risk if risk else 0)


def agg(name, rows):
    ps = [calc(r) for r in rows]
    win = sum(p for p, _ in ps if p > 0)
    loss = -sum(p for p, _ in ps if p < 0)
    n = len(ps)
    return dict(s=name, n=n, wr=round(100 * sum(1 for p, _ in ps if p > 0) / n, 1) if n else 0,
                pnl=round(sum(p for p, _ in ps), 2), r=round(sum(x for _, x in ps) / n, 2) if n else 0,
                pf=round(win / loss, 2) if loss else None)


@app.get("/api/journal")
@auth
def journal():
    out = []
    for r in q("SELECT * FROM journal WHERE uid=? ORDER BY id DESC LIMIT 500", (g.uid,)):
        pnl, rr = calc(r)
        out.append({**dict(r), "pnl": round(pnl, 2), "r": round(rr, 2)})
    return jsonify(out)


@app.get("/api/journal/stats")
@auth
def jstats():
    rows = q("SELECT * FROM journal WHERE uid=?", (g.uid,))
    by = {}
    for r in rows:
        by.setdefault(r["strategy"], []).append(r)
    return jsonify(all=agg("all", rows), by=[agg(k, v) for k, v in sorted(by.items())])


@app.post("/api/journal")
@auth
def add_trade():
    d = body()
    st = (d.get("strategy") or "").strip()[:40] or "بدون استراتيجية"
    sym, side = (d.get("sym") or "").strip().upper(), d.get("side")
    en, sl, ex, qty = pos(d.get("en")), pos(d.get("sl")), pos(d.get("ex")), pos(d.get("qty"))
    try:
        fee = max(0.0, float(d.get("fee") or 0))
    except ValueError:
        fee = 0.0
    if not re.fullmatch(r"[A-Z0-9._-]{2,15}", sym) or side not in ("long", "short") or not (en and sl and ex and qty):
        return err("أكمل الرمز والاتجاه والدخول والوقف والخروج والكمية")
    run("INSERT INTO journal(uid,strategy,sym,side,en,sl,ex,qty,fee,note,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (g.uid, st, sym, side, en, sl, ex, qty, fee, (d.get("note") or "").strip()[:300], int(time.time())))
    return jsonify(ok=1), 201


@app.delete("/api/journal/<int:i>")
@auth
def del_trade(i):
    run("DELETE FROM journal WHERE id=? AND uid=?", (i, g.uid))
    return jsonify(ok=1)


# ---------- الرسائل ----------
@app.get("/api/chats")
@auth
def chats():
    rows = q("""SELECT u.username n, m.text, m.ts FROM messages m
      JOIN users u ON u.id = CASE WHEN m.sender=? THEN m.rcpt ELSE m.sender END
      WHERE m.id IN (SELECT MAX(id) FROM messages WHERE sender=? OR rcpt=?
                     GROUP BY CASE WHEN sender=? THEN rcpt ELSE sender END)
      ORDER BY m.id DESC""", (g.uid,) * 4)
    return jsonify([dict(r) for r in rows])


@app.get("/api/messages/<n>")
@auth
def msgs(n):
    p = one("SELECT id FROM users WHERE username=?", (n,))
    if not p:
        return err("المستخدم غير موجود", 404)
    rows = q("""SELECT id, sender=? AS mine, text, ts FROM messages
      WHERE (sender=? AND rcpt=?) OR (sender=? AND rcpt=?) ORDER BY id LIMIT 200""",
             (g.uid, g.uid, p["id"], p["id"], g.uid))
    return jsonify([dict(r) for r in rows])


@app.post("/api/messages/<n>")
@auth
def send(n):
    p = one("SELECT id FROM users WHERE username=?", (n,))
    t = (body().get("text") or "").strip()[:1000]
    if not p or p["id"] == g.uid or not t:
        return err("رسالة غير صالحة")
    run("INSERT INTO messages(sender,rcpt,text,ts) VALUES(?,?,?,?)", (g.uid, p["id"], t, int(time.time())))
    return jsonify(ok=1), 201


# ---------- الأسعار الحية (Binance Spot، بيانات عامة) ----------
SYMS = ["BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT", "DOGEUSDT"]
cache = {"t": 0, "d": []}


@app.get("/api/prices")
def prices():
    if time.time() - cache["t"] > 2:
        try:
            u = "https://data-api.binance.vision/api/v3/ticker/24hr?symbols=" + \
                urllib.parse.quote(json.dumps(SYMS, separators=(",", ":")))
            raw = json.load(urllib.request.urlopen(u, timeout=5))
            raw.sort(key=lambda x: SYMS.index(x["symbol"]))
            cache.update(t=time.time(), d=[dict(s=x["symbol"], p=float(x["lastPrice"]), c=float(x["priceChangePercent"]),
                                                h=float(x["highPrice"]), l=float(x["lowPrice"])) for x in raw])
        except Exception:
            if not cache["d"]:
                return err("مصدر الأسعار غير متاح من هذا الخادم", 503)
    return jsonify(cache["d"])


@app.get("/")
def index():
    return send_from_directory(BASE, "index.html")


@app.get("/healthz")
def healthz():
    return "ok"


PUBLIC = {"manifest.json", "sw.js", "icon-192.png", "icon-512.png", "terms.html"}


@app.get("/<f>")
def public_file(f):
    if f not in PUBLIC:
        return err("غير موجود", 404)
    return send_from_directory(BASE, f)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
