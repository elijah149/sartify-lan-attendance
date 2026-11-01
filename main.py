import os, re, csv, io, calendar, sqlite3, secrets, hashlib, hmac, ipaddress
from datetime import datetime, date as ddate
from contextlib import closing
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

DB = "attendance.db"
SECRET = os.environ.get("SECRET_KEY", "change-this-secret")
NETS = [ipaddress.ip_network(n.strip()) for n in os.environ.get(
    "ALLOWED_NETWORKS", "127.0.0.1/32,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12").split(",")]

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with closing(db()) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            staff_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            active INTEGER NOT NULL DEFAULT 1,
            device_hash TEXT,
            must_change INTEGER NOT NULL DEFAULT 1,
            created_date TEXT
        );
        CREATE TABLE IF NOT EXISTS attendance(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            work_date TEXT NOT NULL,
            check_in TEXT,
            check_out TEXT,
            ip_in TEXT,
            ip_out TEXT,
            UNIQUE(user_id, work_date)
        );
        """)
        # Migration: older databases do not have the registration date yet
        cols = [r["name"] for r in c.execute("PRAGMA table_info(users)").fetchall()]
        if "created_date" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN created_date TEXT")
        c.execute("UPDATE users SET created_date = COALESCE("
                  "(SELECT MIN(work_date) FROM attendance WHERE attendance.user_id = users.id), "
                  "date('now','localtime')) WHERE created_date IS NULL AND role='user'")
        c.commit()


init_db()


def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", p.encode(), bytes.fromhex(salt), 200000).hex()
    return f"{salt}${h}"


def check_pw(p, stored):
    salt, h = stored.split("$")
    return hmac.compare_digest(hash_pw(p, salt).split("$")[1], h)


# ---------------- Report helpers ----------------
def secs(t: str) -> int:
    parts = t.split(":")
    h, m = int(parts[0]), int(parts[1])
    s = int(parts[2]) if len(parts) > 2 else 0
    return h * 3600 + m * 60 + s


def hours_worked(check_in, check_out):
    if check_in and check_out:
        return round((secs(check_out) - secs(check_in)) / 3600, 2)
    return None


def build_report(month: str):
    y, m = int(month[:4]), int(month[5:7])
    today = ddate.today()
    last = calendar.monthrange(y, m)[1]
    if ddate(y, m, 1) > today:
        end_day = 0
    elif (y, m) == (today.year, today.month):
        end_day = today.day
    else:
        end_day = last

    workday_set = set()
    for d in range(1, end_day + 1):
        dd = ddate(y, m, d)
        if dd.weekday() < 5:
            workday_set.add(dd.isoformat())
    workdays = len(workday_set)

    with closing(db()) as c:
        users = c.execute("SELECT id, full_name, staff_id, created_date FROM users "
                          "WHERE role='user' AND active=1 ORDER BY full_name").fetchall()
        rows = c.execute("SELECT a.*, u.full_name, u.staff_id FROM attendance a "
                         "JOIN users u ON u.id=a.user_id WHERE a.work_date LIKE ? "
                         "ORDER BY a.work_date, u.full_name", (month + "-%",)).fetchall()

    details = []
    summary = {u["id"]: {"full_name": u["full_name"], "staff_id": u["staff_id"],
                         "start": u["created_date"], "present": 0, "present_work": 0,
                         "hours": 0.0} for u in users}
    for r in rows:
        hours = hours_worked(r["check_in"], r["check_out"])
        details.append({"work_date": r["work_date"], "full_name": r["full_name"],
                        "staff_id": r["staff_id"], "check_in": r["check_in"],
                        "check_out": r["check_out"], "hours": hours})
        s = summary.get(r["user_id"])
        if s is not None:
            s["present"] += 1
            s["hours"] += hours or 0
            # only days after the registration day count against absence
            if r["work_date"] in workday_set and (s["start"] is None or r["work_date"] > s["start"]):
                s["present_work"] += 1
    summ = []
    for s in summary.values():
        s["hours"] = round(s["hours"], 2)
        counted = sum(1 for d in workday_set if s["start"] is None or d > s["start"])
        s["workdays"] = counted
        s["absent"] = max(0, counted - s["present_work"])
        summ.append(s)
    return summ, details, workdays


def clean_month(month: str) -> str:
    if month and re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
        return month
    return datetime.now().strftime("%Y-%m")


@app.middleware("http")
async def lan_only(request: Request, call_next):
    ip = request.client.host if request.client else ""
    try:
        ok = any(ipaddress.ip_address(ip) in n for n in NETS)
    except ValueError:
        ok = False
    if not ok:
        return HTMLResponse("Access denied: office network only.", status_code=403)
    return await call_next(request)


app.add_middleware(SessionMiddleware, secret_key=SECRET, max_age=60 * 60 * 10, same_site="lax")


def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with closing(db()) as c:
        u = c.execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
    return u


@app.get("/")
def root(request: Request):
    u = current_user(request)
    if not u:
        return RedirectResponse("/login", 303)
    if u["must_change"]:
        return RedirectResponse("/change-password", 303)
    return RedirectResponse("/admin" if u["role"] == "admin" else "/dashboard", 303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    def fail(msg):
        return templates.TemplateResponse(request, "login.html", {"error": msg}, status_code=401)

    with closing(db()) as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (username.strip(),)).fetchone()
        if not u or not u["active"] or not check_pw(password, u["password_hash"]):
            return fail("Invalid username or password")
        device = request.cookies.get("device_id") or secrets.token_hex(24)
        dh = hashlib.sha256(device.encode()).hexdigest()
        if u["role"] == "user":
            other = c.execute("SELECT id FROM users WHERE device_hash=? AND id!=?", (dh, u["id"])).fetchone()
            if other:
                return fail("This device belongs to another user.")
            if u["device_hash"] is None:
                c.execute("UPDATE users SET device_hash=? WHERE id=?", (dh, u["id"]))
                c.commit()
            elif u["device_hash"] != dh:
                return fail("Account is bound to another device. Ask the admin to reset it.")
        request.session["uid"] = u["id"]
    resp = RedirectResponse("/", 303)
    resp.set_cookie("device_id", device, max_age=31536000, httponly=True, samesite="lax")
    return resp


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", 303)


@app.get("/change-password", response_class=HTMLResponse)
def change_pw_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", 303)
    return templates.TemplateResponse(request, "change_password.html", {"error": None})


@app.post("/change-password")
def change_pw(request: Request, password: str = Form(...), confirm: str = Form(...)):
    u = current_user(request)
    if not u:
        return RedirectResponse("/login", 303)
    if len(password) < 8 or password != confirm:
        return templates.TemplateResponse(
            request, "change_password.html",
            {"error": "Passwords must match and be at least 8 characters."}, status_code=400)
    with closing(db()) as c:
        c.execute("UPDATE users SET password_hash=?, must_change=0 WHERE id=?", (hash_pw(password), u["id"]))
        c.commit()
    return RedirectResponse("/", 303)


# ---------------- User side ----------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, msg: str = ""):
    u = current_user(request)
    if not u:
        return RedirectResponse("/login", 303)
    if u["must_change"]:
        return RedirectResponse("/change-password", 303)
    today = datetime.now().strftime("%Y-%m-%d")
    with closing(db()) as c:
        rec = c.execute("SELECT * FROM attendance WHERE user_id=? AND work_date=?", (u["id"], today)).fetchone()
        history = c.execute("SELECT * FROM attendance WHERE user_id=? ORDER BY work_date DESC LIMIT 14",
                            (u["id"],)).fetchall()
    return templates.TemplateResponse(request, "dashboard.html",
                                      {"user": u, "rec": rec, "history": history, "msg": msg})


@app.post("/checkin")
def checkin(request: Request):
    u = current_user(request)
    if not u:
        return RedirectResponse("/login", 303)
    now = datetime.now()
    try:
        with closing(db()) as c:
            c.execute("INSERT INTO attendance(user_id, work_date, check_in, ip_in) VALUES(?,?,?,?)",
                      (u["id"], now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S"), request.client.host))
            c.commit()
        msg = "Checked in successfully."
    except sqlite3.IntegrityError:
        msg = "You already checked in today."
    return RedirectResponse(f"/dashboard?msg={msg}", 303)


@app.post("/checkout")
def checkout(request: Request):
    u = current_user(request)
    if not u:
        return RedirectResponse("/login", 303)
    now = datetime.now()
    with closing(db()) as c:
        cur = c.execute("UPDATE attendance SET check_out=?, ip_out=? "
                        "WHERE user_id=? AND work_date=? AND check_in IS NOT NULL AND check_out IS NULL",
                        (now.strftime("%H:%M:%S"), request.client.host, u["id"], now.strftime("%Y-%m-%d")))
        c.commit()
    msg = "Checked out successfully." if cur.rowcount else "Cannot check out (not checked in, or already checked out)."
    return RedirectResponse(f"/dashboard?msg={msg}", 303)


# ---------------- Admin side ----------------
def admin_only(request: Request):
    u = current_user(request)
    return u if u and u["role"] == "admin" else None


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, date: str = "", msg: str = ""):
    if not admin_only(request):
        return RedirectResponse("/login", 303)
    date = date or datetime.now().strftime("%Y-%m-%d")
    try:
        weekend = ddate.fromisoformat(date).weekday() >= 5
    except ValueError:
        weekend = False
    with closing(db()) as c:
        users = c.execute("SELECT * FROM users WHERE role='user' ORDER BY full_name").fetchall()
        records = c.execute("SELECT a.*, u.full_name, u.staff_id FROM attendance a "
                            "JOIN users u ON u.id=a.user_id WHERE a.work_date=? ORDER BY a.check_in",
                            (date,)).fetchall()
        absent = []
        if not weekend:
            # absence starts the day after registration
            absent = c.execute("SELECT full_name, staff_id FROM users WHERE role='user' AND active=1 "
                               "AND (created_date IS NULL OR created_date < ?) "
                               "AND id NOT IN (SELECT user_id FROM attendance WHERE work_date=?)",
                               (date, date)).fetchall()
    return templates.TemplateResponse(request, "admin.html",
                                      {"users": users, "records": records, "absent": absent,
                                       "date": date, "msg": msg, "weekend": weekend})


@app.get("/admin/report", response_class=HTMLResponse)
def report_page(request: Request, month: str = "", day: str = ""):
    if not admin_only(request):
        return RedirectResponse("/login", 303)
    month = clean_month(month)
    summary, details, workdays = build_report(month)

    y, m = int(month[:4]), int(month[5:7])
    last = calendar.monthrange(y, m)[1]
    day_min = ddate(y, m, 1).isoformat()
    day_max = ddate(y, m, last).isoformat()
    today = ddate.today()
    try:
        d = ddate.fromisoformat(day)
    except ValueError:
        d = None
    if d is None or not (day_min <= d.isoformat() <= day_max):
        if (today.year, today.month) == (y, m):
            d = today
        elif ddate(y, m, 1) > today:
            d = ddate(y, m, 1)
        else:
            d = ddate(y, m, last)
    day = d.isoformat()
    day_rows = [x for x in details if x["work_date"] == day]

    return templates.TemplateResponse(request, "report.html",
                                      {"month": month, "summary": summary, "workdays": workdays,
                                       "day": day, "day_rows": day_rows,
                                       "day_min": day_min, "day_max": day_max})


@app.get("/admin/report.csv")
def report_csv(request: Request, month: str = "", kind: str = "detail"):
    if not admin_only(request):
        return RedirectResponse("/login", 303)
    month = clean_month(month)
    summary, details, _ = build_report(month)
    out = io.StringIO()
    w = csv.writer(out)
    if kind == "summary":
        w.writerow(["Name", "Staff ID", "Registered", "Workdays counted", "Days present", "Absent", "Total hours"])
        for s in summary:
            w.writerow([s["full_name"], s["staff_id"], s["start"] or "", s["workdays"],
                        s["present"], s["absent"], s["hours"]])
        fname = f"attendance_summary_{month}.csv"
    else:
        w.writerow(["Date", "Name", "Staff ID", "Check in", "Check out", "Hours"])
        for d in details:
            w.writerow([d["work_date"], d["full_name"], d["staff_id"], d["check_in"] or "",
                        d["check_out"] or "", d["hours"] if d["hours"] is not None else ""])
        fname = f"attendance_detail_{month}.csv"
    return Response(content=out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.post("/admin/users")
def add_user(request: Request, full_name: str = Form(...), staff_id: str = Form(...),
             username: str = Form(...), password: str = Form(...)):
    if not admin_only(request):
        return RedirectResponse("/login", 303)
    try:
        with closing(db()) as c:
            c.execute("INSERT INTO users(full_name, staff_id, username, password_hash, role, must_change, created_date) "
                      "VALUES(?,?,?,?, 'user', 1, ?)",
                      (full_name.strip(), staff_id.strip(), username.strip(), hash_pw(password),
                       ddate.today().isoformat()))
            c.commit()
        msg = "User registered."
    except sqlite3.IntegrityError:
        msg = "Staff ID or username already exists."
    return RedirectResponse(f"/admin?msg={msg}", 303)


@app.post("/admin/users/{uid}/reset-device")
def reset_device(request: Request, uid: int):
    if not admin_only(request):
        return RedirectResponse("/login", 303)
    with closing(db()) as c:
        c.execute("UPDATE users SET device_hash=NULL WHERE id=? AND role='user'", (uid,))
        c.commit()
    return RedirectResponse("/admin?msg=Device reset.", 303)


@app.post("/admin/users/{uid}/toggle")
def toggle_user(request: Request, uid: int):
    if not admin_only(request):
        return RedirectResponse("/login", 303)
    with closing(db()) as c:
        c.execute("UPDATE users SET active = 1 - active WHERE id=? AND role='user'", (uid,))
        c.commit()
    return RedirectResponse("/admin?msg=User status changed.", 303)
