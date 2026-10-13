import os
import json
import re
import subprocess
import shutil
import psutil
import socket
import sys
import hashlib
import secrets
import time
import requests
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, session, redirect, url_for, make_response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
os.makedirs(USERS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=BASE_DIR)
SECRET_KEY_FILE = os.path.join(BASE_DIR, ".flask_secret")
def load_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    try:
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    except OSError:
        pass
    key = secrets.token_hex(32)
    try:
        with open(SECRET_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(key)
    except OSError:
        pass
    return key

app.secret_key = load_secret_key()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

running_procs = {}
USERS_FILE = os.path.join(BASE_DIR, "users.json")
REMEMBER_TOKENS_FILE = os.path.join(BASE_DIR, "remember_tokens.json")

# الحساب الرئيسي (المسؤول)
ADMIN_USERNAME = "7826514908"
ADMIN_PASSWORD = "7826514908"

# ============== Helper Functions ==============

def init_users_db():
    """Initialize users and migrate the configured admin account."""
    if not os.path.exists(USERS_FILE):
        users = {}
    else:
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                users = json.load(f)
            if not isinstance(users, dict):
                users = {}
        except (OSError, json.JSONDecodeError):
            users = {}

    existing_admin_key = next(
        (name for name, data in users.items()
         if isinstance(data, dict) and data.get("is_admin")),
        None
    )
    if ADMIN_USERNAME not in users:
        if existing_admin_key:
            users[ADMIN_USERNAME] = users.pop(existing_admin_key)
        else:
            users[ADMIN_USERNAME] = {
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "theme": "premium",
                "can_create_users": True
            }

    admin_data = users[ADMIN_USERNAME]
    admin_data["password"] = hash_password(ADMIN_PASSWORD)
    admin_data["is_admin"] = True
    admin_data["can_create_users"] = True
    admin_data.setdefault("created_at", datetime.now().isoformat())

    now = datetime.now()
    for username, data in users.items():
        if not isinstance(data, dict):
            continue
        if username != ADMIN_USERNAME:
            data.setdefault("is_admin", False)
            if not data.get("expires_at"):
                data["expires_at"] = (now + timedelta(days=30)).isoformat()
                data["expiry_days_set"] = 30

    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def init_tokens_db():
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_remember_token(username):
    """إنشاء رمز تذكر جديد للمستخدم"""
    init_tokens_db()
    
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    
    tokens[token] = {
        "username": username,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires,
        "last_used": datetime.now().isoformat()
    }
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    
    return token

def validate_remember_token(token):
    """التحقق من رمز التذكر"""
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        return None
    
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    if token not in tokens:
        return None
    
    token_data = tokens[token]
    expires_at = datetime.fromisoformat(token_data["expires_at"])
    
    if datetime.now() > expires_at:
        del tokens[token]
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
        return None
    
    token_data["last_used"] = datetime.now().isoformat()
    tokens[token] = token_data
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    
    return token_data["username"]

def delete_remember_token(token):
    """حذف رمز التذكر"""
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        return
    
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    if token in tokens:
        del tokens[token]
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)

def delete_all_user_tokens(username):
    """حذف جميع رموز التذكر للمستخدم"""
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        return
    
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    
    tokens_to_delete = []
    for token, data in tokens.items():
        if data["username"] == username:
            tokens_to_delete.append(token)
    
    for token in tokens_to_delete:
        del tokens[token]
    
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)

def account_expiry_status(user_data):
    if not user_data or user_data.get("is_admin") or not user_data.get("expires_at"):
        return False, None
    try:
        expiry = datetime.fromisoformat(user_data["expires_at"])
    except (TypeError, ValueError):
        return False, None
    seconds = (expiry - datetime.now()).total_seconds()
    return seconds <= 0, max(0, int((seconds + 86399) // 86400))


def register_user(username, password, created_by_admin=False, days=30):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username in users:
        return False, "المستخدم موجود بالفعل"
    
    if len(password) < 6:
        return False, "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
    
    created_at = datetime.now()
    users[username] = {
        "password": hash_password(password),
        "created_at": created_at.isoformat(),
        "expires_at": (created_at + timedelta(days=days)).isoformat(),
        "expiry_days_set": days,
        "last_login": None,
        "theme": "blue",
        "is_admin": username == ADMIN_USERNAME,
        "created_by_admin": created_by_admin,
        "created_by": session.get('username') if 'username' in session else None
    }
    
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    user_dir = os.path.join(USERS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    
    return True, "تم إنشاء الحساب بنجاح"

def authenticate_user(username, password):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username not in users:
        return False, "المستخدم غير موجود"
    
    if users[username]["password"] != hash_password(password):
        return False, "كلمة المرور غير صحيحة"
    
    users[username]["last_login"] = datetime.now().isoformat()
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    return True, "تم تسجيل الدخول بنجاح"

def is_admin(username):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username in users:
        return users[username].get("is_admin", False)
    return False

def get_user_servers_dir(username):
    return os.path.join(USERS_DIR, username, "SERVERS")

def ensure_user_servers_dir():
    if 'username' not in session:
        return None
    user_dir = get_user_servers_dir(session['username'])
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def sanitize_folder_name(name):
    if not name: return ""
    name = name.strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", name)
    return name[:200]

def sanitize_filename(name):
    if not name: return ""
    name = name.strip()
    name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", name)
    return name[:200]

def ensure_meta(folder):
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir:
        return None
    
    meta_path = os.path.join(user_servers_dir, folder, "meta.json")
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"display_name": folder, "startup_file": ""}, f)
    return meta_path

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: 
        return '127.0.0.1'

def load_servers_list():
    if 'username' not in session:
        return []
    
    user_servers_dir = ensure_user_servers_dir()
    if not user_servers_dir or not os.path.exists(user_servers_dir):
        return []
    
    try:
        entries = [d for d in os.listdir(user_servers_dir) 
                  if os.path.isdir(os.path.join(user_servers_dir, d))]
    except: 
        entries = []
    
    servers = []
    for i, folder in enumerate(entries, start=1):
        ensure_meta(folder)
        runtime = "python"
        meta_path = os.path.join(user_servers_dir, folder, "meta.json")
        display_name, startup_file = folder, ""
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                display_name = meta.get("display_name", folder)
                startup_file = meta.get("startup_file", "")
                runtime = meta.get("runtime", "python")
        except: 
            pass
        servers.append({
            "id": i,
            "title": display_name,
            "folder": folder,
            "subtitle": f"Project-{i} · Local",
            "startup_file": startup_file,
            "runtime": locals().get("runtime", "python")
        })
    return servers

# ============== Runtime helpers (Python / Node.js) ==============
def available_runtimes():
    py_bins = []
    for name in ("python3", "python3.13", "python3.12", "python3.11", "python3.10", "python3.9", "python"):
        path = shutil.which(name)
        if path and path not in [x["path"] for x in py_bins]:
            try:
                ver = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3)
                label = (ver.stdout or ver.stderr).strip() or name
            except Exception:
                label = name
            py_bins.append({"label": label, "path": path})
    node_bins, npm_bins = [], []
    for name in ("node", "nodejs", "node18", "node20", "node22", "node24"):
        path = shutil.which(name)
        if path and path not in [x["path"] for x in node_bins]:
            try:
                ver = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3)
                label = "Node.js " + ((ver.stdout or ver.stderr).strip() or name)
            except Exception:
                label = name
            node_bins.append({"label": label, "path": path})
    for name in ("npm", "npm10", "npm11", "npm9", "npm8"):
        path = shutil.which(name)
        if path and path not in [x["path"] for x in npm_bins]:
            try:
                ver = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3)
                label = "npm " + ((ver.stdout or ver.stderr).strip() or name)
            except Exception:
                label = name
            npm_bins.append({"label": label, "path": path})
    return {"python": py_bins, "node_versions": node_bins, "npm_versions": npm_bins,
            "node": node_bins[0] if node_bins else {"path": None, "label": "Node.js غير منصب"},
            "npm": npm_bins[0] if npm_bins else {"path": None, "label": "npm غير منصب"}}

def get_project_meta(folder):
    base = ensure_user_servers_dir()
    safe = sanitize_folder_name(folder)
    if not base or not safe or safe != folder:
        return None, None
    project = os.path.realpath(os.path.join(base, safe))
    if os.path.commonpath([os.path.realpath(base), project]) != os.path.realpath(base) or not os.path.isdir(project):
        return None, None
    meta_path = ensure_meta(safe)
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception:
        meta = {"display_name": safe, "startup_file": ""}
    meta.setdefault("runtime", "python")
    meta.setdefault("python_bin", sys.executable)
    meta.setdefault("run_mode", "file")
    meta.setdefault("node_bin", available_runtimes()["node"]["path"])
    meta.setdefault("npm_bin", available_runtimes()["npm"]["path"])
    return project, meta

# ============== Routes ==============

@app.before_request
def check_remember_token():
    """Restore remembered sessions and block accounts after their expiry."""
    if 'username' not in session:
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            username = validate_remember_token(remember_token)
            if username:
                session['username'] = username
                session.permanent = True

    username = session.get("username")
    if not username:
        return None
    try:
        init_users_db()
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
        user_data = users.get(username)
        if not user_data:
            session.pop("username", None)
            return None
        expired, _ = account_expiry_status(user_data)
        if expired:
            session.pop("username", None)
            delete_all_user_tokens(username)
            response = jsonify({"success": False, "expired": True,
                                "message": "انتهت مدة الحساب، تواصل مع المسؤول لتجديده"})
            response.status_code = 403
            if request.path.startswith("/api/") or request.path.startswith("/files/"):
                return response
            return redirect(url_for("login_page"))
    except (OSError, ValueError, TypeError):
        pass
    return None

@app.route("/")
def home():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    # إذا كان المستخدم مسؤولاً، توجيهه لوحة إنشاء الحسابات
    if is_admin(session['username']):
        return send_from_directory(BASE_DIR, "admin_panel.html")
    
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/index.html")
def serve_index():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    if is_admin(session['username']):
        return redirect(url_for('home'))
    
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/login")
def login_page():
    if 'username' in session:
        return redirect(url_for('home'))
    return send_from_directory(BASE_DIR, "login.html")

@app.route("/admin")
def admin_panel():
    if 'username' not in session or not is_admin(session['username']):
        return redirect(url_for('login_page'))
    return send_from_directory(BASE_DIR, "admin_panel.html")

@app.route("/api/register", methods=["POST"])
def api_register():
    # فقط المسؤول يمكنه إنشاء حسابات
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    try:
        days = int(data.get("days", 30))
    except (TypeError, ValueError):
        days = 0
    if not username or not password:
        return jsonify({"success": False, "message": "اسم المستخدم وكلمة المرور مطلوبان"})
    if days < 1 or days > 3650:
        return jsonify({"success": False, "message": "مدة الحساب يجب أن تكون بين 1 و3650 يوماً"})
    try:
        success, message = register_user(username, password, created_by_admin=True, days=days)
        return jsonify({"success": success, "message": message})
    except (OSError, ValueError, TypeError) as exc:
        app.logger.exception("Account registration failed")
        return jsonify({"success": False, "message": "تعذر حفظ الحساب على الخادم. راجع سجلات التطبيق وصلاحيات الكتابة."}), 500

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    remember_me = data.get("remember_me", False)
    
    if not username or not password:
        return jsonify({"success": False, "message": "اسم المستخدم وكلمة المرور مطلوبان"})
    
    success, message = authenticate_user(username, password)
    if success:
        session['username'] = username
        
        response_data = {
            "success": True, 
            "message": message,
            "username": username,
            "is_admin": is_admin(username)
        }
        
        if remember_me:
            token = create_remember_token(username)
            response = make_response(jsonify(response_data))
            response.set_cookie(
                'remember_token',
                token,
                max_age=30*24*60*60,
                httponly=True,
                secure=False,
                samesite='Strict'
            )
            return response
        
        return jsonify(response_data)
    
    return jsonify({"success": False, "message": message})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    username = session.get('username')
    
    if username:
        delete_all_user_tokens(username)
    
    session.pop('username', None)
    
    response = make_response(jsonify({"success": True, "message": "تم تسجيل الخروج"}))
    response.set_cookie('remember_token', '', expires=0)
    
    return response

@app.route("/api/current_user")
def api_current_user():
    if 'username' in session:
        admin = is_admin(session['username'])
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            user_data = json.load(f).get(session['username'], {})
        _, remaining_days = account_expiry_status(user_data)
        return jsonify({
            "success": True,
            "username": session['username'],
            "is_admin": admin,
            "expires_at": user_data.get("expires_at"),
            "days_remaining": remaining_days,
            "has_remember_token": bool(request.cookies.get('remember_token'))
        })
    return jsonify({"success": False})

@app.route("/api/user/settings", methods=["GET", "POST"])
def user_settings():
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    if request.method == "GET":
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
        
        user_data = users.get(session['username'], {})
        return jsonify({
            "success": True,
            "username": session['username'],
            "created_at": user_data.get("created_at"),
            "last_login": user_data.get("last_login"),
            "theme": user_data.get("theme", "blue"),
            "is_admin": user_data.get("is_admin", False)
        })
    
    data = request.get_json()
    theme = data.get("theme", "blue")
    
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if session['username'] in users:
        users[session['username']]["theme"] = theme
        
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        
        return jsonify({"success": True, "message": "تم تحديث الإعدادات"})
    
    return jsonify({"success": False, "message": "المستخدم غير موجود"})

# ============== Protected Routes ==============

@app.route("/api/runtimes")
def api_runtimes():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    return jsonify(available_runtimes())

@app.route("/servers")
def get_servers():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    return jsonify({"success": True, "servers": load_servers_list()})

@app.route("/add", methods=["POST"])
def add_server():
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    folder = sanitize_folder_name(name)
    
    user_servers_dir = ensure_user_servers_dir()
    target = os.path.join(user_servers_dir, folder)
    
    if os.path.exists(target): 
        return jsonify({"success": False, "message": "Exists"}), 409
    
    os.makedirs(target)
    ensure_meta(folder)
    open(os.path.join(target, "server.log"), "w").close()
    return jsonify({"success": True, "servers": load_servers_list()})

@app.route("/server/stats/<folder>")
def get_stats(folder):
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    proc_key = f"{session['username']}_{folder}"
    proc = running_procs.get(proc_key)
    running = False
    cpu, mem = "0%", "0 MB"
    
    if proc and psutil.pid_exists(proc.pid):
        try:
            p = psutil.Process(proc.pid)
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                running = True
                cpu = f"{p.cpu_percent(interval=None)}%"
                mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
        except: 
            pass
    
    project_dir, _meta = get_project_meta(folder)
    if not project_dir:
        return jsonify({"success": False, "message": "مجلد المشروع غير موجود"}), 404
    log_path = os.path.join(project_dir, "server.log")
    try:
        if os.path.exists(log_path):
            with open(log_path, "rb") as log_file:
                log_file.seek(0, os.SEEK_END)
                size = log_file.tell()
                log_file.seek(max(0, size - 60000))
                logs = log_file.read().decode("utf-8", errors="replace")
        else:
            logs = ""
    except OSError:
        logs = "تعذر قراءة السجل"
    
    return jsonify({
        "status": "Running" if running else "Offline", 
        "cpu": cpu, 
        "mem": mem, 
        "logs": logs, 
        "ip": get_ip()
    })

@app.route("/server/action/<folder>/<act>", methods=["POST"])
def server_action(folder, act):
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    
    proc_key = f"{session['username']}_{folder}"
    
    if proc_key in running_procs:
        try:
            p = psutil.Process(running_procs[proc_key].pid)
            for child in p.children(recursive=True): 
                child.kill()
            p.kill()
        except: 
            pass
        if act == "stop": 
            del running_procs[proc_key]
    
    if act == "stop": 
        return jsonify({"success": True})

    user_servers_dir = ensure_user_servers_dir()
    log_path = os.path.join(user_servers_dir, folder, "server.log")
    open(log_path, "w").close()
    
    meta_path = ensure_meta(folder)
    if not meta_path:
        return jsonify({"success": False, "message": "مجلد غير موجود"})
    
    project_dir, meta = get_project_meta(folder)
    if not project_dir:
        return jsonify({"success": False, "message": "مجلد المشروع غير موجود"}), 404
    runtime = meta.get("runtime", "python")
    startup = (meta.get("startup_file") or "").strip()
    mode = meta.get("run_mode", "file")
    runtimes = available_runtimes()
    if runtime == "node":
        node_bin = meta.get("node_bin") or runtimes["node"]["path"]
        npm_bin = meta.get("npm_bin") or runtimes["npm"]["path"]
        if node_bin not in {x["path"] for x in runtimes["node_versions"]}: node_bin = runtimes["node"]["path"]
        if npm_bin not in {x["path"] for x in runtimes["npm_versions"]}: npm_bin = runtimes["npm"]["path"]
        if mode == "npm":
            if not npm_bin or not node_bin or not os.path.isfile(os.path.join(project_dir, "package.json")):
                return jsonify({"success": False, "message": "خاص Node.js و package.json و npm يكونو متوفرين"}), 400
            command = [npm_bin, "start"]
        else:
            if not startup or os.path.basename(startup) != startup or not os.path.isfile(os.path.join(project_dir, startup)):
                return jsonify({"success": False, "message": "اختار ملف JavaScript الرئيسي من إعدادات Runtime"}), 400
            if not node_bin:
                return jsonify({"success": False, "message": "Node.js ما منصبش فالسيرفر"}), 400
            command = [node_bin, startup]
    else:
        py_bin = meta.get("python_bin", sys.executable)
        allowed = {x["path"] for x in runtimes["python"]}
        if py_bin not in allowed:
            py_bin = sys.executable
        if not startup or os.path.basename(startup) != startup or not os.path.isfile(os.path.join(project_dir, startup)):
            return jsonify({"success": False, "message": "اختار ملف Python الرئيسي من إعدادات Runtime"}), 400
        venv_python = os.path.join(project_dir, ".venv", "bin", "python")
        if os.path.isfile(venv_python):
            py_bin = venv_python
        command = [py_bin, "-u", startup]
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write("\n[SYSTEM] Starting: " + " ".join(command) + "\n")
    log_file = open(log_path, "a", encoding="utf-8")
    run_env = os.environ.copy()
    if runtime == "node":
        chosen_node = meta.get("node_bin") or runtimes["node"]["path"]
        if chosen_node:
            run_env["PATH"] = os.path.dirname(chosen_node) + os.pathsep + run_env.get("PATH", "")
    proc = subprocess.Popen(command, cwd=project_dir, stdout=log_file, stderr=log_file, start_new_session=True, env=run_env)
    running_procs[proc_key] = proc
    return jsonify({"success": True, "command": command})

@app.route("/files/list/<folder>")
def list_files(folder):
    if 'username' not in session:
        return jsonify([]), 401
    
    user_servers_dir = ensure_user_servers_dir()
    p = os.path.join(user_servers_dir, folder)
    files = []
    if os.path.exists(p):
        for f in os.listdir(p):
            if f in ["meta.json", "server.log"]: 
                continue
            f_path = os.path.join(p, f)
            if os.path.isfile(f_path):
                files.append({"name": f, "size": f"{os.path.getsize(f_path) / 1024:.1f} KB"})
    return jsonify(files)

@app.route("/files/content/<folder>/<filename>")
def get_file_content(folder, filename):
    if 'username' not in session:
        return jsonify({"content": ""}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    file_path = os.path.join(user_servers_dir, folder, filename)
    
    if not file_path.startswith(user_servers_dir):
        return jsonify({"content": ""}), 403
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return jsonify({"content": f.read()})
    except: 
        return jsonify({"content": ""})

@app.route("/files/save/<folder>/<filename>", methods=["POST"])
def save_file_content(folder, filename):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    file_path = os.path.join(user_servers_dir, folder, filename)
    
    if not file_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    data = request.json
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(data.get('content', ''))
    return jsonify({"success": True})

@app.route("/files/upload/<folder>", methods=["POST"])
def upload_file(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    
    # رفع ملفات متعددة تلقائياً
    uploaded_files = request.files.getlist('files[]')
    results = []
    
    for f in uploaded_files:
        if f and f.filename:
            safe_name = sanitize_filename(f.filename)
            save_path = os.path.join(user_servers_dir, folder, safe_name)
            f.save(save_path)
            results.append({
                "name": safe_name,
                "size": f"{os.path.getsize(save_path) / 1024:.2f} KB"
            })
    
    return jsonify({
        "success": True, 
        "message": f"تم رفع {len(results)} ملف بنجاح",
        "uploaded_files": results
    })

@app.route("/files/upload-single/<folder>", methods=["POST"])
def upload_single_file(folder):
    """رفع ملف واحد تلقائياً عند الاختيار"""
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "لم يتم اختيار ملف"})
    
    f = request.files['file']
    
    if f and f.filename:
        safe_name = sanitize_filename(f.filename)
        save_path = os.path.join(user_servers_dir, folder, safe_name)
        f.save(save_path)
        
        return jsonify({
            "success": True,
            "message": "تم رفع الملف بنجاح",
            "file": {
                "name": safe_name,
                "size": f"{os.path.getsize(save_path) / 1024:.2f} KB"
            }
        })
    
    return jsonify({"success": False, "message": "فشل رفع الملف"})

@app.route("/files/rename/<folder>", methods=["POST"])
def rename_file(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    data = request.get_json()
    
    old_path = os.path.join(user_servers_dir, folder, data['old'])
    new_path = os.path.join(user_servers_dir, folder, data['new'])
    
    if not old_path.startswith(user_servers_dir) or not new_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    os.rename(old_path, new_path)
    return jsonify({"success": True})

@app.route("/files/delete/<folder>", methods=["POST"])
def delete_file(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    user_servers_dir = ensure_user_servers_dir()
    data = request.get_json()
    file_path = os.path.join(user_servers_dir, folder, data['name'])
    
    if not file_path.startswith(user_servers_dir):
        return jsonify({"success": False}), 403
    
    os.remove(file_path)
    return jsonify({"success": True})

@app.route("/files/install/<folder>", methods=["POST"])
def install_req(folder):
    """Install dependencies for Python requirements.txt or Node package.json."""
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    project_dir, meta = get_project_meta(folder)
    if not project_dir:
        return jsonify({"success": False, "message": "مجلد المشروع غير موجود"}), 404
    runtimes = available_runtimes()
    runtime = meta.get("runtime", "python")
    log_path = os.path.join(project_dir, "server.log")
    if runtime == "node":
        package_path = os.path.join(project_dir, "package.json")
        npm = meta.get("npm_bin") or runtimes["npm"]["path"]
        node_bin = meta.get("node_bin") or runtimes["node"]["path"]
        if npm not in {x["path"] for x in runtimes["npm_versions"]}: npm = runtimes["npm"]["path"]
        if not os.path.isfile(package_path):
            return jsonify({"success": False, "message": "ما لقيتش package.json فالمشروع"}), 400
        if not npm:
            return jsonify({"success": False, "message": "npm ما منصبش فالسيرفر"}), 400
        command = [npm, "install"]
    else:
        req_path = os.path.join(project_dir, "requirements.txt")
        if not os.path.isfile(req_path):
            return jsonify({"success": False, "message": "ما لقيتش requirements.txt فالمشروع"}), 400
        py_bin = meta.get("python_bin", sys.executable)
        if py_bin not in {x["path"] for x in runtimes["python"]}:
            py_bin = sys.executable
        venv_dir = os.path.join(project_dir, ".venv")
        venv_python = os.path.join(venv_dir, "bin", "python")
        if not os.path.isfile(venv_python):
            create_venv = subprocess.run([py_bin, "-m", "venv", venv_dir], cwd=project_dir, capture_output=True, text=True, timeout=120)
            if create_venv.returncode != 0:
                return jsonify({"success": False, "message": "ماقدرتش ننشئ بيئة Python خاصة بالمشروع: " + (create_venv.stderr or create_venv.stdout)[-1200:]}), 500
        command = [venv_python, "-m", "pip", "install", "-r", "requirements.txt"]
    try:
        with open(log_path, "a", encoding="utf-8") as log_file:
            log_file.write("\n[SYSTEM] Installing dependencies: " + " ".join(command) + "\n")
        log_file = open(log_path, "a", encoding="utf-8")
        run_env = os.environ.copy()
        if runtime == "node" and node_bin:
            run_env["PATH"] = os.path.dirname(node_bin) + os.pathsep + run_env.get("PATH", "")
        proc = subprocess.Popen(command, cwd=project_dir, stdout=log_file, stderr=log_file, start_new_session=True, env=run_env)
        return jsonify({"success": True, "message": "بدا تثبيت المكتبات؛ تابع النتيجة فالكونسول", "pid": proc.pid})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/server/runtime/<folder>", methods=["GET", "POST"])
def server_runtime(folder):
    if 'username' not in session:
        return jsonify({"success": False, "message": "غير مصرح"}), 401
    project_dir, meta = get_project_meta(folder)
    if not project_dir:
        return jsonify({"success": False, "message": "مجلد المشروع غير موجود"}), 404
    available = available_runtimes()
    if request.method == "GET":
        return jsonify({"success": True, "runtime": meta.get("runtime", "python"), "python_bin": meta.get("python_bin", sys.executable), "run_mode": meta.get("run_mode", "file"), "startup_file": meta.get("startup_file", ""), "node_bin": meta.get("node_bin"), "npm_bin": meta.get("npm_bin"), "available": available})
    data = request.get_json(silent=True) or {}
    runtime = data.get("runtime", "python")
    mode = data.get("run_mode", "file")
    startup = (data.get("startup_file") or "").strip()
    if runtime not in ("python", "node"):
        return jsonify({"success": False, "message": "Runtime غير صالح"}), 400
    if mode not in ("file", "npm") or (runtime == "python" and mode == "npm"):
        return jsonify({"success": False, "message": "طريقة التشغيل غير صالحة"}), 400
    if mode == "file" and (not startup or os.path.basename(startup) != startup or not os.path.isfile(os.path.join(project_dir, startup))):
        return jsonify({"success": False, "message": "ملف التشغيل خاصو يكون ملف موجود داخل المشروع"}), 400
    if runtime == "node" and not available["node"]["path"]:
        return jsonify({"success": False, "message": "Node.js ما منصبش فالسيرفر"}), 400
    if runtime == "node" and mode == "npm" and (not available["npm"]["path"] or not os.path.isfile(os.path.join(project_dir, "package.json"))):
        return jsonify({"success": False, "message": "تأكد من تثبيت npm ووجود package.json"}), 400
    py_bin = data.get("python_bin", sys.executable)
    valid_py = {x["path"] for x in available["python"]}
    if py_bin not in valid_py:
        py_bin = available["python"][0]["path"] if available["python"] else sys.executable
    node_bin = data.get("node_bin") or available["node"]["path"]
    npm_bin = data.get("npm_bin") or available["npm"]["path"]
    valid_node = {x["path"] for x in available["node_versions"]}
    valid_npm = {x["path"] for x in available["npm_versions"]}
    if node_bin not in valid_node: node_bin = available["node"]["path"]
    if npm_bin not in valid_npm: npm_bin = available["npm"]["path"]
    meta.update({"runtime": runtime, "python_bin": py_bin, "node_bin": node_bin, "npm_bin": npm_bin, "run_mode": mode, "startup_file": startup})
    with open(os.path.join(project_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    return jsonify({"success": True, "message": "تحفظات إعدادات التشغيل"})

@app.route("/server/set-startup/<folder>", methods=["POST"])
def set_startup(folder):
    if 'username' not in session:
        return jsonify({"success": False}), 401
    
    meta_path = ensure_meta(folder)
    if not meta_path:
        return jsonify({"success": False}), 404
    
    with open(meta_path, "r", encoding="utf-8") as f:
        m = json.load(f)
    m["startup_file"] = request.get_json().get('file', '')
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(m, f)
    return jsonify({"success": True})

@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    """الحصول على قائمة جميع المستخدمين (للمسؤول فقط)"""
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    user_list = []
    for username, data in users.items():
        if username != ADMIN_USERNAME:  # عدم عرض المسؤول نفسه
            user_list.append({
                "username": username,
                "created_at": data.get("created_at"),
                "last_login": data.get("last_login"),
                "created_by": data.get("created_by", "system"),
                "expires_at": data.get("expires_at"),
                "days_remaining": account_expiry_status(data)[1],
                "expired": account_expiry_status(data)[0]
            })
    
    return jsonify({"success": True, "users": user_list})

@app.route("/api/admin/set-expiry", methods=["POST"])
def set_user_expiry():
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    try:
        days = int(data.get("days", 0))
    except (TypeError, ValueError):
        days = 0
    if not username or username == ADMIN_USERNAME:
        return jsonify({"success": False, "message": "لا يمكن تغيير مدة حساب المسؤول"})
    if days < 1 or days > 3650:
        return jsonify({"success": False, "message": "أدخل مدة بين 1 و3650 يوماً"})
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    if username not in users:
        return jsonify({"success": False, "message": "المستخدم غير موجود"}), 404
    expiry = datetime.now() + timedelta(days=days)
    users[username]["expires_at"] = expiry.isoformat()
    users[username]["expiry_days_set"] = days
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    return jsonify({"success": True, "message": f"تم تحديد مدة الحساب إلى {days} يوم", "expires_at": expiry.isoformat()})


@app.route("/api/admin/delete-user", methods=["POST"])
def delete_user():
    """حذف مستخدم (للمسؤول فقط)"""
    if 'username' not in session or not is_admin(session['username']):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    data = request.get_json()
    username_to_delete = data.get("username", "").strip()
    
    if not username_to_delete or username_to_delete == ADMIN_USERNAME:
        return jsonify({"success": False, "message": "لا يمكن حذف هذا المستخدم"})
    
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    
    if username_to_delete not in users:
        return jsonify({"success": False, "message": "المستخدم غير موجود"})
    
    # حذف المستخدم
    del users[username_to_delete]
    
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    
    # حذف مجلد المستخدم إذا كان موجوداً
    user_dir = os.path.join(USERS_DIR, username_to_delete)
    if os.path.exists(user_dir):
        import shutil
        shutil.rmtree(user_dir)
    
    return jsonify({"success": True, "message": "تم حذف المستخدم بنجاح"})

# Telegram bot management endpoints removed from the hosting panel.

@app.route("/proxy/<int:port>/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(port, path):
    """
    تمرير الطلبات إلى السيرفرات المحلية
    مثال: /proxy/8000/api/spam?user_id=12345678
    """
    try:
        if port < 1024 or port > 65535:
            return jsonify({"error": "Invalid port"}), 400
        
        # بناء الرابط الكامل مع الـ Query String
        query_string = request.query_string.decode('utf-8')
        url = f"http://localhost:{port}/{path}"
        if query_string:
            url += f"?{query_string}"
        
        # تمرير الرأس والبيانات
        headers = {key: value for key, value in request.headers if key != 'Host'}
        
        if request.method == "GET":
            resp = requests.get(url, headers=headers, timeout=30)
        elif request.method == "POST":
            resp = requests.post(url, data=request.get_data(), headers=headers, timeout=30)
        elif request.method == "PUT":
            resp = requests.put(url, data=request.get_data(), headers=headers, timeout=30)
        elif request.method == "DELETE":
            resp = requests.delete(url, headers=headers, timeout=30)
        elif request.method == "PATCH":
            resp = requests.patch(url, data=request.get_data(), headers=headers, timeout=30)
        
        # إرسال الرد
        response = make_response(resp.content)
        response.status_code = resp.status_code
        for key, value in resp.headers.items():
            if key.lower() not in ['content-encoding', 'content-length']:
                response.headers[key] = value
        return response
    
    except ValueError:
        return jsonify({"error": "Invalid port number"}), 400
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timeout"}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Connection refused"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 21910))
    app.run(host="0.0.0.0", port=port, debug=True)