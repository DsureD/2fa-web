"""
2FA 验证器 Web 应用
单文件后端：Flask + SQLite + PyOTP
"""

import os
import re
import time
import hmac
import sqlite3
import hashlib
import secrets
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse, parse_qs, unquote, urlencode

from flask import (
    Flask, request, jsonify, session,
    render_template
)
from dotenv import load_dotenv
import pyotp
import urllib.request
import json as _json

# ---------------------------------------------------------------------------
# 初始化
# ---------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

# Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)
# 生产环境（非 DEBUG）强制 Secure cookie
if os.getenv("DEBUG", "false").lower() != "true":
    app.config["SESSION_COOKIE_SECURE"] = True

ACCESS_PASSWORD = os.getenv("ACCESS_PASSWORD", "admin")
SENSITIVE_PASSWORD = os.getenv("SENSITIVE_PASSWORD", "")
HCAPTCHA_SITE_KEY = os.getenv("HCAPTCHA_SITE_KEY", "")
HCAPTCHA_SECRET_KEY = os.getenv("HCAPTCHA_SECRET_KEY", "")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "2fa.db")

# ---------------------------------------------------------------------------
# 登录频率限制（内存级，简单有效）
# ---------------------------------------------------------------------------
_login_attempts = {}  # ip -> {"count": int, "first_attempt": float}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300  # 5 分钟窗口

def _check_rate_limit(ip):
    """检查登录频率限制，返回 (allowed, retry_after_seconds)"""
    now = time.time()
    rec = _login_attempts.get(ip)
    if not rec:
        return True, 0
    # 窗口过期，重置
    if now - rec["first_attempt"] > LOGIN_WINDOW_SECONDS:
        del _login_attempts[ip]
        return True, 0
    if rec["count"] >= LOGIN_MAX_ATTEMPTS:
        retry_after = int(LOGIN_WINDOW_SECONDS - (now - rec["first_attempt"])) + 1
        return False, retry_after
    return True, 0

def _record_failed_attempt(ip):
    """记录一次失败的登录尝试"""
    now = time.time()
    rec = _login_attempts.get(ip)
    if not rec or now - rec["first_attempt"] > LOGIN_WINDOW_SECONDS:
        _login_attempts[ip] = {"count": 1, "first_attempt": now}
    else:
        rec["count"] += 1

def _clear_attempts(ip):
    """登录成功后清除记录"""
    _login_attempts.pop(ip, None)


def _verify_hcaptcha(token):
    """向 hCaptcha 服务端验证 token，返回 True/False"""
    if not HCAPTCHA_SECRET_KEY:
        return True  # 未配置则跳过
    if not token:
        return False
    try:
        payload = urlencode({
            "secret": HCAPTCHA_SECRET_KEY,
            "response": token,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.hcaptcha.com/siteverify",
            data=payload,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = _json.loads(resp.read())
        return result.get("success", False)
    except Exception:
        return False

# ---------------------------------------------------------------------------
# 数据库
# ---------------------------------------------------------------------------

_db_initialized = False

def get_db():
    """获取数据库连接"""
    global _db_initialized
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    if not _db_initialized:
        conn.execute("PRAGMA journal_mode=WAL")
        _db_initialized = True
    return conn


def init_db():
    """初始化数据库表"""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            issuer      TEXT NOT NULL DEFAULT '',
            username    TEXT NOT NULL DEFAULT '',
            secret      TEXT NOT NULL,
            digits      INTEGER NOT NULL DEFAULT 6,
            period      INTEGER NOT NULL DEFAULT 30,
            algorithm   TEXT NOT NULL DEFAULT 'SHA1',
            note        TEXT NOT NULL DEFAULT '',
            group_name  TEXT NOT NULL DEFAULT '',
            sort_order  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            sort_order  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    # 迁移：为已有表添加 group_name 列
    try:
        conn.execute("ALTER TABLE accounts ADD COLUMN group_name TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass  # 列已存在
    # 迁移：为 groups 表添加 sort_order 列
    try:
        conn.execute("ALTER TABLE groups ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass  # 列已存在
    # 迁移：将 accounts 中已有的 group_name 同步到 groups 表
    conn.execute("""
        INSERT OR IGNORE INTO groups (name)
        SELECT DISTINCT group_name FROM accounts WHERE group_name != ''
    """)
    conn.commit()
    conn.close()


init_db()

# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "未登录"}), 401
        return f(*args, **kwargs)
    return decorated


def verify_sensitive_password(data):
    """验证敏感操作密码，返回 (passed, error_response)"""
    if not SENSITIVE_PASSWORD:
        return True, None
    pwd = (data or {}).get("sensitive_password", "")
    if not pwd:
        return False, (jsonify({"error": "需要操作密码", "need_sensitive_password": True}), 403)
    if not hmac.compare_digest(pwd.encode("utf-8"), SENSITIVE_PASSWORD.encode("utf-8")):
        return False, (jsonify({"error": "操作密码错误", "need_sensitive_password": True}), 403)
    return True, None


# 输入参数白名单验证
VALID_DIGITS = {6, 8}
VALID_PERIODS = {30, 60}
VALID_ALGORITHMS = {"SHA1", "SHA256", "SHA512"}

def validate_totp_params(digits, period, algorithm):
    """验证 TOTP 参数合法性，返回清洗后的值或抛出 ValueError"""
    if digits not in VALID_DIGITS:
        raise ValueError(f"位数必须为 {VALID_DIGITS} 之一")
    if period not in VALID_PERIODS:
        raise ValueError(f"周期必须为 {VALID_PERIODS} 之一")
    if algorithm not in VALID_ALGORITHMS:
        raise ValueError(f"算法必须为 {VALID_ALGORITHMS} 之一")
    return digits, period, algorithm


# ---------------------------------------------------------------------------
# 安全响应头
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    """为所有响应添加安全头"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # CSP：允许 inline style/script（单体应用需要），限制外部只允许 CDN 和 hCaptcha
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://hcaptcha.com https://*.hcaptcha.com https://js.hcaptcha.com; "
        "style-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com; "
        "img-src 'self' data: https://hcaptcha.com https://*.hcaptcha.com; "
        "connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; "
        "frame-src https://hcaptcha.com https://*.hcaptcha.com; "
        "worker-src https://hcaptcha.com https://*.hcaptcha.com blob:; "
        "child-src https://hcaptcha.com https://*.hcaptcha.com; "
        "frame-ancestors 'none';"
    )
    return response


def parse_otpauth_uri(uri):
    """解析 otpauth:// URI"""
    uri = uri.strip()
    if not uri.startswith("otpauth://totp/"):
        return None
    try:
        parsed = urlparse(uri)
        label = unquote(parsed.path[1:])  # 去掉前导 /
        params = parse_qs(parsed.query)

        # 解析 issuer 和 username
        issuer = params.get("issuer", [""])[0]
        username = label
        if ":" in label:
            parts = label.split(":", 1)
            if not issuer:
                issuer = parts[0]
            username = parts[1]

        secret = params.get("secret", [""])[0].upper().replace(" ", "")
        digits = int(params.get("digits", ["6"])[0])
        period = int(params.get("period", ["30"])[0])
        algorithm = params.get("algorithm", ["SHA1"])[0].upper()

        return {
            "issuer": issuer,
            "username": username,
            "secret": secret,
            "digits": digits,
            "period": period,
            "algorithm": algorithm,
        }
    except Exception:
        return None


def clean_secret(secret):
    """清理密钥字符串"""
    return re.sub(r"[\s\-=]", "", secret).upper()


def generate_totp(secret, digits=6, period=30, algorithm="SHA1"):
    """生成 TOTP 验证码"""
    try:
        totp = pyotp.TOTP(secret, digits=digits, interval=period,
                          digest=getattr(hashlib, algorithm.lower(), hashlib.sha1))
        code = totp.now()
        remaining = period - (int(time.time()) % period)
        return {"code": code, "remaining": remaining, "period": period}
    except Exception as e:
        return {"code": "ERROR", "remaining": 0, "period": period, "error": str(e)}


# ---------------------------------------------------------------------------
# 页面路由
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# API 路由
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    """登录验证"""
    ip = request.remote_addr or "unknown"
    allowed, retry_after = _check_rate_limit(ip)
    if not allowed:
        return jsonify({"error": f"尝试次数过多，请 {retry_after} 秒后重试"}), 429

    data = request.get_json(silent=True) or {}

    # hCaptcha 验证（启用时）
    if HCAPTCHA_SECRET_KEY:
        captcha_token = data.get("captcha_token", "")
        if not _verify_hcaptcha(captcha_token):
            return jsonify({"error": "人机验证失败，请重试", "captcha_failed": True}), 403

    password = data.get("password", "")
    # 使用常数时间比较防止时序攻击
    if hmac.compare_digest(password.encode("utf-8"), ACCESS_PASSWORD.encode("utf-8")):
        _clear_attempts(ip)
        session["authenticated"] = True
        session.permanent = True
        return jsonify({"ok": True})
    _record_failed_attempt(ip)
    return jsonify({"error": "密码错误"}), 403


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """登出"""
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/status")
def api_status():
    """检查登录状态"""
    resp = {
        "authenticated": bool(session.get("authenticated")),
        "sensitive_password_enabled": bool(SENSITIVE_PASSWORD),
    }
    if HCAPTCHA_SITE_KEY:
        resp["hcaptcha_site_key"] = HCAPTCHA_SITE_KEY
    return jsonify(resp)


@app.route("/api/accounts", methods=["GET"])
@login_required
def api_list_accounts():
    """获取所有账户列表"""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM accounts ORDER BY sort_order ASC, id DESC"
        ).fetchall()
    finally:
        conn.close()

    accounts = []
    for row in rows:
        item = dict(row)
        totp = generate_totp(item["secret"], item["digits"],
                             item["period"], item["algorithm"])
        item.update(totp)
        # 不向前端暴露密钥
        del item["secret"]
        accounts.append(item)

    return jsonify(accounts)


@app.route("/api/accounts", methods=["POST"])
@login_required
def api_add_account():
    """添加新账户"""
    data = request.get_json(silent=True) or {}

    # 支持 otpauth:// URI 直接粘贴
    uri = data.get("uri", "").strip()
    if uri.startswith("otpauth://"):
        parsed = parse_otpauth_uri(uri)
        if not parsed:
            return jsonify({"error": "无效的 otpauth URI"}), 400
        data = {**parsed, **{k: v for k, v in data.items() if v and k != "uri"}}

    secret = clean_secret(data.get("secret", ""))
    if not secret:
        return jsonify({"error": "密钥不能为空"}), 400

    # 验证密钥有效性
    try:
        pyotp.TOTP(secret).now()
    except Exception:
        return jsonify({"error": "无效的密钥格式"}), 400

    issuer = data.get("issuer", "").strip()
    username = data.get("username", "").strip()
    note = data.get("note", "").strip()
    group_name = data.get("group_name", "").strip()

    try:
        digits = int(data.get("digits", 6))
        period = int(data.get("period", 30))
        algorithm = data.get("algorithm", "SHA1").upper()
        digits, period, algorithm = validate_totp_params(digits, period, algorithm)
    except (ValueError, TypeError) as e:
        return jsonify({"error": str(e)}), 400

    conn = get_db()
    try:
        cursor = conn.execute(
            """INSERT INTO accounts (issuer, username, secret, digits, period, algorithm, note, group_name)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (issuer, username, secret, digits, period, algorithm, note, group_name)
        )
        new_id = cursor.lastrowid
        conn.commit()
    finally:
        conn.close()

    return jsonify({"ok": True, "id": new_id}), 201


@app.route("/api/accounts/<int:account_id>", methods=["PUT"])
@login_required
def api_update_account(account_id):
    """更新账户信息"""
    data = request.get_json(silent=True) or {}
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        if not row:
            return jsonify({"error": "账户不存在"}), 404

        issuer = data.get("issuer", row["issuer"]).strip()
        username = data.get("username", row["username"]).strip()
        note = data.get("note", row["note"]).strip()
        group_name = data.get("group_name", row["group_name"]).strip()
        secret = data.get("secret", "").strip()
        if secret:
            secret = clean_secret(secret)
            try:
                pyotp.TOTP(secret).now()
            except Exception:
                return jsonify({"error": "无效的密钥格式"}), 400
        else:
            secret = row["secret"]

        try:
            digits = int(data.get("digits", row["digits"]))
            period = int(data.get("period", row["period"]))
            algorithm = data.get("algorithm", row["algorithm"]).upper()
            digits, period, algorithm = validate_totp_params(digits, period, algorithm)
        except (ValueError, TypeError) as e:
            return jsonify({"error": str(e)}), 400

        conn.execute(
            """UPDATE accounts SET issuer=?, username=?, secret=?, digits=?, period=?,
               algorithm=?, note=?, group_name=?, updated_at=datetime('now') WHERE id=?""",
            (issuer, username, secret, digits, period, algorithm, note, group_name, account_id)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.route("/api/accounts/<int:account_id>", methods=["DELETE"])
@login_required
def api_delete_account(account_id):
    """删除账户（需验证敏感操作密码）"""
    data = request.get_json(silent=True) or {}
    passed, err = verify_sensitive_password(data)
    if not passed:
        return err

    conn = get_db()
    try:
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.route("/api/totp/<int:account_id>")
@login_required
def api_get_totp(account_id):
    """获取单个账户的当前 TOTP"""
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "账户不存在"}), 404
    result = generate_totp(row["secret"], row["digits"], row["period"], row["algorithm"])
    result["id"] = account_id
    return jsonify(result)


@app.route("/api/accounts/<int:account_id>/secret", methods=["POST"])
@login_required
def api_get_account_secret(account_id):
    """获取单个账户的密钥（按需加载，编辑时使用，需验证敏感操作密码）"""
    data = request.get_json(silent=True) or {}
    passed, err = verify_sensitive_password(data)
    if not passed:
        return err

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT secret, digits, period, algorithm FROM accounts WHERE id = ?",
            (account_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "账户不存在"}), 404
    return jsonify({
        "secret": row["secret"],
        "digits": row["digits"],
        "period": row["period"],
        "algorithm": row["algorithm"],
    })


@app.route("/api/groups")
@login_required
def api_list_groups():
    """获取所有分组名称（合并 groups 表和 accounts 表中的分组，按 sort_order 排序）"""
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT name FROM (
                   SELECT name, sort_order FROM groups
                   UNION
                   SELECT DISTINCT group_name AS name, 999999 AS sort_order
                   FROM accounts WHERE group_name != ''
                   AND group_name NOT IN (SELECT name FROM groups)
               ) ORDER BY sort_order ASC, name ASC"""
        ).fetchall()
    finally:
        conn.close()
    return jsonify([row["name"] for row in rows])


@app.route("/api/groups", methods=["POST"])
@login_required
def api_create_group():
    """创建分组（持久化存储到 groups 表）"""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "分组名称不能为空"}), 400

    conn = get_db()
    try:
        max_order = conn.execute("SELECT COALESCE(MAX(sort_order), -1) FROM groups").fetchone()[0]
        conn.execute("INSERT INTO groups (name, sort_order) VALUES (?, ?)", (name, max_order + 1))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "分组已存在"}), 400
    finally:
        conn.close()
    return jsonify({"ok": True, "name": name})


@app.route("/api/groups/rename", methods=["POST"])
@login_required
def api_rename_group():
    """重命名分组（更新 groups 表和 accounts 表）"""
    data = request.get_json(silent=True) or {}
    old_name = data.get("old_name", "").strip()
    new_name = data.get("new_name", "").strip()
    if not old_name or not new_name:
        return jsonify({"error": "分组名称不能为空"}), 400
    if old_name == new_name:
        return jsonify({"ok": True})

    conn = get_db()
    try:
        # 更新 groups 表
        try:
            conn.execute("UPDATE groups SET name=? WHERE name=?", (new_name, old_name))
        except sqlite3.IntegrityError:
            return jsonify({"error": "目标分组名已存在"}), 400
        # 更新 accounts 表
        conn.execute(
            "UPDATE accounts SET group_name=?, updated_at=datetime('now') WHERE group_name=?",
            (new_name, old_name)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/reorder", methods=["POST"])
@login_required
def api_reorder_groups():
    """更新分组排序（接收按新顺序排列的分组名称数组）"""
    data = request.get_json(silent=True) or {}
    names = data.get("names", [])
    if not isinstance(names, list):
        return jsonify({"error": "参数错误"}), 400

    conn = get_db()
    try:
        for i, name in enumerate(names):
            conn.execute("UPDATE groups SET sort_order=? WHERE name=?", (i, name))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups", methods=["DELETE"])
@login_required
def api_delete_group():
    """删除分组（从 groups 表移除，accounts 中该分组的账户变为未分组）"""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "分组名称不能为空"}), 400

    conn = get_db()
    try:
        conn.execute("DELETE FROM groups WHERE name=?", (name,))
        conn.execute(
            "UPDATE accounts SET group_name='', updated_at=datetime('now') WHERE group_name=?",
            (name,)
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    print(f"2FA 验证器启动于 http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
