#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WorkBuddy 媒体工作台（Kusylit's Studio）— 本地生图 / 改图 / 生视频工作台。

能力：
  - 生图 / 改图（多图）/ 生视频（首尾帧、参考图、负向提示、音频开关）
  - 分辨率 / 比例 / 时长预设 + 图片自定义宽高
  - 任务面板：筛选、搜索、取消、复用、删除、重试保存、打开文件夹、统计
  - 控制台：服务端持久化日志、级别筛选、搜索、暂停滚动、下载
  - 自动保存到可配置目录；视频完成时跟随当前设置
  - 同步网关历史任务；健康状态与积分余额
只依赖标准库。启动后浏览器打开 http://127.0.0.1:8790 。
"""
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.join(os.path.dirname(HERE), "workbuddy2api-hub")
GATEWAY = "http://127.0.0.1:8788"
LISTEN = ("127.0.0.1", 8790)
MAX_BODY = 24 * 1024 * 1024
MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_VIDEO_BYTES = 512 * 1024 * 1024

CONFIG_PATH = os.path.join(HERE, "studio-config.json")
JOBS_PATH = os.path.join(HERE, "studio-jobs.json")
TAGS_PATH = os.path.join(HERE, "studio-tags.json")
FAVORITES_PATH = os.path.join(HERE, "studio-favorites.json")
LOG_PATH = os.path.join(HERE, "studio-console.log")
AUDIT_PATH = os.path.join(HERE, "studio-audit.log")
DEFAULT_SAVE_DIR = os.path.join(HERE, "media-out")
GATEWAY_TASKS_PATH = os.path.join(PROJ, "media", "tasks.json")

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_safe_image_url(newurl):
            raise urllib.error.URLError("redirect to a disallowed image host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


IMAGE_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), SafeRedirectHandler())
SERVER_STARTED = time.strftime("%Y-%m-%d %H:%M:%S")
STUDIO_TOKEN = secrets.token_hex(16)
CSP_NONCE = secrets.token_hex(16)
FILE_SECRET = secrets.token_hex(32)
FILE_TTL = 24 * 3600
STATE_LOCK = threading.RLock()
LOG_LOCK = threading.Lock()
TAG_LOCK = threading.RLock()
FAV_LOCK = threading.RLock()
AUDIT_LOCK = threading.Lock()
POST_LOCK = threading.Lock()
CONFIG_LOCK = threading.RLock()
SAVE_LOCKS_LOCK = threading.Lock()
WATCHERS_LOCK = threading.Lock()
SYNC_LOCK = threading.Lock()
ACCESS_CACHE_LOCK = threading.Lock()
POST_WINDOW = {}
CONFIG_STATE = {"error": False}
SAVE_LOCKS = {}
WATCHERS = set()
ACCESS_CACHE = {}
POST_LIMIT = 40
JOBS = []
LOG_ENTRIES = []
JOB_KEEP = 100
MAX_JOBS = 500
LOG_KEEP = 500
DEFAULT_TAG_CATEGORIES = ["风格", "角色", "构图", "动作", "表情", "背景", "光线", "其他"]
ACTIVE_STATUSES = {"queued", "waiting", "submitting", "running", "in_progress",
                   "processing", "saving", "unknown"}
TERMINAL_STATUSES = {"completed", "failed", "rejected", "cancelled", "lost"}
MEDIA_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".webm", ".mov"}
INLINE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".webm", ".mov"}


def normalize_status(value):
    status = str(value or "unknown").strip().lower()
    return status if status in ACTIVE_STATUSES or status in TERMINAL_STATUSES else "unknown"


def load_key():
    path = os.path.join(PROJ, "accounts", "settings.json")
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return ""
    for item in data.get("api_keys") or []:
        if item.get("enabled") and not item.get("deleted_at") and item.get("key"):
            return item["key"]
    return ""


API_KEY = load_key()


def is_safe_image_url(url):
    """只允许指向公网主机的 http(s) 图片地址，阻止 file/data/内网/元数据 SSRF。"""
    try:
        if not url or len(str(url)) > 4096:
            return False
        if any(ord(ch) < 33 for ch in str(url)):
            return False
        parts = urllib.parse.urlsplit(str(url))
        if parts.scheme not in ("http", "https"):
            return False
        if parts.username or parts.password:
            return False
        parts.port  # 触发非法端口异常
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            return False
        if host in ("localhost", "localhost.localdomain") or host.endswith(
                (".localhost", ".local", ".internal", ".lan", ".home")):
            return False
        try:
            if not ipaddress.ip_address(host).is_global:
                return False
        except ValueError:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            if not infos:
                return False
            for info in infos:
                addr = str(info[4][0]).split("%", 1)[0]
                if not ipaddress.ip_address(addr).is_global:
                    return False
        return True
    except Exception:
        return False


def _file_signature(name, exp):
    msg = ("%s\n%d" % (name, exp)).encode("utf-8")
    return hmac.new(FILE_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def file_url(name):
    name = os.path.basename(str(name or ""))
    if not name or os.path.splitext(name)[1].lower() not in MEDIA_EXTS:
        return ""
    exp = int(time.time()) + FILE_TTL
    return "/files/%s?exp=%d&sig=%s" % (
        urllib.parse.quote(name), exp, _file_signature(name, exp))


def verify_file_signature(parsed):
    qs = urllib.parse.parse_qs(parsed.query)
    name = os.path.basename(urllib.parse.unquote(parsed.path[len("/files/"):]))
    if not name or os.path.splitext(name)[1].lower() not in MEDIA_EXTS:
        return None
    try:
        exp = int((qs.get("exp") or [""])[0])
        sig = (qs.get("sig") or [""])[0]
    except (TypeError, ValueError):
        return None
    if exp < int(time.time()) or not sig:
        return None
    if not hmac.compare_digest(sig, _file_signature(name, exp)):
        return None
    return name


def public_job(job):
    if not job:
        return job
    out = dict(job)
    out["events"] = list(job.get("events") or [])
    if out.get("filename"):
        out["file_url"] = file_url(out["filename"])
    return out


def _read_limited(resp, limit):
    if not limit:
        return resp.read()
    length = resp.headers.get("Content-Length")
    if length:
        try:
            if int(length) > limit:
                raise ValueError("响应超过大小限制")
        except ValueError:
            pass
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError("响应超过大小限制")
    return data


def gateway(path, body=None, method=None, timeout=300, extra_headers=None, max_bytes=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": "Bearer " + API_KEY}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(GATEWAY + path, data=data, headers=headers, method=method)
    try:
        resp = OPENER.open(req, timeout=timeout)
        return resp.status, resp.headers.get("Content-Type", ""), _read_limited(resp, max_bytes)
    except urllib.error.HTTPError as exc:
        try:
            body = _read_limited(exc, max_bytes)
        except Exception:
            body = b""
        return exc.code, exc.headers.get("Content-Type", ""), body
    except Exception as exc:
        msg = "网关不可用: %s" % exc
        return 502, "application/json; charset=utf-8", json.dumps(
            {"error": {"message": msg}}, ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------- 控制台日志

def slog(level, msg):
    entry = {"t": time.time(), "level": level, "msg": str(msg)}
    with LOG_LOCK:
        LOG_ENTRIES.append(entry)
        if len(LOG_ENTRIES) > LOG_KEEP:
            del LOG_ENTRIES[:-LOG_KEEP]
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if os.path.getsize(LOG_PATH) > 1200000:
                keep = LOG_ENTRIES[-LOG_KEEP:]
                with open(LOG_PATH, "w", encoding="utf-8") as fh:
                    for item in keep:
                        fh.write(json.dumps(item, ensure_ascii=False) + "\n")
        except Exception:
            pass


def load_logs():
    entries = []
    try:
        with open(LOG_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if isinstance(item, dict) and item.get("msg"):
                    entries.append(item)
    except Exception:
        pass
    return entries[-LOG_KEEP:]


def clear_logs():
    with LOG_LOCK:
        LOG_ENTRIES.clear()
        try:
            open(LOG_PATH, "w").close()
        except Exception:
            pass


# ---------------------------------------------------------------- 配置

def load_config():
    data = {}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("config root is not an object")
        CONFIG_STATE["error"] = False
    except FileNotFoundError:
        CONFIG_STATE["error"] = False
    except Exception:
        CONFIG_STATE["error"] = os.path.exists(CONFIG_PATH)
        data = {}
    raw = data.get("save_dir") or DEFAULT_SAVE_DIR
    path = os.path.abspath(os.path.expanduser(str(raw)))
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        path = DEFAULT_SAVE_DIR
        os.makedirs(path, exist_ok=True)
    return {"save_dir": path,
            "access_password_hash": str(data.get("access_password_hash") or "")}


def load_config_raw():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(cfg):
    with CONFIG_LOCK:
        fd, tmp = tempfile.mkstemp(prefix="studio-config-", suffix=".tmp", dir=HERE)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(cfg, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, CONFIG_PATH)
            CONFIG_STATE["error"] = False
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass


def migrate_config():
    try:
        data = json.load(open(CONFIG_PATH, encoding="utf-8"))
    except Exception:
        return
    if not isinstance(data, dict):
        return
    if "panel_password" in data:
        data.pop("panel_password", None)
        data.setdefault("access_password_hash", "")
        save_config(data)


def set_access_password(raw):
    text = str(raw or "").strip()
    if not text:
        return ""
    salt = secrets.token_hex(16)
    iterations = 200000
    digest = hashlib.pbkdf2_hmac(
        "sha256", text.encode("utf-8"), bytes.fromhex(salt), iterations).hex()
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt, digest)


def verify_access_password(raw, stored):
    stored = str(stored or "")
    text = str(raw or "")
    if not stored:
        return True
    cache_key = hashlib.sha256(text.encode("utf-8")).hexdigest()
    now = time.time()
    with ACCESS_CACHE_LOCK:
        cached = ACCESS_CACHE.get(cache_key)
        if cached and cached[0] == stored and cached[1] > now:
            return True
    try:
        if stored.startswith("pbkdf2_sha256$"):
            _algo, iterations, salt, digest = stored.split("$", 3)
            calc = hashlib.pbkdf2_hmac(
                "sha256", text.encode("utf-8"), bytes.fromhex(salt),
                int(iterations)).hex()
            ok = hmac.compare_digest(calc, digest)
        elif len(stored) == 64:
            ok = hmac.compare_digest(
                hashlib.sha256(text.encode("utf-8")).hexdigest(), stored)
        else:
            ok = False
    except Exception:
        ok = False
    if ok:
        with ACCESS_CACHE_LOCK:
            if len(ACCESS_CACHE) > 32:
                ACCESS_CACHE.clear()
            ACCESS_CACHE[cache_key] = (stored, now + 300)
    return ok


def audit(action, detail=""):
    entry = {"t": time.time(), "action": str(action)[:80],
             "detail": str(detail)[:1500]}
    try:
        with AUDIT_LOCK:
            with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if os.path.getsize(AUDIT_PATH) > 2000000:
                with open(AUDIT_PATH, encoding="utf-8") as fh:
                    lines = fh.readlines()[-2000:]
                with open(AUDIT_PATH, "w", encoding="utf-8") as fh:
                    fh.writelines(lines)
    except Exception:
        pass


def set_save_dir(raw):
    text = str(raw or "").strip()
    if not text:
        raise ValueError("保存目录不能为空")
    path = os.path.abspath(os.path.expanduser(text))
    os.makedirs(path, exist_ok=True)
    fd, probe = tempfile.mkstemp(prefix=".wb-write-test-", dir=path)
    try:
        os.write(fd, b"ok")
    finally:
        os.close(fd)
        try:
            os.remove(probe)
        except OSError:
            pass
    if not os.path.isdir(path):
        raise ValueError("不是有效目录: " + path)
    return path


def refresh_upstream_balance(password=None):
    """用看板密码登录网关，触发一次上游积分刷新，再取实时余额。"""
    pwd = str(password or "admin")
    data = json.dumps({"password": pwd}).encode("utf-8")
    req = urllib.request.Request(GATEWAY + "/panel/login", data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        resp = OPENER.open(req, timeout=20)
        login = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError("看板登录失败: " + _error_message(exc.read()))
    token = login.get("token")
    if not token:
        raise RuntimeError("看板登录未返回 token")
    status, _, body = gateway("/accounts/credits", timeout=180,
                              extra_headers={"X-Panel-Token": token})
    if status != 200:
        raise RuntimeError("刷新积分失败: " + _error_message(body))
    status, _, body = gateway("/v1/balance-summary", timeout=20)
    if status != 200:
        raise RuntimeError("读取余额失败: " + _error_message(body))
    bal = json.loads(body.decode("utf-8"))
    slog("ok", "刷新上游余额: %s" % bal.get("balance"))
    return bal


# ---------------------------------------------------------------- 任务记录

def persist_jobs():
    with STATE_LOCK:
        active = [j for j in JOBS if j.get("status") in ACTIVE_STATUSES]
        rest = [j for j in JOBS if j.get("status") not in ACTIVE_STATUSES]
        limit = max(JOB_KEEP, len(active))
        data = [dict(job) for job in (active + rest)[:limit]]
        fd, tmp = tempfile.mkstemp(prefix="studio-jobs-", suffix=".tmp", dir=HERE)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, JOBS_PATH)
        except Exception as exc:
            sys.stderr.write("[jobs] persist failed: %s\n" % exc)
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass


def _status_log_level(status):
    if status == "completed":
        return "ok"
    if status in ("failed", "rejected", "cancelled", "lost"):
        return "err"
    return "info"


def _trim_jobs():
    """内存中保留所有活动任务，其余最多保留到 MAX_JOBS。"""
    global JOBS
    if len(JOBS) <= MAX_JOBS:
        return
    active = [j for j in JOBS if j.get("status") in ACTIVE_STATUSES]
    rest = [j for j in JOBS if j.get("status") not in ACTIVE_STATUSES]
    JOBS = active + rest[:max(0, MAX_JOBS - len(active))]


def start_watcher(job_id):
    with WATCHERS_LOCK:
        if job_id in WATCHERS:
            return False
        WATCHERS.add(job_id)
    threading.Thread(target=watch_video, args=(job_id,), daemon=True).start()
    return True


def load_jobs():
    global JOBS
    try:
        data = json.load(open(JOBS_PATH, encoding="utf-8"))
        if isinstance(data, list):
            JOBS = [j for j in data if isinstance(j, dict) and j.get("id")]
    except Exception:
        try:
            if os.path.exists(JOBS_PATH):
                os.replace(JOBS_PATH, JOBS_PATH + ".corrupt-" + time.strftime("%Y%m%d-%H%M%S"))
        except Exception:
            pass
        JOBS = []
    now = time.time()
    changed = False
    for job in JOBS:
        if not isinstance(job.get("events"), list):
            job["events"] = []
            changed = True
        try:
            job["created_at"] = float(job.get("created_at") or now)
        except (TypeError, ValueError):
            job["created_at"] = now
            changed = True
        try:
            job["updated_at"] = float(job.get("updated_at") or job["created_at"])
        except (TypeError, ValueError):
            job["updated_at"] = job["created_at"]
            changed = True
        if job.get("type") == "image" and job.get("status") in ACTIVE_STATUSES:
            job["status"] = "failed"
            job["error"] = "服务重启，任务中断"
            job["updated_at"] = now
            changed = True
        elif job.get("type") == "video" and job.get("status") in ACTIVE_STATUSES:
            if not job.get("task_id"):
                job["status"] = "failed"
                job["error"] = "缺少 task_id"
                job["updated_at"] = now
                changed = True
    if changed:
        persist_jobs()
    for job in list(JOBS):
        if job.get("type") == "video" and job.get("status") in ACTIVE_STATUSES:
            start_watcher(job["id"])


def find_job(job_id):
    with STATE_LOCK:
        for job in JOBS:
            if job.get("id") == job_id:
                return job
    return None


def find_job_by_task(task_id):
    with STATE_LOCK:
        for job in JOBS:
            if job.get("task_id") == task_id:
                return job
    return None


def new_job(**fields):
    prompt = fields.get("prompt") or ""
    if not isinstance(prompt, str):
        prompt = str(prompt)
    task_id = fields.get("task_id")
    task_id = str(task_id) if task_id else None
    try:
        created_at = float(fields.get("created_at") or time.time())
    except (TypeError, ValueError):
        created_at = time.time()
    job = {
        "id": fields.get("id") or ("job_" + uuid.uuid4().hex[:12]),
        "type": fields.get("type") or "image",
        "model": fields.get("model") or "",
        "prompt": prompt[:2000],
        "status": fields.get("status") or "running",
        "created_at": created_at,
        "updated_at": time.time(),
        "completed_at": fields.get("completed_at"),
        "credit": None,
        "error": None,
        "path": None,
        "filename": None,
        "source_url": None,
        "save_dir": fields.get("save_dir") or load_config()["save_dir"],
        "save_dir_used": None,
        "save_error": None,
        "task_id": task_id,
        "request": fields.get("request") or {},
        "events": [],
    }
    job["events"].append({"t": job["created_at"], "status": job["status"], "note": "created"})
    with STATE_LOCK:
        JOBS.insert(0, job)
        _trim_jobs()
    persist_jobs()
    return job


def update_job(job_id, **fields):
    status_old = None
    status_new = None
    changed = False
    with STATE_LOCK:
        job = next((j for j in JOBS if j.get("id") == job_id), None)
        if not job:
            return None
        if not isinstance(job.get("events"), list):
            job["events"] = []
        for key, value in fields.items():
            if key == "status":
                old = job.get("status")
                if old in TERMINAL_STATUSES and value != old:
                    continue
                if old != value:
                    status_old = old
                    status_new = value
                    job["status"] = value
                    job["events"].append({"t": time.time(), "status": value,
                                          "note": fields.get("note") or ""})
                    if value in TERMINAL_STATUSES:
                        job["completed_at"] = job.get("completed_at") or time.time()
                    changed = True
            elif key == "note":
                continue
            elif key == "created_at":
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    continue
                if job.get(key) != value:
                    job[key] = value
                    changed = True
            elif job.get(key) != value:
                job[key] = value
                changed = True
        if changed:
            job["updated_at"] = time.time()
    if changed:
        persist_jobs()
    if status_new and status_new != status_old:
        slog(_status_log_level(status_new),
             "任务 %s（%s）: %s → %s" % (job_id, job.get("model") or "-",
                                        status_old or "-", status_new))
    return job


def _is_under(path, root):
    try:
        p = os.path.abspath(path)
        r = os.path.abspath(root)
        return os.path.normcase(os.path.commonpath([p, r])) == os.path.normcase(r)
    except Exception:
        return False


def clear_finished_jobs(delete_files=False):
    global JOBS
    removed = []
    with STATE_LOCK:
        keep = []
        for job in JOBS:
            if job.get("status") in ACTIVE_STATUSES:
                keep.append(job)
            else:
                removed.append(job)
        JOBS = keep
    if delete_files:
        save_dir = load_config()["save_dir"]
        for job in removed:
            path = job.get("path")
            if path and _is_under(path, save_dir) and os.path.isfile(path):
                try:
                    os.remove(path)
                except Exception:
                    pass
    persist_jobs()
    audit("jobs_clear", "removed=%d delete_files=%s" % (len(removed), bool(delete_files)))


def delete_job(job_id):
    global JOBS
    with STATE_LOCK:
        job = next((j for j in JOBS if j.get("id") == job_id), None)
        if not job:
            raise ValueError("任务不存在")
        if job.get("status") in ACTIVE_STATUSES:
            raise ValueError("任务仍在进行中，不能删除")
        JOBS.remove(job)
    persist_jobs()
    audit("job_delete", job_id)


# ---------------------------------------------------------------- 提示词标签

def load_tags():
    data = {}
    try:
        data = json.load(open(TAGS_PATH, encoding="utf-8"))
    except Exception:
        pass
    tags = [t for t in (data.get("tags") or []) if isinstance(t, dict) and t.get("id") and t.get("text")]
    cats = []
    for c in data.get("categories") or []:
        text = str(c).strip()
        if text and text not in cats:
            cats.append(text)
    for t in tags:
        text = str(t.get("category") or "").strip()
        if text and text not in cats:
            cats.append(text)
    return {"tags": tags, "categories": cats}


def migrate_tags():
    """一次性清掉旧版硬编码的默认分类，只保留有标签在用的分类。"""
    if not os.path.exists(TAGS_PATH):
        return
    with TAG_LOCK:
        try:
            data = json.load(open(TAGS_PATH, encoding="utf-8"))
        except Exception:
            return
        if not isinstance(data, dict):
            return
        if data.get("preset_cleanup"):
            return
        used = []
        for t in data.get("tags") or []:
            c = str(t.get("category") or "").strip()
            if c and c not in used:
                used.append(c)
        cats = []
        for c in data.get("categories") or []:
            c = str(c).strip()
            if c in used and c not in cats:
                cats.append(c)
        for c in used:
            if c not in cats:
                cats.append(c)
        data["categories"] = cats
        data["preset_cleanup"] = True
        save_tags(data)


def save_tags(data):
    tmp = TAGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, TAGS_PATH)


def upsert_tag(payload):
    text = str(payload.get("text") or "").strip()
    if not text:
        raise ValueError("标签内容不能为空")
    if len(text) > 500:
        raise ValueError("标签最多 500 字")
    category = str(payload.get("category") or "未分类").strip() or "未分类"
    if len(category) > 30:
        raise ValueError("分类名最多 30 字")
    tag_id = str(payload.get("id") or "").strip()
    with TAG_LOCK:
        data = load_tags()
        now = time.time()
        if tag_id:
            tag = next((t for t in data["tags"] if t.get("id") == tag_id), None)
            if not tag:
                raise ValueError("标签不存在")
            tag.update({"text": text, "category": category, "updated_at": now})
        else:
            tag = {"id": "tag_" + uuid.uuid4().hex[:8], "text": text,
                   "category": category, "created_at": now, "updated_at": now,
                   "uses": 0}
            data["tags"].insert(0, tag)
        if category not in data["categories"]:
            data["categories"].append(category)
        save_tags(data)
    return tag


def delete_tag(tag_id):
    tag_id = str(tag_id or "").strip()
    if not tag_id:
        raise ValueError("缺少标签 ID")
    with TAG_LOCK:
        data = load_tags()
        before = len(data["tags"])
        data["tags"] = [t for t in data["tags"] if t.get("id") != tag_id]
        if len(data["tags"]) == before:
            raise ValueError("标签不存在")
        save_tags(data)
    slog("warn", "删除标签: %s" % tag_id)


def tag_category_action(payload):
    action = str(payload.get("action") or "").strip()
    name = str(payload.get("name") or "").strip()
    new_name = str(payload.get("new_name") or "").strip()
    if action not in ("add", "rename", "delete"):
        raise ValueError("action 必须是 add / rename / delete")
    with TAG_LOCK:
        data = load_tags()
        cats = list(data["categories"])
        if action == "add":
            if not name:
                raise ValueError("分类名不能为空")
            if len(name) > 30:
                raise ValueError("分类名最多 30 字")
            if name not in cats:
                cats.append(name)
        elif action == "rename":
            if not name or not new_name:
                raise ValueError("缺少原分类或新分类")
            if name not in cats:
                raise ValueError("分类不存在")
            if len(new_name) > 30:
                raise ValueError("分类名最多 30 字")
            for tag in data["tags"]:
                if tag.get("category") == name:
                    tag["category"] = new_name
            if new_name in cats and new_name != name:
                cats.remove(name)
            else:
                cats[cats.index(name)] = new_name
            if new_name not in cats:
                cats.append(new_name)
        else:
            if not name:
                raise ValueError("缺少分类名")
            if name not in cats:
                raise ValueError("分类不存在")
            moved = False
            for tag in data["tags"]:
                if tag.get("category") == name:
                    tag["category"] = "未分类"
                    moved = True
            cats.remove(name)
            if moved and "未分类" not in cats:
                cats.append("未分类")
        data["categories"] = cats
        save_tags(data)
    return data


def use_tag(tag_id):
    with TAG_LOCK:
        data = load_tags()
        tag = next((t for t in data["tags"] if t.get("id") == tag_id), None)
        if not tag:
            raise ValueError("标签不存在")
        tag["uses"] = int(tag.get("uses") or 0) + 1
        tag["last_used"] = time.time()
        save_tags(data)
    return tag


def import_tags(payload):
    items = payload.get("tags")
    if not isinstance(items, list):
        raise ValueError("tags 必须是数组")
    items = items[:500]
    added = skipped = 0
    with TAG_LOCK:
        data = load_tags()
        seen = {(str(t.get("text") or "").strip(), str(t.get("category") or "未分类"))
                for t in data["tags"]}
        now = time.time()
        for item in items:
            if not isinstance(item, dict):
                skipped += 1
                continue
            text = str(item.get("text") or "").strip()
            category = str(item.get("category") or "未分类").strip() or "未分类"
            if not text or len(text) > 500 or len(category) > 30:
                skipped += 1
                continue
            key = (text, category)
            if key in seen:
                skipped += 1
                continue
            data["tags"].insert(0, {
                "id": "tag_" + uuid.uuid4().hex[:8], "text": text,
                "category": category, "created_at": now, "updated_at": now,
                "uses": 0})
            seen.add(key)
            if category not in data["categories"]:
                data["categories"].append(category)
            added += 1
        if added:
            save_tags(data)
    return {"added": added, "skipped": skipped}


# ---------------------------------------------------------------- 文件保存

def _safe_name(text, limit=32):
    raw = re.sub(r"\s+", "-", str(text or "")).strip()
    slug = re.sub(r"[^0-9A-Za-z_-]", "", raw)[:limit].strip("-_")
    if len(slug) < 2:
        slug = hashlib.sha1(str(text or "item").encode("utf-8")).hexdigest()[:8]
    return slug


ARTIFACT_CHARACTERS = [
    "樱羽艾玛", "艾玛", "拉姆", "雷姆", "初音未来", "初音", "奶龙", "橘猫", "柴犬",
    "猫娘", "龙娘", "狐狸", "兔子", "猫", "狗", "龙",
]
ARTIFACT_KEYWORDS = [
    "粗糙", "涂鸦", "线稿", "平涂", "Live2D", "半睁眼", "淡笑", "坏笑", "尖牙", "眨眼",
    "回眸", "侧脸", "近景", "头像", "半身", "全身", "符纸", "贝雷帽", "樱花", "红月",
    "花瓣", "霓虹", "赛博朋克", "墨镜", "耳机", "围巾", "银灰长发", "银灰", "长发",
    "短发", "银发", "粉发", "白发", "异色瞳", "紫指甲", "女仆装", "制服", "长袍",
    "腰封", "项链", "choker", "猫耳", "水手服", "和服", "旗袍", "机甲", "逆光",
    "轮廓光", "枯枝", "薄雾", "月夜", "写实", "插画", "可爱", "高领", "红眼", "蓝眼",
    "3D", "卡通", "动画", "中景", "纯白", "黄色", "圆胖", "大肚皮",
]


def _prompt_keywords(prompt):
    """从 prompt 里提取角色名和少量画面关键词，用于文件名。"""
    text = str(prompt or "")
    chosen = []

    chars = sorted((c for c in ARTIFACT_CHARACTERS if c in text), key=len, reverse=True)
    for c in chars:
        if any(c in existing for existing in chosen):
            continue
        chosen.append(c)
        if len(chosen) >= 2:
            break

    hits = []
    for kw in ARTIFACT_KEYWORDS:
        idx = text.find(kw)
        if idx < 0:
            continue
        if any(kw in existing for existing in chosen):
            continue
        hits.append((idx, kw))
    hits.sort(key=lambda item: item[0])
    for _, kw in hits:
        if any(kw in existing for existing in chosen):
            continue
        chosen.append(kw)
        if len(chosen) >= 4:
            break

    if len(chosen) >= 2:
        return "_".join(chosen)

    cleaned = re.sub(r"^.*?角色为《[^》]*》中的", "", text)
    cleaned = re.sub(
        r"^(?:以首帧图为?[^，,。]*?[，,。]|严格保持[^：:]*[：:]|一张[^，,。]*?涂鸦[，,。]?)",
        "", cleaned)
    han = re.sub(r"[^\u4e00-\u9fff]+", "", cleaned)
    if len(han) >= 2:
        return han[:20]
    words = re.findall(r"[A-Za-z0-9]+", text)
    stop = {"a", "an", "the", "of", "with", "wearing", "in", "on", "at", "for",
            "and", "or", "to", "is", "are", "style", "photo"}
    picked = [w[:14] for w in words if w.lower() not in stop][:4]
    if len(picked) >= 2:
        return "_".join(picked)
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]


def _artifact_base(prompt, kind, unique, stamp=None):
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    kw = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff_-]", "", _prompt_keywords(prompt))
    kw = re.sub(r"_{2,}", "_", kw).strip("_-")[:48] or "未命名"
    unique = re.sub(r"[^0-9A-Za-z]", "", str(unique or ""))[:8] or uuid.uuid4().hex[:6]
    return "%s_%s_%s_%s" % (stamp, kind, kw, unique)


def _unique_path(directory, base, ext):
    path = os.path.join(directory, base + ext)
    if not os.path.exists(path):
        return path
    for i in range(2, 1000):
        candidate = os.path.join(directory, "%s-%d%s" % (base, i, ext))
        if not os.path.exists(candidate):
            return candidate
    return os.path.join(directory, "%s-%s%s" % (base, uuid.uuid4().hex[:6], ext))


def _image_ext(raw, content_type):
    head = raw[:16] or b""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if head.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return ".webp"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype in ("image/png", "image/x-png"):
        return ".png"
    if ctype in ("image/jpeg", "image/jpg", "image/pjpeg"):
        return ".jpg"
    if ctype == "image/webp":
        return ".webp"
    if ctype == "image/gif":
        return ".gif"
    return None


def save_image_bytes(raw, content_type, prompt, save_dir, kind="image"):
    os.makedirs(save_dir, exist_ok=True)
    ext = _image_ext(raw, content_type)
    if not ext:
        raise RuntimeError("返回内容不是支持的图片格式")
    base = _artifact_base(prompt, kind, uuid.uuid4().hex[:6])
    path = _unique_path(save_dir, base, ext)
    tmp = path + ".part"
    try:
        with open(tmp, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
    return path, os.path.basename(path)


def save_image_result(item, prompt, kind="image"):
    save_dir = load_config()["save_dir"]
    if item.get("b64_json"):
        import base64
        try:
            raw = base64.b64decode(item["b64_json"], validate=False)
        except Exception as exc:
            raise RuntimeError("图片 base64 解码失败: %s" % exc)
        if len(raw) > MAX_IMAGE_BYTES:
            raise RuntimeError("图片超过大小限制")
        return save_image_bytes(raw, "image/png", prompt, save_dir, kind)
    url = item.get("url")
    if not url:
        raise RuntimeError("返回里没有图片数据")
    if not is_safe_image_url(url):
        raise RuntimeError("图片来源地址不允许（只允许公网 http/https）")
    try:
        resp = IMAGE_OPENER.open(url, timeout=180)
        length = resp.headers.get("Content-Length")
        if length and int(length) > MAX_IMAGE_BYTES:
            raise RuntimeError("图片超过大小限制")
        raw = resp.read(MAX_IMAGE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RuntimeError("图片下载失败: HTTP %s" % exc.code)
    except Exception as exc:
        raise RuntimeError("图片下载失败: %s" % exc)
    if len(raw) > MAX_IMAGE_BYTES:
        raise RuntimeError("图片超过大小限制")
    return save_image_bytes(raw, resp.headers.get("Content-Type", ""),
                            prompt, save_dir, kind)


def video_name(prompt, task_id):
    return _artifact_base(prompt, "video", task_id[-8:]) + ".mp4"


def _save_lock(key):
    with SAVE_LOCKS_LOCK:
        return SAVE_LOCKS.setdefault(str(key), threading.Lock())


def save_video(task_id, prompt):
    save_dir = load_config()["save_dir"]
    os.makedirs(save_dir, exist_ok=True)
    base = video_name(prompt, task_id)
    with _save_lock(task_id):
        path = _unique_path(save_dir, base[:-4], ".mp4")
        name = os.path.basename(path)
        status, _, body = gateway(
            "/v1/videos/%s/content" % urllib.parse.quote(str(task_id), safe=""),
            timeout=900, max_bytes=MAX_VIDEO_BYTES)
        if status != 200 or not body:
            raise RuntimeError("下载视频失败: HTTP %s" % status)
        if len(body) > MAX_VIDEO_BYTES:
            raise RuntimeError("视频超过大小限制")
        tmp = path + ".part"
        try:
            with open(tmp, "wb") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
        return path, name, save_dir


def watch_video(job_id):
    failures = 0
    deadline = time.time() + 3600
    try:
        while True:
            time.sleep(5)
            job = find_job(job_id)
            if not job or job.get("status") not in ACTIVE_STATUSES:
                return
            if time.time() > deadline:
                update_job(job_id, status="failed", error="轮询超时（超过 1 小时）")
                return
            task_id = job.get("task_id")
            if not task_id:
                update_job(job_id, status="failed", error="缺少 task_id")
                return
            status, _, body = gateway(
                "/v1/videos/%s" % urllib.parse.quote(str(task_id), safe=""),
                timeout=30)
            if status != 200:
                failures += 1
                if failures >= 12:
                    update_job(job_id, status="failed",
                               error="连续 %d 次查询任务失败（HTTP %s）" % (failures, status))
                    return
                continue
            failures = 0
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            st = normalize_status(data.get("status"))
            err = data.get("error")
            err_msg = err.get("message") if isinstance(err, dict) else err
            if st == "completed":
                current = find_job(job_id)
                if not current or current.get("status") not in ACTIVE_STATUSES:
                    return
                update_job(job_id, status="saving", credit=data.get("credit"),
                           error=None, note="下载视频")
                current = find_job(job_id)
                if not current or current.get("status") != "saving":
                    return
                try:
                    path, name, used = save_video(task_id, job.get("prompt") or "")
                    update_job(job_id, status="completed", path=path, filename=name,
                               save_dir_used=used, save_error=None)
                    slog("ok", "视频已保存: %s" % name)
                except Exception as exc:
                    update_job(job_id, status="completed", save_error=str(exc))
                    slog("err", "视频保存失败 %s: %s" % (task_id, exc))
                return
            update_job(job_id, status=st, credit=data.get("credit"), error=err_msg)
            if st in ("failed", "rejected", "cancelled", "lost"):
                return
    finally:
        with WATCHERS_LOCK:
            WATCHERS.discard(job_id)


def extract_image(data):
    return (data.get("data") or [{}])[0] if isinstance(data.get("data"), list) else {}


def _error_message(raw):
    try:
        obj = json.loads(raw.decode("utf-8"))
        err = obj.get("error")
        if isinstance(err, dict):
            return err.get("message") or json.dumps(err, ensure_ascii=False)
        if err:
            return str(err)
    except Exception:
        pass
    return (raw or b"").decode("utf-8", "replace")[:300] or "请求失败"


# ---------------------------------------------------------------- 历史同步 / 健康

def resolve_saved_file(name):
    """按文件名找已保存文件：先当前目录，再任务记录里的历史目录。"""
    name = os.path.basename(name or "")
    if not name:
        return None
    candidate = os.path.join(load_config()["save_dir"], name)
    if os.path.isfile(candidate):
        return candidate
    with STATE_LOCK:
        for job in JOBS:
            if job.get("filename") == name and job.get("path") and os.path.isfile(job["path"]):
                return job["path"]
    return None


def sync_gateway_history():
    if not SYNC_LOCK.acquire(False):
        raise RuntimeError("同步正在进行，请稍后再试")
    try:
        try:
            data = json.load(open(GATEWAY_TASKS_PATH, encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError("读取网关任务失败: %s" % exc)
        tasks = data.get("tasks") or []
        our_key = None
        try:
            settings = json.load(open(os.path.join(PROJ, "accounts", "settings.json"), encoding="utf-8"))
            for item in settings.get("api_keys") or []:
                if item.get("enabled") and not item.get("deleted_at"):
                    our_key = item.get("id")
                    break
        except Exception:
            pass
        with STATE_LOCK:
            existing = {j.get("task_id") for j in JOBS if j.get("task_id")}
        save_dir = load_config()["save_dir"]
        added = 0
        for task in tasks:
            if not isinstance(task, dict):
                continue
            task_id = str(task.get("id") or "")
            if not task_id or task_id in existing:
                continue
            if our_key and task.get("key") and task.get("key") != our_key:
                continue
            status = normalize_status(task.get("status") or "completed")
            prompt = task.get("prompt") or task.get("prompt_head") or ""
            if not isinstance(prompt, str):
                prompt = str(prompt)
            filename = None
            path = None
            save_error = None
            if status == "completed" and task.get("videos"):
                src = task["videos"][0]
                if isinstance(src, str) and os.path.isfile(src):
                    base = video_name(prompt, task_id)
                    path = _unique_path(save_dir, base[:-4], ".mp4")
                    try:
                        shutil.copyfile(src, path)
                        filename = os.path.basename(path)
                    except Exception as exc:
                        save_error = str(exc)
                        path = None
                else:
                    save_error = "网关源文件不存在"
            job = new_job(type="video", model=task.get("model"), prompt=prompt,
                          status=status, task_id=task_id, save_dir=save_dir,
                          request={"kind": "video", "prompt": prompt,
                                   "seconds": task.get("seconds"),
                                   "resolution": task.get("resolution"),
                                   "aspect_ratio": task.get("aspect_ratio")})
            update_job(job["id"],
                       created_at=task.get("created_at") or job["created_at"],
                       completed_at=task.get("completed_at"),
                       credit=task.get("credit"), path=path, filename=filename,
                       save_error=save_error, save_dir_used=save_dir if path else None)
            if status in ACTIVE_STATUSES:
                start_watcher(job["id"])
            existing.add(task_id)
            added += 1
        slog("ok", "同步网关历史：新增 %d 条任务" % added)
        audit("history_sync", "added=%d" % added)
        return added
    finally:
        SYNC_LOCK.release()


def collect_health():
    out = {"gateway": False, "accounts": 0, "accounts_ready": 0, "realm": None,
           "media_enabled": None, "media_realm": None, "credits": None, "models": 0}
    try:
        raw = OPENER.open(GATEWAY + "/health", timeout=5).read().decode("utf-8")
        data = json.loads(raw)
        out["gateway"] = True
        out["accounts"] = data.get("accounts") or 0
        out["accounts_ready"] = data.get("accounts_ready") or 0
        out["realm"] = data.get("realm")
        media = data.get("media") or {}
        out["media_enabled"] = media.get("enabled")
        out["media_realm"] = media.get("realm")
    except Exception as exc:
        out["error"] = str(exc)
    out["models"] = 0
    # 优先取网关内部的实时余额快照；账号文件里的 credits 只在生成时刷新，会滞后。
    try:
        status, _, body = gateway("/v1/balance-summary", timeout=10)
        if status == 200:
            bal = json.loads(body.decode("utf-8"))
            out["credits"] = bal.get("balance")
            out["credits_updated_at"] = bal.get("updated_at")
            out["credits_source"] = "gateway"
    except Exception:
        pass
    try:
        if out.get("credits") is None:
            best = None
            acc_dir = os.path.join(PROJ, "accounts")
            for name in os.listdir(acc_dir):
                if not name.endswith(".json") or name == "settings.json":
                    continue
                try:
                    acc = json.load(open(os.path.join(acc_dir, name), encoding="utf-8"))
                except Exception:
                    continue
                credits = acc.get("credits") or {}
                remain = credits.get("remain")
                if isinstance(remain, (int, float)) and (best is None or remain > best):
                    best = remain
            out["credits"] = best
            out["credits_source"] = "cache"
        try:
            status, _, body = gateway("/v1/models?realm=cn", timeout=10)
            if status == 200:
                out["models"] = len(json.loads(body.decode("utf-8")).get("data") or [])
        except Exception:
            pass
    except Exception:
        pass
    return out


def load_favorites():
    try:
        data = json.load(open(FAVORITES_PATH, encoding="utf-8"))
    except Exception:
        return []
    values = data.get("favorites") if isinstance(data, dict) else data
    if not isinstance(values, list):
        return []
    out = []
    for value in values:
        name = str(value or "")
        if name and name not in out:
            out.append(name)
    return out


def save_favorites(names):
    tmp = FAVORITES_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"favorites": names}, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, FAVORITES_PATH)


def set_favorite(name, favorite):
    name = os.path.basename(str(name or ""))
    if not name:
        raise ValueError("缺少文件名")
    root = load_config()["save_dir"]
    if favorite and not os.path.isfile(os.path.join(root, name)):
        raise ValueError("文件不存在")
    with FAV_LOCK:
        names = [n for n in load_favorites() if n != name]
        if favorite:
            names.append(name)
        save_favorites(names)
    return bool(favorite)


def delete_gallery_item(name):
    name = os.path.basename(str(name or ""))
    if not name:
        raise ValueError("缺少文件名")
    root = load_config()["save_dir"]
    ext = os.path.splitext(name)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".webm", ".mov"}:
        raise ValueError("不是可删除的媒体文件")
    fp = os.path.join(root, name)
    if not os.path.isfile(fp):
        raise ValueError("文件不存在")
    try:
        os.remove(fp)
    except OSError as exc:
        raise RuntimeError("删除失败（文件可能正在播放）: %s" % exc)
    with FAV_LOCK:
        save_favorites([n for n in load_favorites() if n != name])
    with STATE_LOCK:
        jobs = list(JOBS)
    for job in jobs:
        same_path = job.get("path") and (
            os.path.normcase(os.path.abspath(job["path"])) == os.path.normcase(os.path.abspath(fp)))
        same_name_without_path = job.get("filename") == name and not job.get("path")
        if same_path or same_name_without_path:
            update_job(job["id"], filename=None, path=None, save_error="文件已手动删除")
    audit("gallery_delete", name)
    return {"ok": True, "name": name}


def list_gallery(limit=300, offset=0):
    cfg = load_config()
    root = cfg["save_dir"]
    favorites = set(load_favorites())
    image_exts = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
    video_exts = {".mp4", ".webm", ".mov"}
    items = []
    try:
        names = os.listdir(root)
    except Exception:
        names = []
    for name in names:
        fp = os.path.join(root, name)
        if not os.path.isfile(fp):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext not in image_exts and ext not in video_exts:
            continue
        try:
            st = os.stat(fp)
        except Exception:
            continue
        items.append({
            "name": name,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "type": "video" if ext in video_exts else "image",
            "favorite": name in favorites,
            "url": file_url(name),
        })
    items.sort(key=lambda x: x["mtime"], reverse=True)
    total_size = sum(item["size"] for item in items)
    return {"items": items[offset:offset + limit], "total": len(items),
            "total_size": total_size,
            "favorites_count": sum(1 for item in items if item["favorite"]),
            "save_dir": root}


def read_audit(limit=100):
    entries = []
    try:
        with open(AUDIT_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if isinstance(item, dict):
                    entries.append(item)
    except Exception:
        pass
    return entries[-limit:]


def rename_artifacts():
    """按任务记录 / 网关历史的 prompt 给旧作品重命名。"""
    cfg = load_config()
    root = cfg["save_dir"]
    tasks = []
    try:
        tasks = json.load(open(GATEWAY_TASKS_PATH, encoding="utf-8")).get("tasks") or []
    except Exception:
        tasks = []
    by_suffix = {}
    for task in tasks:
        tid = str(task.get("id") or "")
        if tid:
            by_suffix[tid[-8:]] = (tid, str(task.get("prompt_head") or ""))
    with STATE_LOCK:
        jobs = list(JOBS)
    job_by_path = {}
    for job in jobs:
        path = job.get("path")
        if path:
            job_by_path[os.path.normcase(os.path.abspath(path))] = job
    renamed, errors = [], []
    try:
        names = os.listdir(root)
    except Exception:
        names = []
    for name in names:
        lower = name.lower()
        if not lower.endswith((".mp4", ".png", ".jpg", ".jpeg", ".webp", ".gif")):
            continue
        fp = os.path.join(root, name)
        if not os.path.isfile(fp):
            continue
        prompt = None
        task_id = None
        unique = None
        stamp = None
        parsed = re.match(
            r"^(\d{8}-\d{6})_(image|edit|video)_(.*)_([0-9a-f]{6,8})(\.[^.]+)$",
            name, re.I)
        job = job_by_path.get(os.path.normcase(os.path.abspath(fp)))
        if parsed:
            stamp, kind, _old_kw, unique, _ext = parsed.groups()
            kind = kind.lower()
            if job:
                prompt = str(job.get("prompt") or "")
                task_id = job.get("task_id")
            elif kind == "video":
                for suffix, (tid, head) in by_suffix.items():
                    if suffix == unique:
                        task_id, prompt = tid, head
                        break
            if prompt is None:
                continue
        else:
            kind = "video" if lower.endswith(".mp4") else "image"
            if job:
                prompt = str(job.get("prompt") or "")
                task_id = job.get("task_id")
                kind = "video" if job.get("type") == "video" else (
                    "edit" if (job.get("request") or {}).get("kind") == "edit" else "image")
                unique = str(task_id)[-8:] if task_id else str(job.get("id") or "")[-8:]
                try:
                    stamp = time.strftime("%Y%m%d-%H%M%S",
                                          time.localtime(float(job.get("created_at") or time.time())))
                except Exception:
                    pass
            elif kind == "video":
                for suffix, (tid, head) in by_suffix.items():
                    if suffix and suffix in name:
                        task_id, prompt, unique = tid, head, tid[-8:]
                        break
                if prompt is not None:
                    try:
                        stamp = time.strftime("%Y%m%d-%H%M%S",
                                              time.localtime(os.path.getmtime(fp)))
                    except Exception:
                        pass
            if prompt is None:
                continue
        base = _artifact_base(prompt, kind, unique or "x", stamp)
        if base == os.path.splitext(name)[0]:
            continue
        target = _unique_path(root, base, os.path.splitext(name)[1])
        if os.path.normcase(os.path.abspath(target)) == os.path.normcase(os.path.abspath(fp)):
            continue
        new_name = os.path.basename(target)
        try:
            os.replace(fp, target)
        except Exception as exc:
            errors.append("%s: %s" % (name, exc))
            continue
        for other in jobs:
            other_path = other.get("path")
            same_path = other_path and (
                os.path.normcase(os.path.abspath(other_path)) == os.path.normcase(os.path.abspath(fp)))
            if other.get("filename") == name and (same_path or not other_path):
                update_job(other["id"], path=target, filename=new_name)
        with FAV_LOCK:
            favorites = load_favorites()
            if name in favorites:
                favorites = [n for n in favorites if n != name]
                if new_name not in favorites:
                    favorites.append(new_name)
                save_favorites(favorites)
        renamed.append({"old": name, "new": new_name})
    audit("rename_artifacts", "renamed=%d errors=%d" % (len(renamed), len(errors)))
    return {"renamed": len(renamed), "errors": errors[:10], "items": renamed[:30]}


# ---------------------------------------------------------------- 页面

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WorkBuddy 媒体工作台 · Kusylit's Studio</title>
<meta name="description" content="WorkBuddy 媒体工作台（Kusylit's Studio）— 本地优先的 AI 生图、改图与视频创作工作台。">
<meta name="author" content="Kusylit">
<meta name="theme-color" content="#0f1115">
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2064%2064'%3E%3Crect%20width='64'%20height='64'%20rx='15'%20fill='%237c9cff'/%3E%3Cpath%20d='M22%2015v34M22%2033l17-18M22%2033l17%2016'%20fill='none'%20stroke='%230b1020'%20stroke-width='6'%20stroke-linecap='round'%20stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
:root{--bg:#0f1115;--side:#12141a;--panel:#171a21;--panel2:#1e222b;--line:#2a3040;--fg:#e8eaf0;--dim:#8b93a7;--accent:#7c9cff;--accent2:#a9bcff;--ok:#3ddc97;--warn:#ffb454;--bad:#ff6b6b}
body.light{--bg:#f4f6fb;--side:#ffffff;--panel:#ffffff;--panel2:#f1f4f9;--line:#d8dfe9;--fg:#1c2333;--dim:#5e6a80;--accent:#4f6df5;--accent2:#2f4bd0;--ok:#148a5c;--warn:#a86b00;--bad:#c23a3a}
body.light .console{background:#0b0d12;color:#dbe4f5}
body.light .nav-item:hover,body.light .job-main:hover,body.light .task-row:hover{background:#eef2f9;color:#1c2333}
body.light .task-row.on{background:#eaf0ff}
body.light .task-row-grid:hover{background:#eef2f9}
body.light .task-item.open>.task-row-grid{background:#eaf0ff}
body.light .task-detail{background:#fff}
body.light .side-foot{border-color:var(--line)}
body.light .toast{background:#fff;color:#1c2333}
body.light .gallery-item.video{color:#5e6a80}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
button{font:inherit;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
code{background:var(--panel2);padding:1px 5px;border-radius:4px;font-size:12px}
.app{display:flex;min-height:100vh;align-items:stretch}
.sidebar{width:252px;flex:0 0 252px;background:var(--side);border-right:1px solid var(--line);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;padding:18px 12px 14px}
.brand{display:flex;align-items:center;gap:10px;padding:2px 8px 16px;border-bottom:1px solid var(--line);margin-bottom:12px}
.logo{width:38px;height:38px;border-radius:11px;background:var(--accent);color:#0b1020;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:20px;letter-spacing:-.04em;box-shadow:0 4px 12px rgba(0,0,0,.18)}
.brand-text{display:flex;flex-direction:column;line-height:1.15;min-width:0}
.brand-text b{font-size:14.5px;font-weight:700;letter-spacing:.003em;white-space:nowrap}
.brand-text span{font-size:9.5px;color:var(--dim);letter-spacing:.13em;text-transform:uppercase;white-space:nowrap}
.nav{flex:1;overflow-y:auto;padding-right:2px}
.nav-group{font-size:10.5px;color:#5f6779;letter-spacing:.12em;padding:14px 10px 6px;text-transform:uppercase}
.nav-item{width:100%;display:flex;align-items:center;gap:10px;background:transparent;border:0;color:var(--dim);padding:9px 10px;border-radius:9px;text-align:left;margin-bottom:2px;transition:background .15s,color .15s}
.nav-item svg{flex:0 0 16px;opacity:.85}
.nav-item span{flex:1;font-size:13.5px}
.nav-item .count{font-style:normal;font-size:11px;color:#6d768a;background:var(--panel2);border-radius:999px;padding:1px 7px;min-width:20px;text-align:center}
.nav-item:hover{background:#1a1e27;color:#cfd6e6}
.nav-item.on{background:rgba(124,156,255,.14);color:var(--accent2);box-shadow:inset 2px 0 0 var(--accent)}
.nav-item.on .count{color:#0b1020;background:var(--accent)}
.side-foot{border-top:1px solid var(--line);padding:10px 10px 0;font-size:11px;color:#6d768a;line-height:1.8}
.side-foot .row2{display:flex;justify-content:space-between;gap:8px}
.content{flex:1;min-width:0;padding:20px 26px 40px}
.content-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.content-head h2{margin:0 0 3px;font-size:21px;font-weight:650;letter-spacing:.01em}
.view-sub{font-size:12px;color:var(--dim)}
.head-right{display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.chip{background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:4px 10px;font-size:11.5px;color:var(--dim);white-space:nowrap}
.chip b{color:var(--fg);font-weight:600}
.icon-btn{background:var(--panel);border:1px solid var(--line);color:var(--dim);border-radius:8px;width:32px;height:30px;display:flex;align-items:center;justify-content:center;font-size:14px}
.icon-btn:hover{color:var(--fg);border-color:var(--accent)}
.stale{border:1px solid var(--warn);color:var(--warn);background:rgba(255,180,84,.08);border-radius:10px;padding:8px 12px;margin-bottom:14px;font-size:12px}
.toast-box{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px;z-index:90;max-width:360px}
.toast{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:9px;padding:9px 12px;font-size:12.5px;box-shadow:0 6px 24px rgba(0,0,0,.35);color:var(--fg);animation:toastIn .18s ease}
.toast.ok{border-left-color:var(--ok)}
.toast.warn{border-left-color:var(--warn)}
.toast.err{border-left-color:var(--bad)}
@keyframes toastIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.access-gate{position:fixed;inset:0;background:var(--bg);z-index:100;display:flex;align-items:center;justify-content:center}
.access-gate.hidden{display:none}
.gate-brand{display:flex;align-items:center;gap:10px;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid var(--line)}
.gate-brand .logo{width:36px;height:36px;font-size:18px;flex:0 0 36px}
.view{display:none}
.view.on{display:block}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
.card + .card{margin-top:14px}
.form-card{max-width:1080px}
.form-grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(270px,.85fr);gap:18px;align-items:start}
.field{min-width:0}
label{display:block;font-size:12px;color:var(--dim);margin-bottom:6px}
input,select,textarea{width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:10px 12px;color:var(--fg);font:inherit;outline:none}
textarea{resize:vertical;min-height:120px}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
button.primary{background:var(--accent);color:#0b1020;border:0;border-radius:9px;padding:11px 22px;font-weight:650}
button.ghost{background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:8px 13px;font-weight:500}
button.mini{padding:5px 10px;font-size:12px}
.hint{font-size:12px;color:var(--dim)}
.err{color:var(--bad);white-space:pre-wrap;font-size:13px;margin-top:10px}
.meta{font-size:12px;color:var(--dim);margin-top:8px;word-break:break-all}
.out{margin-top:16px}
.out img{max-width:100%;border-radius:12px;border:1px solid var(--line);display:block;cursor:zoom-in}
.progress{margin-top:14px;display:none}
.progress.on{display:block}
.bar-track{height:9px;background:var(--panel2);border:1px solid var(--line);border-radius:999px;overflow:hidden}
.bar-fill{height:100%;width:0;background:var(--accent);border-radius:999px;transition:width .35s}
.bar-fill.indet{width:35%;animation:indet 1.2s ease-in-out infinite}
.bar-fill.ok{background:var(--ok)}
.bar-fill.bad{background:var(--bad)}
@keyframes indet{0%{margin-left:-35%}100%{margin-left:100%}}
.progress-text{font-size:12px;color:var(--dim);margin-top:6px}
.save-hint{font-size:11.5px;color:#6d768a;margin-top:8px;word-break:break-all}
.slot-group{margin-bottom:8px}
.slot-title{font-size:11px;color:var(--dim);margin-bottom:5px}
.slot-chip{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line);border-radius:999px;padding:3px 9px;margin:0 6px 6px 0;font-size:11px;color:var(--dim);cursor:pointer;background:var(--panel2)}
.slot-chip input{width:12px;height:12px;margin:0;accent-color:var(--accent)}
.slot-chip:has(input:checked){border-color:var(--accent);color:var(--accent2);background:rgba(124,156,255,.08)}
.drawer{position:fixed;top:0;right:0;width:400px;max-width:95vw;height:100vh;background:var(--side);border-left:1px solid var(--line);z-index:70;display:none;flex-direction:column;padding:16px;overflow:hidden;box-shadow:-12px 0 40px rgba(0,0,0,.35)}
.drawer.on{display:flex}
.drawer-overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:60}
.tag-cats{display:flex;gap:5px;flex-wrap:wrap;margin:8px 0}
.tag-cats button{padding:3px 9px;font-size:11px;border-radius:999px;background:var(--panel2);color:var(--dim);border:1px solid var(--line)}
.tag-cats button.on{background:var(--accent);color:#0b1020;border-color:var(--accent)}
.tag-form{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px;margin-bottom:10px}
.tag-form textarea{min-height:58px}
.tag-form .btns{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.tag-list{flex:1;overflow-y:auto;min-height:0}
.tag-item{border:1px solid var(--line);border-radius:9px;padding:8px 10px;margin-bottom:6px;background:var(--panel2)}
.tag-item .tag-text{font-size:12px;line-height:1.5;word-break:break-all}
.tag-item .tag-meta{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:6px}
.tag-item .tag-cat{font-size:10.5px;color:var(--accent2);border:1px solid var(--line);border-radius:999px;padding:1px 7px}
.tag-item .tag-acts{display:flex;gap:5px}
.tag-item .tag-acts button{padding:2px 7px;font-size:10.5px;border-radius:6px;background:var(--panel);border:1px solid var(--line);color:var(--fg)}
.tag-empty{font-size:12px;color:var(--dim);padding:8px 0}
.preset-row{display:flex;gap:10px}
.preset-row .field{flex:1}
details.adv{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:14px 0;background:var(--panel2)}
details.adv summary{cursor:pointer;font-size:12px;color:var(--dim)}
details.adv[open] summary{margin-bottom:12px}
.toolbar-row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.toolbar-row .stats{font-size:12px;color:var(--dim)}
.btns{display:flex;gap:6px;flex-wrap:wrap}
.filters{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:10px}
.filters button{padding:4px 11px;font-size:12px;border-radius:7px;background:var(--panel2);color:var(--dim);border:1px solid var(--line);font-weight:500}
.filters button.on{color:#0b1020;background:var(--accent);border-color:var(--accent)}
.gallery-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0 12px}
.gallery-tools input[type=search]{flex:1 1 220px;max-width:360px;padding:7px 10px;font-size:12px}
.gallery-tools select{width:auto;padding:7px 9px;font-size:12px}
.gallery-range{display:flex;align-items:center;gap:6px;color:var(--dim);font-size:12px}
.gallery-range.hidden{display:none}
.gallery-range input[type=date]{width:auto;padding:6px 8px;font-size:12px}
.gallery-range .range-sep{font-size:11px;color:var(--dim)}
.gallery-shown{margin-left:auto;font-size:11.5px;color:var(--dim);font-variant-numeric:tabular-nums}
@media(max-width:700px){.gallery-shown{margin-left:0;width:100%}}
.jobs-list{display:flex;flex-direction:column;gap:8px;margin-top:12px}
.job-row{background:var(--panel2);border:1px solid var(--line);border-radius:10px;overflow:hidden;transition:border-color .15s}
.job-row.open{border-color:#3d4d72}
.job-main{display:flex;align-items:center;gap:8px;padding:10px 12px;cursor:pointer;flex-wrap:wrap}
.job-main:hover{background:#222836}
.chevron{color:var(--dim);width:14px;flex:0 0 14px;font-size:11px;text-align:center}
.job-prompt-inline{flex:1 1 200px;min-width:0;color:var(--dim);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.job-pct{font-size:11px;color:var(--dim);font-variant-numeric:tabular-nums}
.job-mini{padding:0 12px 9px}
.job-mini .bar-track{height:4px}
.job-detail{display:none;padding:0 12px 12px;border-top:1px solid var(--line)}
.job-row.open .job-detail{display:block}
.job-detail .kv{margin-top:10px;grid-template-columns:112px 1fr;font-size:12px}
.job-prompt-full{font-size:12px;color:var(--dim);white-space:pre-wrap;margin:10px 0;max-height:140px;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:9px 11px}
.job-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.job-actions button{padding:4px 9px;font-size:11px;border-radius:7px;background:var(--panel);color:var(--fg);border:1px solid var(--line);font-weight:500}
.job-actions button:hover{border-color:var(--accent)}
.job{border:1px solid var(--line);border-radius:12px;padding:13px 14px;background:var(--panel2);display:flex;flex-direction:column;min-width:0}
.job-head{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.job-title{font-weight:600;font-size:13px;word-break:break-all}
.job-prompt{color:var(--dim);font-size:12px;margin:7px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.job .bar-track{height:7px;margin:2px 0 6px}
.job-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:auto;padding-top:8px}
.job-actions button{padding:4px 9px;font-size:11px;border-radius:7px;background:var(--panel);color:var(--fg);border:1px solid var(--line);font-weight:500}
.job-actions button:hover{border-color:var(--accent)}
.task-filterbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.task-filterbar .filters{margin-bottom:0}
.task-filterbar input,.task-filterbar select{padding:7px 9px;font-size:12px}
.task-table{border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:6px}
.task-table-head,.task-row-grid{display:grid;grid-template-columns:66px minmax(240px,1fr) 210px 86px 86px 190px;gap:10px;align-items:center;padding:9px 12px}
.task-table-head{background:var(--panel2);font-size:11px;color:var(--dim);border-bottom:1px solid var(--line);letter-spacing:.04em}
.task-item{border-bottom:1px solid var(--line)}
.task-item:last-child{border-bottom:0}
.task-row-grid{cursor:pointer}
.task-row-grid:hover{background:#222836}
.task-item.open>.task-row-grid{background:rgba(124,156,255,.10)}
.col-type{display:flex;align-items:center}
.col-task .job-title{font-size:13px;font-weight:600}
.col-task .prompt{font-size:11.5px;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:3px}
.col-status .bar-track{height:5px;width:150px;margin-top:4px}
.col-status .pct{font-size:10.5px;color:var(--dim)}
.col-elapsed,.col-credit{font-size:12px;color:var(--dim);font-variant-numeric:tabular-nums}
.col-actions{display:flex;gap:4px;flex-wrap:wrap;justify-content:flex-end}
.col-actions button,.task-detail .job-actions button{padding:3px 8px;font-size:10.5px;border-radius:6px;background:var(--panel);border:1px solid var(--line);color:var(--fg)}
.col-actions button:hover,.task-detail .job-actions button:hover{border-color:var(--accent)}
.task-detail{padding:12px 14px 14px;border-top:1px solid var(--line);background:var(--panel)}
.task-detail .job-prompt-full{margin-top:0;max-height:150px}
.task-detail .kv{grid-template-columns:120px 1fr;margin-top:10px}
.task-detail .job-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.task-pager{display:flex;gap:8px;align-items:center;justify-content:center;padding-top:10px;border-top:1px solid var(--line);margin-top:10px}
.task-empty{padding:34px 16px;text-align:center;color:var(--dim);font-size:12.5px}
.task-preview img,.task-preview video{max-width:100%;border-radius:10px;border:1px solid var(--line);display:block;margin-top:10px;background:#000}
.queue-panel{margin-top:10px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);padding:10px}
.queue-list{max-height:230px;overflow:auto;display:flex;flex-direction:column;gap:3px;margin-top:8px}
.queue-item{display:flex;gap:8px;align-items:center;font-size:11.5px;border-bottom:1px dashed var(--line);padding:4px 0}
.queue-item:last-child{border-bottom:0}
.queue-item .idx{color:#6d768a;width:20px;flex:0 0 20px}
.queue-item .qtext{flex:1;min-width:0;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.queue-item button{padding:2px 7px;font-size:10.5px;border-radius:6px;background:var(--panel);border:1px solid var(--line);color:var(--fg)}
.file-preview{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.file-preview img{width:54px;height:54px;object-fit:cover;border-radius:6px;border:1px solid var(--line)}
.file-preview .hint{font-size:11px}
.gallery-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-top:12px}
.gallery-item{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--panel2);cursor:zoom-in;text-decoration:none;color:var(--fg);display:block;position:relative}
.gallery-actions{position:absolute;top:6px;right:6px;display:flex;gap:4px;opacity:0;transition:opacity .15s;z-index:2}
.gallery-item:hover .gallery-actions{opacity:1}
.gallery-act{background:rgba(0,0,0,.66);border:1px solid rgba(255,255,255,.22);color:#fff;border-radius:7px;padding:3px 7px;font-size:11px;cursor:pointer;line-height:1.2}
.gallery-act.fav.on{color:#ffd166;border-color:rgba(255,209,102,.6)}
.gallery-act.del:hover{color:#ff6b6b;border-color:#ff6b6b}
@media(hover:none){.gallery-actions{opacity:1}}
.gallery-item img{width:100%;height:170px;object-fit:cover;display:block}
.gallery-item.video{position:relative;display:block;height:170px;background:#000;color:#fff;cursor:pointer}
.gallery-item.video video{width:100%;height:170px;object-fit:cover;display:block;opacity:.88;pointer-events:none;background:#000}
.gallery-item.video .gplay{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);font-size:34px;color:#fff;text-shadow:0 2px 12px rgba(0,0,0,.8)}
.gallery-item.video .gname{position:absolute;left:0;right:0;bottom:0;background:linear-gradient(transparent,rgba(0,0,0,.78));color:#fff;padding:14px 8px 6px}
.video-modal{position:fixed;inset:0;background:rgba(0,0,0,.84);z-index:85;display:flex;align-items:center;justify-content:center;padding:24px}
.video-modal.hidden{display:none}
.video-modal-box{width:min(1100px,95vw);background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:0 20px 70px rgba(0,0,0,.6)}
.video-modal-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 14px;border-bottom:1px solid var(--line);font-size:12px;color:var(--dim);word-break:break-all}
.video-modal-head a{color:var(--accent);text-decoration:none}
.video-modal video{display:block;width:100%;max-height:78vh;background:#000}
@media(max-width:1150px){
  .task-table-head{display:none}
  .task-row-grid{grid-template-columns:1fr;gap:3px;padding:10px 12px}
  .col-actions{justify-content:flex-start}
  .col-status .bar-track{width:100%}
  .task-detail{padding:12px}
}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;border:1px solid var(--line);color:var(--dim)}
.badge.ok{color:var(--ok);border-color:#1f5c45}
.badge.run{color:var(--warn);border-color:#5c4a1f}
.badge.bad{color:var(--bad);border-color:#5c2525}
.console-card{display:flex;flex-direction:column;height:calc(100vh - 150px);min-height:360px}
.console{background:#0b0d12;border:1px solid var(--line);border-radius:11px;overflow-y:auto;padding:11px 13px;font:12px/1.65 ui-monospace,Consolas,monospace;white-space:pre-wrap;flex:1;min-height:0}
.console .line{margin:1px 0}
.console .t{color:#5b6376;margin-right:8px}
.console .info{color:#9fb0d0}
.console .ok{color:var(--ok)}
.console .warn{color:var(--warn)}
.console .err{color:var(--bad)}
.settings-grid{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:16px;align-items:start}
.settings-grid h3{font-size:13px;margin:0 0 10px;color:var(--fg)}
.kv{display:grid;grid-template-columns:120px 1fr;gap:7px 12px;font-size:12.5px}
.kv .k{color:var(--dim)}
.kv .v{word-break:break-all}
.sep{height:1px;background:var(--line);margin:16px 0}
input[type=checkbox]{width:15px;height:15px;accent-color:var(--accent)}
.checkline{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--fg);margin:10px 0}
.checkline label{margin:0;color:var(--fg);font-size:13px}
#lightbox{position:fixed;inset:0;background:rgba(0,0,0,.85);display:none;align-items:center;justify-content:center;z-index:50;padding:30px}
#lightbox.on{display:flex}
#lightbox img{max-width:95vw;max-height:90vh;border-radius:8px;box-shadow:0 10px 50px rgba(0,0,0,.6)}
.hidden{display:none}
a{color:var(--accent)}
@media(max-width:1150px){
  .form-grid{grid-template-columns:1fr}
  .settings-grid{grid-template-columns:1fr}
}
@media(max-width:900px){
  .app{flex-direction:column}
  .sidebar{width:100%;flex:none;height:auto;position:static;border-right:0;border-bottom:1px solid var(--line);padding:12px}
  .brand{padding-bottom:10px;margin-bottom:8px}
  .nav{display:flex;flex-wrap:wrap;gap:4px;overflow:visible}
  .nav-group{display:none}
  .nav-item{flex:1 1 44%;justify-content:flex-start;margin:0}
  .side-foot{display:none}
  .content{padding:16px}
  .console-card{height:60vh}
}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="logo" aria-hidden="true">K</div>
      <div class="brand-text"><b>WorkBuddy 媒体工作台</b><span>Kusylit's Studio</span></div>
    </div>
    <nav class="nav">
      <div class="nav-group">工作台</div>
      <button class="nav-item on" data-view="image">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9" r="1.5"/><path d="M21 16l-5-5-9 9"/></svg>
        <span>文生图</span><em class="count" id="countImage">0</em>
      </button>
      <button class="nav-item" data-view="edit">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.8 4.2L18 9l-4.2 1.8L12 15l-1.8-4.2L6 9l4.2-1.8z"/><path d="M19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/></svg>
        <span>改图</span><em class="count" id="countEdit">0</em>
      </button>
      <button class="nav-item" data-view="video">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M10 9l5 3-5 3z"/></svg>
        <span>文生视频</span><em class="count" id="countVideo">0</em>
      </button>
      <button class="nav-item" data-view="gallery">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8" cy="9" r="1.4"/><path d="M21 16l-5-5-9 9"/></svg>
        <span>作品</span>
      </button>
      <div class="nav-group">任务</div>
      <button class="nav-item" data-view="jobs">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/></svg>
        <span>任务与进度</span><em class="count" id="countJobs">0</em>
      </button>
      <div class="nav-group">系统</div>
      <button class="nav-item" data-view="console">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>
        <span>控制台</span>
      </button>
      <button class="nav-item" data-view="settings">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h8M18 7h2M4 17h2M10 17h10"/><circle cx="15" cy="7" r="2.2"/><circle cx="7" cy="17" r="2.2"/></svg>
        <span>设置</span>
      </button>
    </nav>
    <div class="side-foot">
      <div class="row2"><span>网关</span><span>127.0.0.1:8788</span></div>
      <div class="row2"><span>版本</span><span id="pageVersion" data-v="__PAGE_VERSION__">__PAGE_VERSION__</span></div>
      <div class="row2"><span>密钥</span><span>本机持有</span></div>
      <div class="row2"><span>作者</span><span>Kusylit</span></div>
    </div>
  </aside>

  <main class="content">
    <header class="content-head">
      <div>
        <h2 id="viewTitle">文生图</h2>
        <div class="view-sub" id="viewSub">文字生成图片，支持预设与自定义尺寸</div>
      </div>
      <div class="head-right">
        <span class="chip">出口 <b id="chipRealm">-</b></span>
        <span class="chip">账号 <b id="chipAccounts">-</b></span>
        <span class="chip" id="chipCreditsWrap" title="网关余额快照">余额 <b id="chipCredits">-</b></span>
        <button class="icon-btn" id="themeBtn" title="切换深色 / 浅色主题" aria-label="切换主题">☀</button>
        <button class="icon-btn" id="refreshAll" title="刷新状态、任务与模型" aria-label="刷新全部数据">↻</button>
      </div>
    </header>

    <div class="stale hidden" id="staleBanner">页面是旧缓存，服务端已更新。 <button class="mini ghost" id="staleReload">立即刷新</button></div>

    <!-- 文生图 -->
    <section class="view on" id="view-image">
      <div class="card form-card">
        <div class="form-grid">
          <div class="field">
            <label>画面描述 prompt <span class="hint">批量模式下每行一个</span></label>
            <textarea id="imgPrompt" placeholder="一只橘猫坐在窗台上晒太阳，暖色调，写实摄影"></textarea>
            <div class="btns" style="margin-top:6px"><button class="ghost mini tag-open" data-target="imgPrompt">从标签库插入</button></div>
          </div>
          <div class="field">
            <label>模型</label>
            <select id="imgModel"></select>
            <div class="hint" id="imgCaps"></div>
            <label style="margin-top:14px">分辨率</label>
            <select id="imgPreset"></select>
            <div class="preset-row hidden" id="imgCustom" style="margin-top:8px">
              <div class="field"><label>宽（16 倍数）</label><input id="imgW" type="number" step="16" min="64" max="4096" value="1024"></div>
              <div class="field"><label>高（16 倍数）</label><input id="imgH" type="number" step="16" min="64" max="4096" value="1024"></div>
            </div>
            <div class="hint" id="imgSizeHint" style="margin-top:6px"></div>
          </div>
        </div>
        <label class="checkline"><input type="checkbox" id="imgBatch"> 批量模式（每行一个 prompt，顺序提交）</label>
        <div class="queue-panel hidden" id="imgQueuePanel">
          <div class="toolbar-row" style="margin-bottom:0">
            <span class="hint" id="imgQueueSummary">队列为空</span>
            <span class="btns">
              <button class="ghost mini" id="imgQueueImport">从文本框导入</button>
              <button class="ghost mini" id="imgQueueStop">停止本批</button>
              <button class="ghost mini" id="imgQueueClear">清空队列</button>
            </span>
          </div>
          <div class="queue-list" id="imgQueueList"></div>
        </div>
        <div class="hint" id="imgCost"></div>
        <div class="save-hint" id="imgSaveHint"></div>
        <div style="margin-top:14px"><button class="primary" id="imgGo">生成图片</button><button class="ghost" id="variantToggle" style="margin-left:8px">变体生成</button><span class="hint" id="imgStatus" style="margin-left:10px"></span></div>
        <div class="progress" id="imgProgress">
          <div class="bar-track"><div class="bar-fill indet" id="imgBar"></div></div>
          <div class="progress-text" id="imgProgressText">准备中…</div>
        </div>
        <div class="err" id="imgErr"></div>
        <div class="out" id="imgOut"></div>
      </div>

      <div class="card form-card hidden" id="variantPanel">
        <div class="toolbar-row">
          <div>
            <h3 style="margin:0;font-size:15px">变体生成</h3>
            <div class="hint">固定角色与画风核心，勾选槽位后自动拼出多条 prompt；只填入批量模式，不会自动扣费。</div>
          </div>
          <button class="ghost mini" id="variantClose">收起</button>
        </div>
        <label>核心提示词模板（可用 {构图}{动作}{表情}{背景}{光线} 占位）</label>
        <textarea id="variantCore" style="min-height:160px"></textarea>
        <div class="hint" style="margin-top:6px">有占位符就替换；没有占位符时，会把选中的槽位作为“变体要求：…”追加到末尾。</div>
        <div id="variantSlots" style="margin-top:12px"></div>
        <div class="row" style="margin-top:10px;align-items:flex-end">
          <div class="field" style="max-width:130px"><label>数量</label><input id="variantCount" type="number" min="1" max="30" value="6"></div>
          <div class="field" style="max-width:180px"><label>模式</label><select id="variantMode"><option value="random">随机组合</option><option value="all">全组合（最多 20 条）</option></select></div>
          <div class="field" style="flex:1"><label>预估</label><div class="hint" id="variantCost">-</div></div>
        </div>
        <label class="checkline" style="margin-top:8px"><input type="checkbox" id="variantAppend"> 追加到现有 prompt（不覆盖）</label>
        <div class="btns" style="margin-top:12px">
          <button class="ghost" id="variantMake">生成变体列表</button>
          <button class="ghost" id="variantSubmit">生成并提交</button>
          <button class="ghost" id="variantTemplate">载入艾玛模板</button>
          <button class="ghost" id="variantLoadPrompt">载入当前 prompt</button>
        </div>
        <div class="hint" id="variantHint" style="margin-top:8px"></div>
        <div id="variantPreview" class="hidden" style="margin-top:10px">
          <div class="toolbar-row" style="margin-bottom:6px">
            <div class="hint" id="variantPreviewTitle">已生成：</div>
            <button class="ghost mini" id="variantGo">用这些变体生成图片</button>
          </div>
          <div class="job-prompt-full" id="variantList" style="max-height:220px"></div>
        </div>
      </div>
    </section>

    <!-- 改图 -->
    <section class="view" id="view-edit">
      <div class="card form-card">
        <div class="form-grid">
          <div class="field">
            <label>改动描述 prompt</label>
            <textarea id="editPrompt" placeholder="把背景换成夜晚的城市霓虹灯"></textarea>
            <div class="btns" style="margin-top:6px"><button class="ghost mini tag-open" data-target="editPrompt">从标签库插入</button></div>
            <label style="margin-top:14px">原图（可多选）</label>
            <input type="file" id="editFiles" accept="image/*" multiple>
            <div class="file-preview" id="editFilePreview"></div>
          </div>
          <div class="field">
            <label>模型</label>
            <select id="editModel"></select>
            <div class="hint" id="editCaps"></div>
            <label style="margin-top:14px">分辨率</label>
            <select id="editPreset"></select>
            <div class="preset-row hidden" id="editCustom" style="margin-top:8px">
              <div class="field"><label>宽</label><input id="editW" type="number" step="16" min="64" max="4096" value="1024"></div>
              <div class="field"><label>高</label><input id="editH" type="number" step="16" min="64" max="4096" value="1024"></div>
            </div>
            <div class="hint" id="editSizeHint" style="margin-top:6px"></div>
          </div>
        </div>
        <div class="hint" id="editCost"></div>
        <div class="save-hint" id="editSaveHint"></div>
        <div style="margin-top:14px"><button class="primary" id="editGo">生成改图</button><span class="hint" id="editStatus" style="margin-left:10px"></span></div>
        <div class="progress" id="editProgress">
          <div class="bar-track"><div class="bar-fill indet" id="editBar"></div></div>
          <div class="progress-text" id="editProgressText">准备中…</div>
        </div>
        <div class="err" id="editErr"></div>
        <div class="out" id="editOut"></div>
      </div>
    </section>

    <!-- 生视频 -->
    <section class="view" id="view-video">
      <div class="card form-card">
        <div class="form-grid">
          <div class="field">
            <label>画面描述 prompt</label>
            <textarea id="vidPrompt" placeholder="一只橘猫在窗台上慢慢伸懒腰，阳光洒进来，镜头缓慢推近"></textarea>
            <div class="btns" style="margin-top:6px"><button class="ghost mini tag-open" data-target="vidPrompt">从标签库插入</button></div>
            <details class="adv">
              <summary>高级：首帧 / 尾帧 / 参考图 / 负向提示</summary>
              <div class="field"><label>首帧图（可选，图生视频）</label><input type="file" id="vidFirst" accept="image/*"><div class="file-preview" id="vidFirstPreview"></div></div>
              <div class="field" style="margin-top:10px"><label>尾帧图（可选）</label><input type="file" id="vidLast" accept="image/*"><div class="file-preview" id="vidLastPreview"></div></div>
              <div class="field" id="vidRefWrap" style="margin-top:10px"><label>参考图（可多选，上限随模型）</label><input type="file" id="vidRefs" accept="image/*" multiple><div class="file-preview" id="vidRefsPreview"></div></div>
              <label style="margin-top:10px">负向提示词（可选）</label>
              <textarea id="vidNegative" style="min-height:64px" placeholder="不要出现文字、水印、变形"></textarea>
            </details>
          </div>
          <div class="field">
            <label>模型</label>
            <select id="vidModel"></select>
            <div class="hint" id="vidCaps"></div>
            <label style="margin-top:14px">分辨率</label>
            <select id="vidResolution"></select>
            <label style="margin-top:14px">画面比例</label>
            <select id="vidAspect"></select>
            <label style="margin-top:14px">时长</label>
            <select id="vidSeconds"></select>
            <label class="checkline" style="margin-top:12px"><input type="checkbox" id="vidAudio"> 生成音频</label>
            <div class="hint" id="vidAudioHint"></div>
          </div>
        </div>
        <label class="checkline"><input type="checkbox" id="vidBatch"> 批量模式（每行一个 prompt，依次提交）</label>
        <div class="queue-panel hidden" id="vidQueuePanel">
          <div class="toolbar-row" style="margin-bottom:0">
            <span class="hint" id="vidQueueSummary">队列为空</span>
            <span class="btns">
              <button class="ghost mini" id="vidQueueImport">从文本框导入</button>
              <button class="ghost mini" id="vidQueueStop">停止本批</button>
              <button class="ghost mini" id="vidQueueClear">清空队列</button>
            </span>
          </div>
          <div class="queue-list" id="vidQueueList"></div>
        </div>
        <div class="hint" id="vidCost"></div>
        <div class="save-hint" id="vidSaveHint"></div>
        <div style="margin-top:14px"><button class="primary" id="vidGo">提交视频任务</button><span class="hint" id="vidStatus" style="margin-left:10px"></span></div>
        <div class="err" id="vidErr"></div>
        <div class="meta">视频是异步任务：上游不提供百分比，任务卡按阶段显示进度与已用时间。提交后关闭页面也会继续轮询并自动保存。</div>
      </div>
    </section>

    <!-- 任务 -->
    <section class="view" id="view-jobs">
      <div class="card">
        <div class="toolbar-row">
          <div class="stats" id="jobsStats"></div>
          <div class="btns">
            <button class="ghost mini" id="jobsSync">同步历史</button>
            <button class="ghost mini" id="jobsClear">清除完成</button>
          </div>
        </div>
        <div class="task-filterbar">
          <div class="filters" id="jobFilters">
            <button class="on" data-filter="all">全部</button>
            <button data-filter="active">进行中</button>
            <button data-filter="completed">已完成</button>
            <button data-filter="failed">失败</button>
          </div>
          <div class="filters" id="jobTypeFilters">
            <button class="on" data-type="all">全部类型</button>
            <button data-type="image">图片</button>
            <button data-type="video">视频</button>
          </div>
          <select id="jobModelFilter" style="max-width:200px"><option value="all">全部模型</option></select>
          <select id="jobDateFilter" style="max-width:130px">
            <option value="all">全部时间</option>
            <option value="today">今天</option>
            <option value="7d">近 7 天</option>
          </select>
          <input id="jobsSearch" placeholder="搜索 prompt / 模型 / 任务 ID" style="flex:1;min-width:180px">
        </div>
        <div class="task-table">
          <div class="task-table-head">
            <div>类型</div><div>任务 / 模型</div><div>状态 / 进度</div>
            <div>耗时</div><div>积分</div><div>操作</div>
          </div>
          <div id="jobsList"><div class="meta">暂无任务</div></div>
        </div>
        <div class="task-pager">
          <button class="ghost mini" id="jobsPrev">上一页</button>
          <span class="hint" id="jobsPage">1 / 1</span>
          <button class="ghost mini" id="jobsNext">下一页</button>
        </div>
      </div>
    </section>

    <!-- 作品 -->
    <section class="view" id="view-gallery">
      <div class="card">
        <div class="toolbar-row">
          <div class="stats" id="galleryStats">读取中…</div>
          <div class="btns">
            <button class="ghost mini" id="galleryRename">整理名称</button>
            <button class="ghost mini" id="galleryRefresh">刷新</button>
            <button class="ghost mini hidden" id="galleryMore">加载更多</button>
          </div>
        </div>
        <div class="filters" id="galleryFilters">
          <button class="on" data-g="all">全部</button>
          <button data-g="image">图片</button>
          <button data-g="video">视频</button>
          <button data-g="fav">收藏</button>
        </div>
        <div class="gallery-tools">
          <input type="search" id="gallerySearch" placeholder="搜索作品名称，多个关键词用空格分隔" autocomplete="off">
          <select id="galleryTime" aria-label="按时间筛选">
            <option value="all">全部时间</option>
            <option value="today">今天</option>
            <option value="3">近 3 天</option>
            <option value="7">近 7 天</option>
            <option value="30">近 30 天</option>
            <option value="custom">自定义日期</option>
          </select>
          <span class="gallery-range hidden" id="galleryRange">
            <input type="date" id="galleryFrom" aria-label="开始日期">
            <span class="range-sep">至</span>
            <input type="date" id="galleryTo" aria-label="结束日期">
          </span>
          <button class="ghost mini" id="galleryReset" type="button">重置筛选</button>
          <span class="gallery-shown" id="galleryShown"></span>
        </div>
        <div class="gallery-grid" id="galleryGrid"></div>
      </div>
    </section>

    <!-- 控制台 -->
    <section class="view" id="view-console">      <div class="card console-card">
        <div class="toolbar-row">
          <div class="filters" id="consoleLevels">
            <button class="on" data-level="all">全部</button>
            <button data-level="info">信息</button>
            <button data-level="ok">成功</button>
            <button data-level="warn">警告</button>
            <button data-level="err">错误</button>
          </div>
          <div class="btns">
            <button class="ghost mini" id="consoleDownload">下载日志</button>
            <button class="ghost mini" id="consoleClear">清空</button>
          </div>
        </div>
        <div class="toolbar-row">
          <input id="consoleSearch" placeholder="搜索日志">
          <label class="checkline" style="margin:0"><input type="checkbox" id="consolePause"> 暂停自动滚动</label>
        </div>
        <div class="console" id="console"></div>
      </div>
    </section>

    <!-- 设置 -->
    <section class="view" id="view-settings">
      <div class="settings-grid">
        <div class="card">
          <h3>保存目录</h3>
          <div class="field">
            <input id="saveDir" placeholder="例如 D:\AI\kusylit-studio">
          </div>
          <div class="hint" id="dirDirty" style="color:var(--warn);margin-top:6px"></div>
          <div class="btns" style="margin-top:10px">
            <button class="ghost" id="saveDirBtn">保存目录</button>
            <button class="ghost" id="openDirBtn">打开文件夹</button>
          </div>
          <div class="sep"></div>
          <h3>余额刷新</h3>
          <label>看板密码（仅本次刷新使用，不保存）</label>
          <input id="panelPassword" type="password" placeholder="默认 admin" autocomplete="current-password">
          <div class="btns" style="margin-top:10px">
            <button class="ghost" id="refreshBalanceBtn">刷新上游余额</button>
          </div>
          <div class="hint" id="panelPwdHint" style="margin-top:6px">余额默认取网关内部快照；刷新会请求上游，约 1–3 秒。</div>
          <div class="sep"></div>
          <h3>工作台访问密码</h3>
          <label>启用后所有 API 都需要密码；局域网访问必开</label>
          <input id="accessPassword" type="password" placeholder="留空表示不启用" autocomplete="new-password">
          <div class="btns" style="margin-top:10px">
            <button class="ghost" id="saveAccessPwd">启用 / 修改</button>
            <button class="ghost" id="clearAccessPwd">关闭密码</button>
          </div>
          <div class="hint" id="accessHint"></div>
          <div class="sep"></div>
          <h3>导出 / 导入 / 目录</h3>
          <div class="btns">
            <button class="ghost" id="exportTags">导出标签</button>
            <button class="ghost" id="importTagsBtn">导入标签</button>
            <input type="file" id="importTagsFile" accept=".json" class="hidden">
            <button class="ghost" id="openConfigDir">打开配置目录</button>
          </div>
          <div class="hint" id="diskUsage"></div>
          <div class="sep"></div>
          <h3>说明</h3>
          <div class="hint">图片和视频完成后自动下载到该目录。视频任务完成时使用当时的目录设置；修改目录只影响之后完成的任务。工作台只监听 127.0.0.1。</div>
        </div>
        <div class="card">
          <h3>网关状态</h3>
          <div class="kv" id="healthBox">
            <div class="k">状态</div><div class="v" id="hGateway">-</div>
            <div class="k">出口</div><div class="v" id="hRealm">-</div>
            <div class="k">账号</div><div class="v" id="hAccounts">-</div>
            <div class="k">媒体</div><div class="v" id="hMedia">-</div>
            <div class="k">模型</div><div class="v" id="hModels">-</div>
            <div class="k">余额</div><div class="v" id="hCredits">-</div>
            <div class="k">上游快照时间</div><div class="v" id="hCreditsAt">-</div>
            <div class="k">页面版本</div><div class="v" id="hVersion">-</div>
          </div>
          <div class="btns" style="margin-top:14px">
            <button class="ghost mini" id="healthBtn2">刷新全部</button>
            <button class="ghost mini" id="reloadBtn">强制重载页面</button>
          </div>
          <div class="sep"></div>
          <h3>最近操作审计</h3>
          <div class="console" id="auditLog" style="height:150px;min-height:0"></div>
          <div class="btns" style="margin-top:8px"><button class="ghost mini" id="auditRefresh">刷新审计</button></div>
        </div>
      </div>
    </section>
  </main>
</div>
<div class="drawer-overlay hidden" id="tagOverlay"></div>
<aside class="drawer" id="tagDrawer">
  <div class="panel-head">
    <h2>提示词标签</h2>
    <button class="ghost mini" id="tagClose">关闭</button>
  </div>
  <div class="hint" id="tagTargetHint">插入到：生图 prompt</div>
  <input id="tagSearch" placeholder="搜索标签内容 / 分类" style="margin-top:10px">
  <div class="tag-cats" id="tagCats"></div>
  <div class="btns" style="margin-bottom:8px">
    <button class="ghost mini" id="tagManageToggle">管理分类</button>
    <button class="ghost mini" id="tagInsertSelected">插入选中标签</button>
  </div>
  <div class="hidden" id="tagManage" style="border:1px solid var(--line);border-radius:10px;padding:10px;margin-bottom:10px;background:var(--panel2)">
    <div class="row" style="margin-bottom:6px">
      <div class="field"><input id="newTagCategory" placeholder="新分类名"></div>
      <button class="ghost mini" id="addTagCategory">添加</button>
    </div>
    <div id="tagCategoryList"></div>
  </div>
  <div class="tag-form">
    <textarea id="tagText" placeholder="标签内容，例如：粗糙黑色线稿，断线错位，平涂溢色"></textarea>
    <div class="row" style="margin-top:6px;margin-bottom:0">
      <div class="field"><input id="tagCategory" list="tagCatList" placeholder="分类，例如 风格 / 构图"></div>
      <datalist id="tagCatList"></datalist>
    </div>
    <div class="btns">
      <button class="primary" id="tagSave">保存标签</button>
      <button class="ghost" id="tagCancelEdit">取消编辑</button>
      <button class="ghost" id="tagUseSelection">填入选中文本</button>
    </div>
  </div>
  <div class="tag-list" id="tagList"></div>
</aside>
<div id="accessGate" class="access-gate hidden">
  <div class="card" style="max-width:380px;width:90%">
    <div class="gate-brand">
      <div class="logo" aria-hidden="true">K</div>
      <div class="brand-text"><b>WorkBuddy 媒体工作台</b><span>Kusylit's Studio</span></div>
    </div>
    <h3 style="margin:0 0 8px">访问受保护</h3>
    <div class="hint">输入访问密码后继续。</div>
    <input id="gatePassword" type="password" placeholder="访问密码" style="margin-top:10px">
    <div class="btns" style="margin-top:10px"><button class="primary" id="gateEnter">进入</button></div>
    <div class="err" id="gateErr"></div>
  </div>
</div>
<div id="toastBox" class="toast-box"></div>
<div id="videoModal" class="video-modal hidden">
  <div class="video-modal-box">
    <div class="video-modal-head">
      <span id="videoTitle">视频</span>
      <span class="btns">
        <a id="videoDownload" href="#" download>下载</a>
        <button class="ghost mini" id="videoClose">关闭</button>
      </span>
    </div>
    <video id="videoPlayer" controls playsinline></video>
  </div>
</div>
<div id="lightbox"><img id="lightboxImg" alt="preview"></div>
<script nonce="__CSP_NONCE__">
const $ = id => document.getElementById(id);
const VIEW_META = {
  image:{title:'文生图', sub:'文字生成图片，支持预设与自定义尺寸'},
  edit:{title:'改图', sub:'上传一张或多张原图，按描述修改'},
  video:{title:'文生视频', sub:'异步生成，支持首尾帧、参考图和负向提示'},
  jobs:{title:'任务与进度', sub:'所有任务的状态、积分、文件与操作'},
  gallery:{title:'作品', sub:'保存目录里的图片与视频'},
  console:{title:'控制台', sub:'服务端持久化日志与本次会话记录'},
  settings:{title:'设置', sub:'保存目录、网关状态与版本信息'}
};
let currentView = 'image';

function showView(name){
  if(!VIEW_META[name]) name = 'image';
  currentView = name;
  if($('tagDrawer').classList.contains('on')) closeTagDrawer();
  if(!$('videoModal').classList.contains('hidden')) closeVideoPlayer();
  $('lightbox').classList.remove('on');
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('on', v.id === 'view-' + name));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('on', b.dataset.view === name));
  $('viewTitle').textContent = VIEW_META[name].title;
  $('viewSub').textContent = VIEW_META[name].sub;
  location.hash = name;
  if(name === 'jobs') renderJobs();
  if(name === 'gallery') loadGallery();
  if(name === 'console') renderConsole();
  if(name === 'settings'){ loadDiskUsage(); loadAudit(); }
}
document.querySelectorAll('.nav-item').forEach(b => b.onclick = () => showView(b.dataset.view));

function tsOf(t){
  const d = new Date((t || Date.now()/1000) * 1000);
  return d.toLocaleTimeString('zh-CN', {hour12:false});
}
function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtElapsed(sec){
  sec = Math.max(0, sec);
  if(sec < 60) return sec.toFixed(1) + ' 秒';
  const m = Math.floor(sec/60), s = Math.floor(sec%60);
  return m + ' 分 ' + s + ' 秒';
}
function statusLabel(st){
  return {queued:'排队中', waiting:'等待中', submitting:'提交上游', running:'生成中',
          in_progress:'生成中', processing:'生成中', saving:'保存中', completed:'已完成',
          failed:'失败', rejected:'被拒绝', cancelled:'已取消', lost:'失败',
          unknown:'未知'}[st] || '未知';
}
function statusClass(st){
  return st === 'completed' ? 'ok' : ['failed','rejected','cancelled','lost'].includes(st) ? 'bad' : 'run';
}
function isActive(st){ return ['queued','waiting','submitting','running','in_progress','processing','saving','unknown'].includes(st); }
function setCount(id, n, unit){
  const el = $(id); if(!el) return;
  el.textContent = n + (unit ? ' ' + unit : '');
  el.classList.toggle('hidden', !n);
}
const STUDIO_TOKEN = '__STUDIO_TOKEN__';
const ACCESS_REQUIRED = __ACCESS_REQUIRED__;
try { sessionStorage.removeItem('studioAccess'); } catch(e){}
let accessPassword = '';
function accessToken(){ return accessPassword; }
function applyTheme(light){
  document.body.classList.toggle('light', light);
  if($('themeBtn')) $('themeBtn').textContent = light ? '☾' : '☀';
  const meta = document.querySelector('meta[name="theme-color"]');
  if(meta) meta.setAttribute('content', light ? '#f4f6fb' : '#0f1115');
}
try { applyTheme(localStorage.getItem('wbTheme') === 'light'); } catch(e){}
$('themeBtn').onclick = () => {
  const light = !document.body.classList.contains('light');
  applyTheme(light);
  try { localStorage.setItem('wbTheme', light ? 'light' : 'dark'); } catch(e){}
};
$('staleReload').onclick = () => location.reload();
let accessPromptPromise = null;
let staleNoticeShown = false;
function showStaleNotice(){
  if(staleNoticeShown) return;
  staleNoticeShown = true;
  $('staleBanner').classList.remove('hidden');
  toast('页面与服务端版本不一致，请刷新页面', 'warn');
}
function askAccess(){
  if(!accessPromptPromise){
    accessPromptPromise = new Promise(resolve => {
      const pwd = (window.prompt('工作台访问密码：') || '').trim();
      if(pwd) accessPassword = pwd;
      resolve(!!pwd);
    }).finally(() => { accessPromptPromise = null; });
  }
  return accessPromptPromise;
}
function toast(text, type){
  const box = $('toastBox');
  if(!box) return;
  const el = document.createElement('div');
  el.className = 'toast ' + (type || 'info');
  el.textContent = text;
  box.appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .2s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 250);
  }, 2800);
}
async function api(path, body, retried){
  const headers = {'X-Studio-Token': STUDIO_TOKEN};
  const at = accessToken();
  if(at) headers['X-Studio-Access'] = at;
  if(body !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(path, body === undefined
    ? {headers}
    : {method:'POST', headers, body: JSON.stringify(body)});
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch(e) { data = {error:{message:text}}; }
  if(!data || typeof data !== 'object') data = {error:{message:text}};
  const msg = (data.error && data.error.message) || ('HTTP ' + r.status);
  if(r.status === 401 && /access password/i.test(msg) && !retried
      && $('accessGate').classList.contains('hidden')){
    const ok = await askAccess();
    if(ok) return api(path, body, true);
  }
  if(r.status === 401 && /studio token/i.test(msg)){
    showStaleNotice();
  }
  if(!r.ok) throw new Error(msg);
  return data;
}

// ---------------- 控制台 ----------------
const consoleState = {lines:[], level:'all', search:'', paused:false};
function consoleMatch(line){
  if(consoleState.level !== 'all' && line.level !== consoleState.level) return false;
  if(consoleState.search && !String(line.msg).toLowerCase().includes(consoleState.search.toLowerCase())) return false;
  return true;
}
function lineHtml(line){
  const level = ['info','ok','warn','err'].includes(line.level) ? line.level : 'info';
  return '<div class="line ' + level + '"><span class="t">' + tsOf(line.t) + '</span>' + esc(line.msg) + '</div>';
}
function renderConsole(){
  const box = $('console');
  box.innerHTML = consoleState.lines.filter(consoleMatch).map(lineHtml).join('');
  if(!consoleState.paused) box.scrollTop = box.scrollHeight;
}
function appendConsole(line){
  consoleState.lines.push(line);
  if(consoleState.lines.length > 600) consoleState.lines.shift();
  if(consoleMatch(line)){
    const box = $('console');
    box.insertAdjacentHTML('beforeend', lineHtml(line));
    if(!consoleState.paused) box.scrollTop = box.scrollHeight;
    while(box.childElementCount > 600) box.removeChild(box.firstChild);
  }
}
function log(text, level){ appendConsole({t: Date.now()/1000, level: level || 'info', msg: text}); }
async function loadConsoleHistory(){
  try{
    const d = await api('/api/logs');
    const items = (d.logs || []).map(item => ({t:item.t, level:item.level || 'info', msg:item.msg}));
    if(items.length){
      consoleState.lines = [{t: items[0].t, level:'warn', msg:'—— 服务端历史日志 ——'}]
        .concat(items, consoleState.lines);
    }
  }catch(e){}
  renderConsole();
}
$('consoleLevels').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-level]'); if(!btn) return;
  consoleState.level = btn.dataset.level;
  document.querySelectorAll('#consoleLevels button').forEach(b => b.classList.toggle('on', b === btn));
  renderConsole();
});
$('consoleSearch').addEventListener('input', () => { consoleState.search = $('consoleSearch').value.trim(); renderConsole(); });
$('consolePause').addEventListener('change', () => { consoleState.paused = $('consolePause').checked; });
$('consoleClear').onclick = async () => {
  consoleState.lines = []; renderConsole();
  try { await api('/api/logs/clear', {}); } catch(e) {}
};
$('consoleDownload').onclick = () => {
  const text = consoleState.lines.map(l => '[' + tsOf(l.t) + '] [' + (l.level||'info') + '] ' + l.msg).join('\r\n');
  const blob = new Blob([text], {type:'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'kusylit-studio-console-' + new Date().toISOString().replace(/[:.]/g,'-').slice(0,19) + '.log';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
};

// ---------------- 作品 / 设置扩展 ----------------
let galleryItems = [], galleryFilter = 'all', galleryTime = 'all', gallerySaveDir = '', galleryTotal = 0, galleryTotalSize = 0, galleryFavorites = 0, galleryLoadSeq = 0;
let galleryObserver = null;
function formatBytes(n){
  if(!n) return '0 B';
  const units = ['B','KB','MB','GB'];
  let value = n, i = 0;
  while(value >= 1024 && i < units.length - 1){ value /= 1024; i++; }
  return value.toFixed(i ? 1 : 0) + ' ' + units[i];
}
function updateGalleryStats(){
  $('galleryStats').textContent = '共 ' + (galleryTotal || galleryItems.length)
    + ' 个文件 · 收藏 ' + galleryFavorites + ' · ' + formatBytes(galleryTotalSize || 0)
    + ' · ' + gallerySaveDir;
}
async function loadGallery(append){
  const seq = ++galleryLoadSeq;
  try{
    const offset = append ? galleryItems.length : 0;
    const d = await api('/api/gallery?limit=1000&offset=' + offset);
    if(seq !== galleryLoadSeq) return false;
    const incoming = Array.isArray(d.items) ? d.items : [];
    if(append){
      const seen = new Set(galleryItems.map(i => i.name));
      galleryItems = galleryItems.concat(incoming.filter(i => !seen.has(i.name)));
    }else{
      galleryItems = incoming;
    }
    gallerySaveDir = d.save_dir || '';
    galleryTotal = d.total || galleryItems.length;
    galleryTotalSize = d.total_size || 0;
    galleryFavorites = d.favorites_count || 0;
    updateGalleryStats();
    renderGallery();
    const more = $('galleryMore');
    if(more){
      more.classList.toggle('hidden', galleryTotal <= galleryItems.length);
      more.textContent = '加载更多（剩余 ' + Math.max(0, galleryTotal - galleryItems.length) + '）';
    }
    return true;
  }catch(e){
    if(seq === galleryLoadSeq) $('galleryStats').textContent = '读取失败: ' + e.message;
    return false;
  }
}
function galleryActions(item){
  const name = esc(item.name);
  return '<div class="gallery-actions">'
    + '<button class="gallery-act fav' + (item.favorite ? ' on' : '') + '" data-gact="fav" data-name="'
    + name + '" title="收藏">' + (item.favorite ? '★' : '☆') + '</button>'
    + '<button class="gallery-act del" data-gact="del" data-name="' + name + '" title="删除">删除</button>'
    + '</div>';
}
function galleryTimeMatch(item){
  if(galleryTime === 'all') return true;
  const ts = Number(item.mtime || 0) * 1000;
  if(!ts) return false;
  if(galleryTime === 'custom'){
    const from = $('galleryFrom').value, to = $('galleryTo').value;
    if(!from && !to) return true;
    const start = from ? new Date(from + 'T00:00:00').getTime() : -Infinity;
    const end = to ? new Date(to + 'T23:59:59.999').getTime() : Infinity;
    return ts >= start && ts <= end;
  }
  if(galleryTime === 'today'){
    const start = new Date(); start.setHours(0, 0, 0, 0);
    return ts >= start.getTime();
  }
  const days = parseInt(galleryTime, 10);
  const start = new Date(); start.setHours(0, 0, 0, 0);
  start.setDate(start.getDate() - (days - 1));
  return ts >= start.getTime();
}
function galleryNameMatch(item, terms){
  if(!terms.length) return true;
  const name = String(item.name || '').toLowerCase();
  return terms.every(term => name.includes(term));
}
function renderGallery(){
  const terms = $('gallerySearch').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const items = galleryItems.filter(i => {
    if(galleryFilter === 'fav'){ if(!i.favorite) return false; }
    else if(galleryFilter !== 'all' && i.type !== galleryFilter) return false;
    return galleryTimeMatch(i) && galleryNameMatch(i, terms);
  });
  const box = $('galleryGrid');
  let shown = '显示 ' + items.length + ' / ' + (galleryTotal || galleryItems.length) + ' 个';
  if(galleryTotal > galleryItems.length) shown += '（已载入 ' + galleryItems.length + ' 个）';
  $('galleryShown').textContent = shown;
  if(!items.length){
    let msg = galleryFilter === 'fav' ? '还没有收藏的作品' : '没有作品';
    if(terms.length || galleryTime !== 'all') msg = '没有匹配的作品';
    box.innerHTML = '<div class="meta">' + msg + '</div>';
    return;
  }
  box.innerHTML = items.map(item => {
    const name = esc(item.name);
    const url = esc(item.url || '');
    const actions = galleryActions(item);
    if(item.type === 'image'){
      return '<div class="gallery-item" data-src="' + url + '">' + actions
        + '<img loading="lazy" src="' + url + '" alt="' + name + '">'
        + '<div class="gname">' + name + '</div></div>';
    }
    return '<div class="gallery-item video" data-video="' + url + '" data-name="' + name + '">'
      + actions
      + '<video src="' + url + '#t=0.1" preload="metadata" muted playsinline></video>'
      + '<div class="gplay">▶</div><div class="gname">' + name + '</div></div>';
  }).join('');
  initGalleryVideos();
}
function initGalleryVideos(){
  if(galleryObserver){ galleryObserver.disconnect(); galleryObserver = null; }
  const videos = [...document.querySelectorAll('#galleryGrid video')];
  if(!videos.length) return;
  const load = v => {
    if(v.dataset.frameReady) return;
    v.dataset.frameReady = '1';
    v.preload = 'metadata';
    const seek = () => {
      try{
        if(v.duration && v.currentTime === 0) v.currentTime = Math.min(0.2, v.duration / 10);
      }catch(e){}
    };
    v.addEventListener('loadedmetadata', seek, {once:true});
    v.addEventListener('seeked', () => { try{ v.pause(); }catch(e){} }, {once:true});
    try{ v.load(); }catch(e){}
  };
  if('IntersectionObserver' in window){
    galleryObserver = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if(entry.isIntersecting){ load(entry.target); galleryObserver.unobserve(entry.target); }
      });
    }, {rootMargin:'250px'});
    videos.forEach(v => galleryObserver.observe(v));
  }else{
    videos.forEach(load);
  }
}
function openVideoPlayer(url, name){
  $('videoTitle').textContent = name || '视频';
  $('videoDownload').href = url;
  $('videoDownload').setAttribute('download', name || 'video.mp4');
  const player = $('videoPlayer');
  player.src = url;
  $('videoModal').classList.remove('hidden');
  player.play().catch(() => {});
}
function closeVideoPlayer(){
  const player = $('videoPlayer');
  try{ player.pause(); }catch(e){}
  player.removeAttribute('src');
  try{ player.load(); }catch(e){}
  $('videoModal').classList.add('hidden');
}
$('videoClose').onclick = closeVideoPlayer;
$('videoModal').addEventListener('click', ev => {
  if(ev.target === $('videoModal')) closeVideoPlayer();
});
$('galleryRefresh').onclick = async () => {
  const ok = await loadGallery();
  toast(ok ? '作品已刷新' : '作品刷新失败', ok ? 'ok' : 'err');
};
$('galleryMore').onclick = async () => {
  const btn = $('galleryMore');
  btn.disabled = true;
  try {
    const ok = await loadGallery(true);
    if(!ok) toast('加载更多失败', 'err');
  } finally {
    btn.disabled = false;
  }
};
$('galleryRename').onclick = async () => {
  if(!confirm('根据任务记录 / 网关历史给旧作品重命名？\n只处理能匹配到 prompt 的文件；无 prompt 记录的图片会跳过。')) return;
  const btn = $('galleryRename');
  btn.disabled = true;
  btn.textContent = '整理中…';
  try{
    const d = await api('/api/rename-artifacts', {});
    toast('已重命名 ' + d.renamed + ' 个文件', 'ok');
    log('整理作品名称：重命名 ' + d.renamed + ' 个', 'ok');
    if(d.errors && d.errors.length) log('部分重命名失败: ' + d.errors.join('; '), 'warn');
    loadGallery();
    loadJobs();
  }catch(e){
    toast('整理名称失败: ' + e.message, 'err');
    log('整理名称失败: ' + e.message, 'err');
  }finally{
    btn.disabled = false;
    btn.textContent = '整理名称';
  }
};
$('galleryFilters').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-g]'); if(!btn) return;
  galleryFilter = btn.dataset.g;
  document.querySelectorAll('#galleryFilters button').forEach(b => b.classList.toggle('on', b === btn));
  renderGallery();
});
let gallerySearchTimer = null;
$('gallerySearch').addEventListener('input', () => {
  clearTimeout(gallerySearchTimer);
  gallerySearchTimer = setTimeout(renderGallery, 120);
});
$('galleryTime').addEventListener('change', () => {
  galleryTime = $('galleryTime').value;
  const custom = galleryTime === 'custom';
  $('galleryRange').classList.toggle('hidden', !custom);
  if(custom && !$('galleryFrom').value && !$('galleryTo').value){
    const fmt = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
    const to = new Date(), from = new Date();
    from.setDate(from.getDate() - 6);
    $('galleryFrom').value = fmt(from);
    $('galleryTo').value = fmt(to);
  }
  renderGallery();
});
['galleryFrom', 'galleryTo'].forEach(id => {
  $(id).addEventListener('change', () => { if(galleryTime === 'custom') renderGallery(); });
});
$('galleryReset').onclick = () => {
  galleryTime = 'all';
  galleryFilter = 'all';
  $('galleryTime').value = 'all';
  $('gallerySearch').value = '';
  $('galleryFrom').value = '';
  $('galleryTo').value = '';
  $('galleryRange').classList.add('hidden');
  document.querySelectorAll('#galleryFilters button').forEach(b => b.classList.toggle('on', b.dataset.g === 'all'));
  renderGallery();
};
async function toggleGalleryFavorite(name){
  const item = galleryItems.find(i => i.name === name);
  if(!item || item.favBusy) return;
  const next = !item.favorite;
  item.favBusy = true;
  try{
    const d = await api('/api/favorites', {name, favorite: next});
    if(!!d.favorite !== !!item.favorite) galleryFavorites += d.favorite ? 1 : -1;
    item.favorite = d.favorite;
    updateGalleryStats();
    renderGallery();
    toast(next ? '已收藏' : '已取消收藏', 'ok');
  }catch(e){
    toast('收藏失败: ' + e.message, 'err');
    log('收藏失败: ' + e.message, 'err');
  }finally{
    item.favBusy = false;
  }
}
async function deleteGalleryItem(name){
  if(!confirm('删除作品「' + name + '」？\n文件会从保存目录永久删除，无法恢复。')) return;
  try{
    await api('/api/gallery/delete', {name});
    toast('已删除作品', 'ok');
    log('删除作品: ' + name, 'warn');
    await loadGallery();
    loadJobs();
  }catch(e){
    toast('删除失败: ' + e.message, 'err');
    log('删除失败: ' + e.message, 'err');
  }
}
$('galleryGrid').addEventListener('click', async ev => {
  const act = ev.target.closest('button[data-gact]');
  if(act){
    ev.preventDefault();
    ev.stopPropagation();
    const name = act.dataset.name;
    if(act.dataset.gact === 'fav') await toggleGalleryFavorite(name);
    else if(act.dataset.gact === 'del') await deleteGalleryItem(name);
    return;
  }
  const video = ev.target.closest('.gallery-item[data-video]');
  if(video){ openVideoPlayer(video.dataset.video, video.dataset.name); return; }
  const item = ev.target.closest('.gallery-item[data-src]');
  if(item) openLightbox(item.dataset.src);
});
async function loadDiskUsage(){
  try{
    const d = await api('/api/gallery?limit=1');
    $('diskUsage').textContent = '保存目录：' + d.save_dir + ' · ' + d.total
      + ' 个文件 · ' + formatBytes(d.total_size || 0);
  }catch(e){}
}
$('exportTags').onclick = async () => {
  try{
    const d = await api('/api/tags');
    const blob = new Blob([JSON.stringify(d, null, 2)], {type:'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'kusylit-studio-tags.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    toast('标签已导出', 'ok');
  }catch(e){ toast('导出失败: ' + e.message, 'err'); }
};
$('importTagsBtn').onclick = () => $('importTagsFile').click();
$('importTagsFile').addEventListener('change', async () => {
  const file = $('importTagsFile').files[0];
  if(!file) return;
  try{
    const data = JSON.parse(await file.text());
    const list = Array.isArray(data) ? data : (data.tags || []);
    if(!Array.isArray(list)) throw new Error('文件里没有 tags 数组');
    const d = await api('/api/tags/import', {tags: list});
    toast('已导入 ' + (d.added || 0) + ' 个标签，跳过 ' + (d.skipped || 0) + ' 个', 'ok');
    await loadTags();
  }catch(e){ toast('导入失败: ' + e.message, 'err'); log('导入标签失败: ' + e.message, 'err'); }
  finally{ $('importTagsFile').value = ''; }
});
$('openConfigDir').onclick = async () => {
  try{ await api('/api/open-config', {}); toast('已打开配置目录', 'ok'); }
  catch(e){ toast('打开失败: ' + e.message, 'err'); }
};

// ---------------- 配置 ----------------
let cfgSaveDir = '';
function updateSaveHints(){
  ['imgSaveHint','editSaveHint','vidSaveHint'].forEach(id => {
    const el = $(id); if(el) el.textContent = '保存到：' + (cfgSaveDir || '-') + '（可在「设置」修改）';
  });
}
async function loadConfig(){
  try{
    const d = await api('/api/config');
    cfgSaveDir = d.save_dir;
    $('saveDir').value = d.save_dir;
    $('panelPassword').placeholder = '默认 admin（不保存）';
    if($('accessHint')) $('accessHint').textContent = d.access_required
      ? '已启用：所有 API 需要访问密码' : '未启用：仅监听 127.0.0.1';
    updateSaveHints();
    const pageV = $('pageVersion').dataset.v;
    if(d.version && pageV && pageV !== d.version){
      $('staleBanner').classList.remove('hidden');
      log('页面版本 ' + pageV + ' 落后于服务端 ' + d.version + '，请刷新', 'warn');
    }
  }catch(e){ log('读取保存目录失败: ' + e.message, 'err'); }
}
let saveDirPromise = null;
async function persistSaveDir(){
  const v = $('saveDir').value.trim();
  if(!v) return;
  if(v === cfgSaveDir){ $('dirDirty').textContent = ''; return; }
  if(saveDirPromise) return saveDirPromise;
  saveDirPromise = (async () => {
    const d = await api('/api/config', {save_dir: v});
    cfgSaveDir = d.save_dir;
    $('saveDir').value = d.save_dir;
    $('dirDirty').textContent = '';
    updateSaveHints();
    await loadDiskUsage();
    log('保存目录已更新: ' + d.save_dir, 'ok');
    toast('保存目录已更新', 'ok');
  })().finally(() => { saveDirPromise = null; });
  return saveDirPromise;
}
$('saveDir').addEventListener('input', () => { $('dirDirty').textContent = '未保存'; });
$('saveDir').addEventListener('blur', () => { persistSaveDir().catch(e => log('保存目录设置失败: ' + e.message, 'err')); });
$('saveDirBtn').onclick = () => persistSaveDir().catch(e => log('保存目录设置失败: ' + e.message, 'err'));
$('openDirBtn').onclick = async () => {
  try { await persistSaveDir(); await api('/api/open-folder', {}); }
  catch(e){ log('打开目录失败: ' + e.message, 'err'); }
};
$('refreshBalanceBtn').onclick = async () => {
  const btn = $('refreshBalanceBtn');
  btn.disabled = true;
  try{
    const d = await api('/api/refresh-balance', {panel_password: $('panelPassword').value});
    log('上游余额已刷新: ' + Number(d.balance).toFixed(2), 'ok');
    toast('上游余额已刷新: ' + Number(d.balance).toFixed(2), 'ok');
    await loadHealth();
  }catch(e){ log('刷新余额失败: ' + e.message, 'err'); toast('刷新余额失败: ' + e.message, 'err'); }
  finally{ btn.disabled = false; }
};
$('saveAccessPwd').onclick = async () => {
  const value = $('accessPassword').value.trim();
  if(!value){ toast('请输入访问密码', 'warn'); return; }
  try{
    await api('/api/config', {access_password: value});
    accessPassword = value;
    $('accessPassword').value = '';
    $('accessHint').textContent = '已启用：所有 API 需要访问密码';
    log('工作台访问密码已启用', 'ok');
    toast('访问密码已启用', 'ok');
  }catch(e){ log('启用访问密码失败: ' + e.message, 'err'); toast('启用失败: ' + e.message, 'err'); }
};
$('clearAccessPwd').onclick = async () => {
  if(!confirm('关闭访问密码后，本机任何程序都能调用工作台 API。继续？')) return;
  try{
    await api('/api/config', {access_password: ''});
    accessPassword = '';
    $('accessHint').textContent = '未启用：仅监听 127.0.0.1';
    log('工作台访问密码已关闭', 'warn');
    toast('访问密码已关闭', 'warn');
  }catch(e){ log('关闭访问密码失败: ' + e.message, 'err'); toast('关闭失败: ' + e.message, 'err'); }
};
$('reloadBtn').onclick = () => location.reload();
async function loadAudit(){
  try{
    const d = await api('/api/audit?limit=40');
    const box = $('auditLog');
    if(!box) return;
    const items = (d.entries || []).slice().reverse();
    box.innerHTML = items.length
      ? items.map(e => '<div class="line info"><span class="t">' + tsOf(e.t) + '</span>' + esc(e.action) + ' · ' + esc(e.detail || '') + '</div>').join('')
      : '<div class="line info">暂无操作记录</div>';
  }catch(e){}
}
$('auditRefresh').onclick = async () => {
  try { await api('/api/audit?limit=1'); await loadAudit(); toast('审计已刷新', 'ok'); }
  catch(e){ toast('审计刷新失败: ' + e.message, 'err'); }
};
async function refreshAllData(){
  try{
    await Promise.all([api('/api/config'), api('/api/health')]);
    await Promise.all([loadHealth(), loadModels(), loadJobs(), loadConfig(), loadAudit(), loadDiskUsage()]);
    if(currentView === 'gallery' && !(await loadGallery())) throw new Error('作品读取失败');
    toast('已刷新状态、任务与模型', 'ok');
    log('全部数据已刷新', 'info');
  }catch(e){ toast('刷新失败: ' + e.message, 'err'); }
}
$('refreshAll').onclick = refreshAllData;
$('healthBtn2').onclick = refreshAllData;
async function ensureSaveDir(){ await persistSaveDir().catch(e => { throw new Error('保存目录不可用: ' + e.message); }); }

// ---------------- 健康 ----------------
async function loadHealth(){
  try{
    const d = await api('/api/health');
    $('chipRealm').textContent = (d.media_realm || d.realm || '-') + (d.media_enabled === false ? '（媒体关）' : '');
    $('chipAccounts').textContent = (d.accounts_ready || 0) + '/' + (d.accounts || 0);
    $('chipCredits').textContent = d.credits == null ? '-' : Number(d.credits).toFixed(1);
    const at = d.credits_updated_at ? new Date(d.credits_updated_at * 1000).toLocaleString('zh-CN', {hour12:false}) : '-';
    const src = d.credits_source === 'gateway' ? '网关快照' : '本地缓存';
    $('chipCreditsWrap').title = '网关余额，已计本机扣费；上游快照时间 ' + at;
    $('hGateway').textContent = d.gateway ? '正常' : ('不可用' + (d.error ? '：' + d.error : ''));
    $('hRealm').textContent = (d.media_realm || d.realm || '-');
    $('hAccounts').textContent = (d.accounts_ready || 0) + ' / ' + (d.accounts || 0);
    $('hMedia').textContent = d.media_enabled ? '已开启' : '未开启';
    $('hModels').textContent = (d.models || 0) + ' 个';
    $('hCredits').textContent = d.credits == null ? '-' : Number(d.credits).toFixed(1);
    $('hCreditsAt').textContent = at + '（' + src + '）';
    $('hVersion').textContent = $('pageVersion').dataset.v;
  }catch(e){ $('chipRealm').textContent = '网关不可用'; }
}

// ---------------- 模型与预设 ----------------
let MEDIA = {models:[], realm:'-', enabled:false};
const IMAGE_PRESETS = [
  {id:'1024x1024', label:'1:1 · 1024×1024'},
  {id:'1280x720', label:'16:9 · 1280×720'},
  {id:'720x1280', label:'9:16 · 720×1280'},
  {id:'1536x1024', label:'3:2 · 1536×1024'},
  {id:'1024x1536', label:'2:3 · 1024×1536'},
  {id:'2048x1152', label:'16:9 2K · 2048×1152'},
  {id:'1152x2048', label:'9:16 2K · 1152×2048'},
  {id:'2048x2048', label:'1:1 2K · 2048×2048'},
  {id:'2048x1536', label:'3:2 2K · 2048×1536'},
  {id:'1536x2048', label:'2:3 2K · 1536×2048'},
  {id:'2560x1440', label:'16:9 QHD · 2560×1440'},
  {id:'1440x2560', label:'9:16 QHD · 1440×2560'},
  {id:'custom', label:'自定义宽高…'}
];
function modelById(id){ return (MEDIA.models || []).find(m => m.id === id) || null; }
function videoModel(){ return modelById($('vidModel').value) || {}; }
function imageModel(){ return modelById($('imgModel').value) || {}; }
function editModel(){ return modelById($('editModel').value) || {}; }

function fillImagePresets(sel){
  sel.innerHTML = IMAGE_PRESETS.map(p => '<option value="' + p.id + '">' + p.label + '</option>').join('');
}
function syncCustom(prefix){
  const custom = $(prefix + 'Preset').value === 'custom';
  $(prefix + 'Custom').classList.toggle('hidden', !custom);
}
function updateSizeHint(prefix){
  const hint = $(prefix + 'SizeHint');
  if(!hint) return;
  try{
    const size = imageSize(prefix);
    const parts = size.split('x').map(Number);
    hint.style.color = 'var(--dim)';
    hint.textContent = size + ' · ' + (parts[0] / parts[1]).toFixed(2) + ':1 · '
      + (parts[0] * parts[1] / 1000000).toFixed(2) + ' MP';
  }catch(e){
    hint.style.color = 'var(--bad)';
    hint.textContent = e.message;
  }
}
function renderFilePreview(inputId, previewId, max){
  const input = $(inputId), box = $(previewId);
  if(!input || !box) return;
  const files = Array.from(input.files || []).slice(0, max || 99);
  box.innerHTML = '';
  if(!files.length){ box.innerHTML = '<span class="hint">未选择文件</span>'; return; }
  files.forEach(f => {
    if(!/^image\//.test(f.type)) return;
    const url = URL.createObjectURL(f);
    const img = document.createElement('img');
    img.src = url;
    img.title = f.name;
    img.onload = () => URL.revokeObjectURL(url);
    img.onerror = () => URL.revokeObjectURL(url);
    box.appendChild(img);
  });
}
function validateImageFiles(files, label, max){
  if(files.length > max) throw new Error(label + '最多 ' + max + ' 张');
  let total = 0;
  for(const f of files){
    if(!/^image\//.test(f.type)) throw new Error(label + '必须是图片');
    if(f.size > 8 * 1024 * 1024) throw new Error(label + '单张不能超过 8MB');
    total += f.size;
  }
  if(total > 16 * 1024 * 1024) throw new Error(label + '总大小不能超过 16MB');
}
const FORM_KEY = 'wbStudioForm';
function saveFormState(){
  const ids = ['imgModel','imgPreset','imgW','imgH','editModel','editPreset','editW','editH',
               'vidModel','vidSeconds','vidResolution','vidAspect','vidNegative'];
  const data = {};
  ids.forEach(id => { const el = $(id); if(el) data[id] = el.value; });
  data.vidAudio = $('vidAudio') ? $('vidAudio').checked : true;
  try { localStorage.setItem(FORM_KEY, JSON.stringify(data)); } catch(e){}
}
function restoreFormState(){
  let data = {};
  try { data = JSON.parse(localStorage.getItem(FORM_KEY) || '{}'); } catch(e){ return; }
  if(!data || typeof data !== 'object' || Array.isArray(data)) return;
  const set = (id, value) => {
    const el = $(id);
    if(!el || value === undefined || value === null || value === '') return;
    if(el.tagName === 'SELECT' && ![...el.options].some(o => o.value === String(value))) return;
    el.value = value;
  };
  set('imgModel', data.imgModel);
  set('imgPreset', data.imgPreset);
  set('imgW', data.imgW);
  set('imgH', data.imgH);
  set('editModel', data.editModel);
  set('editPreset', data.editPreset);
  set('editW', data.editW);
  set('editH', data.editH);
  set('vidModel', data.vidModel);
  refreshVideoOptions();
  set('vidSeconds', data.vidSeconds);
  set('vidResolution', data.vidResolution);
  set('vidAspect', data.vidAspect);
  set('vidNegative', data.vidNegative);
  if(data.vidAudio !== undefined && !$('vidAudio').disabled) $('vidAudio').checked = !!data.vidAudio;
  syncCustom('img'); syncCustom('edit');
  updateSizeHint('img'); updateSizeHint('edit');
  updateImageCost(); updateEditCost(); updateVideoCaps();
}
['imgModel','imgPreset','imgW','imgH','editModel','editPreset','editW','editH',
 'vidModel','vidSeconds','vidResolution','vidAspect','vidNegative','vidAudio'].forEach(id => {
  const el = $(id);
  if(el && !el.dataset.persistBound){
    el.dataset.persistBound = '1';
    const persist = () => setTimeout(saveFormState, 0);
    el.addEventListener('change', persist);
    el.addEventListener('input', persist);
  }
});
$('imgPreset').addEventListener('change', () => updateSizeHint('img'));
$('editPreset').addEventListener('change', () => updateSizeHint('edit'));
$('imgW').addEventListener('input', () => updateSizeHint('img'));
$('imgH').addEventListener('input', () => updateSizeHint('img'));
$('editW').addEventListener('input', () => updateSizeHint('edit'));
$('editH').addEventListener('input', () => updateSizeHint('edit'));
$('editFiles').addEventListener('change', () => renderFilePreview('editFiles', 'editFilePreview', 8));
$('vidFirst').addEventListener('change', () => renderFilePreview('vidFirst', 'vidFirstPreview', 1));
$('vidLast').addEventListener('change', () => renderFilePreview('vidLast', 'vidLastPreview', 1));
$('vidRefs').addEventListener('change', () => renderFilePreview('vidRefs', 'vidRefsPreview', 9));
function imageSize(prefix){
  if($(prefix + 'Preset').value !== 'custom') return $(prefix + 'Preset').value;
  const w = parseInt($(prefix + 'W').value, 10), h = parseInt($(prefix + 'H').value, 10);
  if(!w || !h || w < 64 || h < 64) throw new Error('宽高至少 64');
  if(w % 16 || h % 16) throw new Error('宽高需为 16 的倍数');
  if(w * h > 4194304) throw new Error('总像素超过 4.19 MP（例如 2048×2048 已到上限）');
  return w + 'x' + h;
}
function updateImageCost(){
  const m = imageModel();
  const per = m.creditPerImage != null ? m.creditPerImage : 5.77;
  $('imgCost').textContent = '预估 ' + per + ' 积分/张' + ($('imgBatch').checked ? '（批量按行数累加）' : '');
  $('imgCaps').textContent = '文生图 · 总像素上限 4.19 MP';
}
function updateEditCost(){
  const m = editModel();
  const per = m.creditPerImage != null ? m.creditPerImage : 6;
  $('editCost').textContent = '预估 ' + per + ' 积分/张';
  $('editCaps').textContent = '改图 · 支持多张参考图';
}
function updateVideoCaps(){
  const m = videoModel(); const g = m.videoGeneration || {};
  const res = (g.resolutions || []).join(' / ') || '-';
  const ratio = (g.aspectRatios || []).join(' / ') || '-';
  const audio = g.audioMode === 'always-on' ? '音频常开' : (g.audioMode === 'switchable' ? '音频可开关' : '无音频设置');
  $('vidCaps').textContent = '时长 ' + (g.minSeconds ?? '-') + '–' + (g.maxSeconds ?? '-') + ' 秒 · ' + res + ' · ' + ratio + ' · ' + audio;
  const per = m.creditPerSecond != null ? m.creditPerSecond : (m.creditPerSecondCeiling != null ? m.creditPerSecondCeiling : 26);
  const sec = parseInt($('vidSeconds').value || '5', 10);
  $('vidCost').textContent = '预估 ' + (per * sec).toFixed(1) + ' 积分（按 ' + per + ' 积分/秒估算，实际以扣费为准）';
  const refMax = g.maxReferenceImages || 0;
  $('vidRefWrap').classList.toggle('hidden', refMax <= 0);
  $('vidRefs').dataset.max = String(refMax);
  const supportsLast = g.supportsFirstLastFrame !== false;
  $('vidLast').parentElement.classList.toggle('hidden', !supportsLast);
  if(refMax <= 0 && $('vidRefs').files.length){
    $('vidRefs').value = '';
    renderFilePreview('vidRefs', 'vidRefsPreview', 9);
  }
  if(!supportsLast && $('vidLast').files.length){
    $('vidLast').value = '';
    renderFilePreview('vidLast', 'vidLastPreview', 1);
  }
}
function refreshVideoOptions(){
  const m = videoModel(); const g = m.videoGeneration || {};
  const keepRes = $('vidResolution').value, keepAspect = $('vidAspect').value, keepSec = $('vidSeconds').value;
  const resList = Array.isArray(g.resolutions) ? g.resolutions : [];
  $('vidResolution').innerHTML = resList.map(r => '<option>' + esc(r) + '</option>').join('') || '<option>720P</option>';
  if(resList.includes(keepRes)) $('vidResolution').value = keepRes;
  else if(g.defaultResolution && resList.includes(g.defaultResolution)) $('vidResolution').value = g.defaultResolution;
  const aspectList = Array.isArray(g.aspectRatios) && g.aspectRatios.length ? g.aspectRatios : ['16:9','9:16','1:1'];
  $('vidAspect').innerHTML = aspectList.map(r => '<option>' + esc(r) + '</option>').join('');
  if(aspectList.includes(keepAspect)) $('vidAspect').value = keepAspect;
  else if(g.defaultAspectRatio && aspectList.includes(g.defaultAspectRatio)) $('vidAspect').value = g.defaultAspectRatio;
  const lo = Math.max(1, Math.min(60, parseInt(g.minSeconds || 3, 10) || 3));
  const hi = Math.max(lo, Math.min(60, parseInt(g.maxSeconds || 15, 10) || 15));
  let opts = '';
  for(let s = lo; s <= hi; s++) opts += '<option value="' + s + '">' + s + ' 秒</option>';
  $('vidSeconds').innerHTML = opts;
  const want = parseInt(keepSec, 10);
  if(want >= lo && want <= hi) $('vidSeconds').value = String(want);
  else $('vidSeconds').value = String(g.defaultSeconds || lo);
  if(g.audioMode === 'always-on'){
    $('vidAudio').checked = true; $('vidAudio').disabled = true;
    $('vidAudioHint').textContent = '该模型音频常开，无法关闭';
  }else{
    $('vidAudio').disabled = false;
    $('vidAudio').checked = g.defaultEnableAudio !== false;
    $('vidAudioHint').textContent = g.audioMode === 'switchable' ? '' : '该模型未声明音频开关';
  }
  updateVideoCaps();
}
async function loadModels(){
  try{
    const d = await api('/api/models');
    MEDIA = d;
    $('chipRealm').textContent = d.realm + (d.enabled ? '' : '（媒体关）');
    const all = Array.isArray(d.models) ? d.models : [];
    const fill = (sel, tag, fallback) => {
      const list = all.filter(m => (m.tags || []).includes(tag));
      sel.innerHTML = (list.length ? list : all).map(m => '<option>' + esc(m.id) + '</option>').join('');
      if(!list.length) sel.innerHTML = '<option>' + esc(fallback) + '</option>';
    };
    fill($('imgModel'), 'text-to-image', 'hunyuan-image-alpha');
    fill($('editModel'), 'image-to-image', 'hunyuan-image-alpha-edit');
    fill($('vidModel'), 'text-to-video', 'kling-video-v3');
    fillImagePresets($('imgPreset'));
    fillImagePresets($('editPreset'));
    const count = tag => all.filter(m => (m.tags || []).includes(tag)).length;
    setCount('countImage', count('text-to-image'), '模型');
    setCount('countEdit', count('image-to-image'), '模型');
    setCount('countVideo', count('text-to-video'), '模型');
    $('imgModel').onchange = updateImageCost;
    $('editModel').onchange = updateEditCost;
    $('vidModel').onchange = refreshVideoOptions;
    $('imgBatch').onchange = updateImageCost;
    refreshVideoOptions();
    updateImageCost(); updateEditCost();
    restoreFormState();
    updateSizeHint('img'); updateSizeHint('edit');
    log('模型目录：图 ' + count('text-to-image') + ' / 改图 ' + count('image-to-image')
        + ' / 视频 ' + count('text-to-video'), 'info');
  }catch(e){
    $('chipRealm').textContent = '读取失败';
    log('读取模型目录失败: ' + e.message, 'err');
  }
}
$('imgPreset').onchange = () => syncCustom('img');
$('editPreset').onchange = () => syncCustom('edit');
$('vidSeconds').onchange = updateVideoCaps;
$('vidResolution').onchange = updateVideoCaps;

// ---------------- 任务 ----------------
let JOBS = [], jobFilter = 'all', jobTypeFilter = 'all', jobModelFilter = 'all', jobDateFilter = 'all', jobSearch = '', lastJobsSig = '';
let jobPage = 1, PAGE_SIZE = 20, selectedJobId = '';
function jobElapsed(job){
  const end = job.completed_at || (isActive(job.status) ? Date.now()/1000 : job.updated_at) || Date.now()/1000;
  return fmtElapsed(end - job.created_at);
}
function jobProgressPct(job){
  if(job.status === 'completed' || ['failed','rejected','cancelled','lost'].includes(job.status)) return 100;
  if(job.type === 'image') return isActive(job.status) ? 55 : 15;
  const base = {queued:10, waiting:15, submitting:25, running:55, in_progress:55, processing:55, saving:85}[job.status] ?? 10;
  const elapsed = Date.now()/1000 - job.created_at;
  return Math.min(90, base + Math.max(0, elapsed - 5) * 0.6);
}
function jobMatches(job){
  if(jobTypeFilter !== 'all' && job.type !== jobTypeFilter) return false;
  if(jobModelFilter !== 'all' && job.model !== jobModelFilter) return false;
  if(jobDateFilter !== 'all'){
    const now = Date.now() / 1000;
    let cutoff;
    if(jobDateFilter === 'today'){
      const d = new Date(); d.setHours(0,0,0,0); cutoff = d.getTime() / 1000;
    }else{
      cutoff = now - 7 * 86400;
    }
    if((job.created_at || 0) < cutoff) return false;
  }
  if(jobFilter === 'active' && !isActive(job.status)) return false;
  if(jobFilter === 'completed' && job.status !== 'completed') return false;
  if(jobFilter === 'failed' && !['failed','rejected','cancelled','lost'].includes(job.status)) return false;
  if(jobSearch){
    const hay = [job.prompt, job.model, job.task_id, job.id, job.filename].join(' ').toLowerCase();
    if(!hay.includes(jobSearch.toLowerCase())) return false;
  }
  return true;
}
function fmtTime(ts, short){
  if(!ts) return '-';
  const d = new Date(ts * 1000);
  return short ? d.toLocaleTimeString('zh-CN', {hour12:false}) : d.toLocaleString('zh-CN', {hour12:false});
}
function jobParams(job){
  const req = job.request || {};
  if(job.type === 'video'){
    const bits = [];
    if(req.seconds) bits.push(req.seconds + ' 秒');
    if(req.resolution) bits.push(req.resolution);
    if(req.aspect_ratio) bits.push(req.aspect_ratio);
    if(req.has_image) bits.push('首帧');
    if(req.has_last) bits.push('尾帧');
    if(req.ref_count) bits.push('参考图 ' + req.ref_count);
    if(req.negative_prompt) bits.push('含负向提示');
    return bits.join(' · ') || '-';
  }
  if(req.size) return req.size + (req.kind === 'edit' ? ' · 改图' : ' · 文生图');
  return '-';
}
function jobActionButtons(job){
  const active = isActive(job.status);
  const actions = [];
  if(active && job.type === 'video' && job.task_id && job.status === 'queued') actions.push('<button data-act="cancel" data-task="' + esc(job.task_id) + '">取消</button>');
  actions.push('<button data-act="reuse" data-job="' + esc(job.id) + '">复用参数</button>');
  if(job.filename) actions.push('<button data-act="reveal" data-file="' + esc(job.filename) + '" data-path="' + esc(job.path || '') + '">打开文件夹</button>');
  if(!active && !job.filename && ((job.type === 'video' && job.task_id) || (job.type === 'image' && job.source_url))) actions.push('<button data-act="resave" data-job="' + esc(job.id) + '">重试保存</button>');
  if(job.task_id) actions.push('<button data-act="copy" data-text="' + esc(job.task_id) + '">复制 ID</button>');
  if(!active) actions.push('<button data-act="delete" data-job="' + esc(job.id) + '">删除记录</button>');
  return actions.join('');
}
function quickActions(job){
  const active = isActive(job.status);
  const actions = [];
  if(active && job.type === 'video' && job.task_id && job.status === 'queued') actions.push('<button data-act="cancel" data-task="' + esc(job.task_id) + '">取消</button>');
  actions.push('<button data-act="reuse" data-job="' + esc(job.id) + '">复用</button>');
  if(job.filename) actions.push('<button data-act="reveal" data-file="' + esc(job.filename) + '" data-path="' + esc(job.path || '') + '">打开</button>');
  return actions.join('');
}
function taskRow(job){
  const open = selectedJobId === job.id;
  const cls = statusClass(job.status);
  const active = isActive(job.status);
  const pct = jobProgressPct(job).toFixed(0);
  let status = '<span class="badge ' + cls + '">' + esc(statusLabel(job.status)) + '</span>';
  if(active){
    status += '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%"></div></div>'
      + '<span class="pct">' + pct + '%</span>';
  }else if(job.status === 'completed' && job.filename){
    status += '<div class="hint">文件已保存</div>';
  }else if(job.error){
    status += '<div class="hint" style="color:var(--bad)">' + esc(String(job.error).slice(0, 36)) + '</div>';
  }
  return '<div class="task-item' + (open ? ' open' : '') + '" data-job="' + esc(job.id) + '">'
    + '<div class="task-row-grid">'
    + '<div class="col-type"><span class="badge">' + (job.type === 'video' ? '视频' : '图片') + '</span></div>'
    + '<div class="col-task"><div class="job-title">' + esc(job.model) + '</div>'
    + '<div class="prompt">' + esc(job.prompt || '（无 prompt）') + '</div></div>'
    + '<div class="col-status">' + status + '</div>'
    + '<div class="col-elapsed">' + jobElapsed(job) + '</div>'
    + '<div class="col-credit">' + esc(job.credit != null ? job.credit : '-') + '</div>'
    + '<div class="col-actions">' + quickActions(job) + '</div>'
    + '</div>'
    + (open ? '<div class="task-detail">' + taskDetailHtml(job) + '</div>' : '')
    + '</div>';
}
function taskDetailHtml(job){
  if(!job) return '<div class="meta">选择任务查看详情</div>';
  const active = isActive(job.status);
  const pct = jobProgressPct(job).toFixed(0);
  const fileUrl = esc(job.file_url || '');
  const fileLink = job.filename && job.file_url
    ? '<a href="' + fileUrl + '" target="_blank">' + esc(job.filename) + '</a>'
    : (job.filename ? esc(job.filename) : '-');
  const times = fmtTime(job.created_at) + (job.completed_at ? ' → ' + fmtTime(job.completed_at) : '');
  let preview = '';
  if(job.filename && job.file_url){
    const src = fileUrl;
    preview = job.type === 'video'
      ? '<div class="task-preview"><video controls preload="metadata" src="' + src + '"></video></div>'
      : '<div class="task-preview"><img loading="lazy" src="' + src + '" alt="preview"></div>';
  }
  return '<div class="job-prompt-full">' + esc(job.prompt || '（无 prompt）') + '</div>'
    + (active ? '<div class="bar-track" style="margin-top:10px"><div class="bar-fill" style="width:' + pct + '%"></div></div><div class="progress-text">阶段进度 ' + pct + '%（上游不提供精确百分比）</div>' : '')
    + '<div class="kv">'
    + '<div class="k">任务 ID</div><div class="v">' + esc(job.task_id || job.id) + '</div>'
    + '<div class="k">创建 / 完成</div><div class="v">' + times + '</div>'
    + '<div class="k">参数</div><div class="v">' + esc(jobParams(job)) + '</div>'
    + '<div class="k">保存位置</div><div class="v">' + (job.path ? esc(job.path) : '未保存') + '</div>'
    + '<div class="k">文件</div><div class="v">' + fileLink + '</div>'
    + (job.error ? '<div class="k">错误</div><div class="v" style="color:var(--bad)">' + esc(job.error) + '</div>' : '')
    + (job.save_error ? '<div class="k">保存错误</div><div class="v" style="color:var(--bad)">' + esc(job.save_error) + '</div>' : '')
    + '</div>'
    + preview
    + '<div class="job-actions">' + jobActionButtons(job) + '</div>';
}
function updateStats(){
  const today = new Date(); today.setHours(0,0,0,0);
  const todayJobs = JOBS.filter(j => (j.created_at || 0) >= today.getTime()/1000);
  const todayCredits = todayJobs.reduce((sum, j) => sum + (typeof j.credit === 'number' ? j.credit : 0), 0);
  const totalCredits = JOBS.reduce((sum, j) => sum + (typeof j.credit === 'number' ? j.credit : 0), 0);
  $('jobsStats').textContent = '共 ' + JOBS.length + ' 条 · 今日 ' + todayJobs.length + ' 条 / ' + todayCredits.toFixed(1)
    + ' 积分 · 累计 ' + totalCredits.toFixed(1) + ' 积分 · 进行中 ' + JOBS.filter(j => isActive(j.status)).length;
  setCount('countJobs', JOBS.length, '任务');
}
function refreshJobModelOptions(){
  const sel = $('jobModelFilter');
  if(!sel) return;
  const current = sel.value;
  const models = [...new Set(JOBS.map(j => j.model).filter(Boolean))].sort();
  sel.innerHTML = '<option value="all">全部模型</option>'
    + models.map(m => '<option>' + esc(m) + '</option>').join('');
  if(current !== 'all' && models.includes(current)) sel.value = current;
  else { sel.value = 'all'; jobModelFilter = 'all'; }
}
function renderTaskList(){
  const all = JOBS.filter(jobMatches);
  const pages = Math.max(1, Math.ceil(all.length / PAGE_SIZE));
  if(jobPage > pages) jobPage = pages;
  const start = (jobPage - 1) * PAGE_SIZE;
  const pageJobs = all.slice(start, start + PAGE_SIZE);
  if(selectedJobId && !pageJobs.some(j => j.id === selectedJobId)) selectedJobId = '';
  const box = $('jobsList');
  box.innerHTML = pageJobs.length
    ? pageJobs.map(taskRow).join('')
    : '<div class="task-empty">暂无任务，去「文生图 / 改图 / 文生视频」生成第一条；也可以点右上角「同步历史」导入网关里已有的任务。</div>';
  $('jobsPage').textContent = jobPage + ' / ' + pages + '（' + all.length + ' 条）';
  $('jobsPrev').disabled = jobPage <= 1;
  $('jobsNext').disabled = jobPage >= pages;
}
function renderJobs(){
  renderTaskList();
}
function refreshActiveProgress(){
  const byId = new Map(JOBS.map(j => [j.id, j]));
  document.querySelectorAll('#jobsList .task-item[data-job]').forEach(item => {
    const job = byId.get(item.dataset.job);
    if(!job || !isActive(job.status)) return;
    const pct = jobProgressPct(job).toFixed(0);
    const fill = item.querySelector('.bar-fill');
    const pctEl = item.querySelector('.pct');
    const elapsed = item.querySelector('.col-elapsed');
    if(fill) fill.style.width = pct + '%';
    if(pctEl) pctEl.textContent = pct + '%';
    if(elapsed) elapsed.textContent = jobElapsed(job);
  });
}
async function loadJobs(){
  try{
    const d = await api('/api/jobs');
    JOBS = Array.isArray(d.jobs) ? d.jobs : [];
    const sig = JOBS.map(j => [j.id, j.status, j.updated_at, j.filename, j.credit].join(':')).join('|');
    const changed = sig !== lastJobsSig;
    const hasActive = JOBS.some(j => isActive(j.status));
    if(changed){
      lastJobsSig = sig;
      refreshJobModelOptions();
      renderJobs();
    }else if(hasActive){
      refreshActiveProgress();
    }
    updateStats();
    if(changed) loadHealth();
  }catch(e){}
}
$('jobsSearch').addEventListener('input', () => { jobSearch = $('jobsSearch').value.trim(); jobPage = 1; renderJobs(); });
$('jobFilters').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-filter]'); if(!btn) return;
  jobFilter = btn.dataset.filter;
  document.querySelectorAll('#jobFilters button').forEach(b => b.classList.toggle('on', b === btn));
  jobPage = 1;
  renderJobs();
});
$('jobTypeFilters').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-type]'); if(!btn) return;
  jobTypeFilter = btn.dataset.type;
  document.querySelectorAll('#jobTypeFilters button').forEach(b => b.classList.toggle('on', b === btn));
  jobPage = 1;
  renderJobs();
});
$('jobModelFilter').addEventListener('change', () => {
  jobModelFilter = $('jobModelFilter').value;
  jobPage = 1;
  renderJobs();
});
$('jobDateFilter').addEventListener('change', () => {
  jobDateFilter = $('jobDateFilter').value;
  jobPage = 1;
  renderJobs();
});
$('jobsPrev').onclick = () => { if(jobPage > 1){ jobPage--; renderJobs(); } };
$('jobsNext').onclick = () => { jobPage++; renderJobs(); };
$('jobsList').addEventListener('click', async ev => {
  const btn = ev.target.closest('button[data-act]');
  if(btn){
    const act = btn.dataset.act;
    try{
      if(act === 'cancel'){
        await api('/api/video/' + encodeURIComponent(btn.dataset.task) + '/cancel', {});
        log('已请求取消任务 ' + btn.dataset.task, 'warn');
        toast('已请求取消任务', 'warn');
        loadJobs();
      }else if(act === 'reuse'){
        const job = JOBS.find(j => j.id === btn.dataset.job);
        if(job) reuseJob(job);
      }else if(act === 'reveal'){
        await api('/api/reveal', {filename: btn.dataset.file, path: btn.dataset.path || ''});
        toast('已打开文件夹', 'ok');
      }else if(act === 'resave'){
        const d = await api('/api/job/' + encodeURIComponent(btn.dataset.job) + '/save', {});
        log('重新保存成功: ' + (d.filename || ''), 'ok');
        toast('重新保存成功', 'ok');
        loadJobs();
      }else if(act === 'copy'){
        await navigator.clipboard.writeText(btn.dataset.text || '');
        log('已复制: ' + btn.dataset.text, 'info');
        toast('已复制任务 ID', 'ok');
      }else if(act === 'delete'){
        if(!confirm('删除这条任务记录？（不会删除本地文件）')) return;
        await api('/api/jobs/delete', {id: btn.dataset.job});
        if(selectedJobId === btn.dataset.job) selectedJobId = '';
        log('已删除任务记录', 'info');
        toast('已删除任务记录', 'ok');
        loadJobs();
      }
    }catch(e){ log('操作失败: ' + e.message, 'err'); toast('操作失败: ' + e.message, 'err'); }
    return;
  }
  const grid = ev.target.closest('.task-row-grid');
  if(!grid) return;
  const item = grid.closest('.task-item');
  selectedJobId = selectedJobId === item.dataset.job ? '' : item.dataset.job;
  renderJobs();
});
$('jobsClear').onclick = async () => {
  if(!confirm('清除所有已完成 / 失败的记录？活动任务会保留。')) return;
  const deleteFiles = confirm('是否同时删除保存目录里这些任务的图片/视频文件？\n确定 = 删除文件，取消 = 只删记录');
  try{
    await api('/api/jobs/clear', {delete_files: deleteFiles});
    log('已清除完成的任务' + (deleteFiles ? '（含本地文件）' : ''), 'info');
    toast('已清除完成的任务', 'ok');
    loadJobs();
  }catch(e){ log('清除失败: ' + e.message, 'err'); toast('清除失败: ' + e.message, 'err'); }
};
$('jobsSync').onclick = async () => {
  const btn = $('jobsSync');
  btn.disabled = true;
  btn.textContent = '同步中…';
  try{
    const d = await api('/api/sync-history', {});
    log('同步网关历史：新增 ' + d.added + ' 条', 'ok');
    toast('同步网关历史：新增 ' + d.added + ' 条', 'ok');
    loadJobs();
  }catch(e){ log('同步历史失败: ' + e.message, 'err'); toast('同步历史失败: ' + e.message, 'err'); }
  finally{ btn.disabled = false; btn.textContent = '同步历史'; }
};
function reuseJob(job){
  const r = job.request || {};
  if(r.kind === 'video' || job.type === 'video'){
    showView('video');
    if(r.model) $('vidModel').value = r.model;
    refreshVideoOptions();
    $('vidPrompt').value = job.prompt || r.prompt || '';
    if(r.seconds) $('vidSeconds').value = String(r.seconds);
    if(r.resolution) $('vidResolution').value = r.resolution;
    if(r.aspect_ratio) $('vidAspect').value = r.aspect_ratio;
    $('vidNegative').value = r.negative_prompt || '';
    log('已填入视频参数；首帧/尾帧/参考图需要重新选择', 'info');
  }else if(r.kind === 'edit' || job.model.indexOf('edit') >= 0){
    showView('edit');
    if(r.model) $('editModel').value = r.model;
    $('editPrompt').value = job.prompt || r.prompt || '';
    if(r.size) setImageSize('edit', r.size);
    log('已填入改图参数；原图需要重新选择', 'info');
  }else{
    showView('image');
    if(r.model) $('imgModel').value = r.model;
    $('imgPrompt').value = job.prompt || r.prompt || '';
    if(r.size) setImageSize('img', r.size);
    updateImageCost();
    log('已填入生图参数', 'info');
  }
}
function setImageSize(prefix, size){
  const preset = IMAGE_PRESETS.find(p => p.id === size);
  if(preset){
    $(prefix + 'Preset').value = size;
  }else{
    $(prefix + 'Preset').value = 'custom';
    const parts = String(size).split('x');
    $(prefix + 'W').value = parts[0] || 1024;
    $(prefix + 'H').value = parts[1] || 1024;
  }
  syncCustom(prefix);
}

// ---------------- 提示词标签 ----------------
const tagState = {tags:[], categories:[], filter:'全部', search:'', editing:'', target:'imgPrompt'};
const TAG_TARGET_LABEL = {imgPrompt:'生图 prompt', editPrompt:'改图 prompt', vidPrompt:'视频 prompt'};
function openTagDrawer(target){
  tagState.target = target || tagState.target;
  $('tagTargetHint').textContent = '插入到：' + (TAG_TARGET_LABEL[tagState.target] || tagState.target);
  $('tagDrawer').classList.add('on');
  $('tagOverlay').classList.remove('hidden');
  const el = $(tagState.target);
  if(el){
    const sel = String(el.value).slice(el.selectionStart || 0, el.selectionEnd || 0).trim();
    if(sel && sel.length <= 500 && !$('tagText').value.trim()) $('tagText').value = sel;
  }
  loadTags();
}
function closeTagDrawer(){
  if(tagState.editing) cancelTagEdit();
  $('tagDrawer').classList.remove('on');
  $('tagOverlay').classList.add('hidden');
}
function renderTagCats(){
  const cats = ['全部'].concat(tagState.categories);
  if(!cats.includes(tagState.filter)) tagState.filter = '全部';
  $('tagCats').innerHTML = cats.map(c =>
    '<button class="' + (tagState.filter === c ? 'on' : '') + '" data-tagcat="' + esc(c) + '">' + esc(c) + '</button>').join('');
  $('tagCatList').innerHTML = tagState.categories.map(c => '<option value="' + esc(c) + '">').join('');
  $('tagCategoryList').innerHTML = tagState.categories.length
    ? tagState.categories.map(c =>
        '<div class="queue-item"><span class="qtext">' + esc(c) + '</span>'
        + '<button data-catact="rename" data-cat="' + esc(c) + '">重命名</button>'
        + '<button data-catact="delete" data-cat="' + esc(c) + '">删除</button></div>').join('')
    : '<div class="hint">还没有分类，保存标签时会自动创建</div>';
}
function renderTagList(){
  const q = tagState.search.toLowerCase();
  const list = tagState.tags.filter(t => {
    if(tagState.filter !== '全部' && t.category !== tagState.filter) return false;
    if(q && !((t.text || '') + ' ' + (t.category || '')).toLowerCase().includes(q)) return false;
    return true;
  });
  const box = $('tagList');
  if(!list.length){
    box.innerHTML = '<div class="tag-empty">没有标签。上面输入内容并保存，就会出现在这里。</div>';
    return;
  }
  box.innerHTML = list.map(t =>
    '<div class="tag-item" data-tagid="' + esc(t.id) + '">'
    + '<div class="tag-text"><label style="display:flex;gap:6px;align-items:flex-start;cursor:pointer">'
    + '<input type="checkbox" class="tag-pick" data-tagid="' + esc(t.id) + '" style="margin-top:3px">'
    + '<span>' + esc(t.text) + '</span></label></div>'
    + '<div class="tag-meta"><span class="tag-cat">' + esc(t.category || '未分类')
    + (t.uses ? ' · ' + esc(t.uses) + ' 次' : '') + '</span>'
    + '<span class="tag-acts"><button data-tagact="insert">插入</button><button data-tagact="edit">编辑</button><button data-tagact="delete">删除</button></span></div>'
    + '</div>').join('');
}
async function loadTags(){
  try{
    const d = await api('/api/tags');
    tagState.tags = Array.isArray(d.tags) ? d.tags : [];
    tagState.categories = Array.isArray(d.categories) ? d.categories : [];
    renderTagCats();
    renderTagList();
  }catch(e){
    $('tagList').innerHTML = '<div class="tag-empty">读取标签失败: ' + esc(e.message) + '</div>';
  }
}
function insertTagText(text, tagId){
  const el = $(tagState.target);
  if(!el) return;
  const start = el.selectionStart != null ? el.selectionStart : el.value.length;
  const end = el.selectionEnd != null ? el.selectionEnd : start;
  const before = el.value.slice(0, start);
  const after = el.value.slice(end);
  let sep = '';
  if(before && !/[，,。；;\s]$/.test(before)) sep = '，';
  const inserted = sep + text;
  el.value = before + inserted + after;
  const pos = (before + inserted).length;
  el.focus();
  el.setSelectionRange(pos, pos);
  if(tagId){
    const tag = tagState.tags.find(t => t.id === tagId);
    if(tag) tag.uses = (tag.uses || 0) + 1;
    api('/api/tags/use', {id: tagId}).catch(() => {});
    renderTagList();
  }
  if(tagState.target === 'imgPrompt') updateImageCost();
  log('插入标签：' + text.slice(0, 40), 'info');
  toast('已插入标签', 'ok');
}
async function saveTag(){
  const text = $('tagText').value.trim();
  const category = $('tagCategory').value.trim() || '未分类';
  if(!text){ log('标签内容不能为空', 'warn'); return; }
  try{
    await api('/api/tags', {id: tagState.editing, text, category});
    log((tagState.editing ? '标签已更新：' : '标签已保存：') + text.slice(0, 40), 'ok');
    cancelTagEdit();
    loadTags();
  }catch(e){ log('保存标签失败: ' + e.message, 'err'); }
}
function editTag(tag){
  tagState.editing = tag.id;
  $('tagText').value = tag.text || '';
  $('tagCategory').value = tag.category || '未分类';
  $('tagSave').textContent = '更新标签';
  $('tagText').focus();
}
function cancelTagEdit(){
  tagState.editing = '';
  $('tagSave').textContent = '保存标签';
  $('tagText').value = '';
  $('tagCategory').value = '';
}
document.querySelectorAll('.tag-open').forEach(btn => btn.onclick = () => openTagDrawer(btn.dataset.target));
$('tagClose').onclick = closeTagDrawer;
$('tagOverlay').onclick = closeTagDrawer;
$('tagSearch').addEventListener('input', () => { tagState.search = $('tagSearch').value.trim(); renderTagList(); });
$('tagCats').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-tagcat]'); if(!btn) return;
  tagState.filter = btn.dataset.tagcat;
  renderTagCats();
  renderTagList();
});
$('tagList').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-tagact]');
  if(!btn) return;
  const item = btn.closest('.tag-item');
  const tag = tagState.tags.find(t => t.id === item.dataset.tagid);
  if(!tag) return;
  if(btn.dataset.tagact === 'insert') insertTagText(tag.text, tag.id);
  else if(btn.dataset.tagact === 'edit') editTag(tag);
  else if(btn.dataset.tagact === 'delete'){
    if(confirm('删除标签「' + tag.text.slice(0, 40) + '」？')){
      api('/api/tags/delete', {id: tag.id})
        .then(() => { log('标签已删除', 'info'); loadTags(); })
        .catch(e => log('删除标签失败: ' + e.message, 'err'));
    }
  }
});
$('tagSave').onclick = saveTag;
$('tagCancelEdit').onclick = cancelTagEdit;
$('tagManageToggle').onclick = () => $('tagManage').classList.toggle('hidden');
async function tagCategoryAction(action, name, newName){
  try{
    const payload = {action, name};
    if(newName !== undefined) payload.new_name = newName;
    const d = await api('/api/tag-categories', payload);
    await loadTags();
    toast('分类已更新', 'ok');
  }catch(e){ toast('分类操作失败: ' + e.message, 'err'); log('分类操作失败: ' + e.message, 'err'); }
}
$('addTagCategory').onclick = async () => {
  const name = $('newTagCategory').value.trim();
  if(!name){ toast('请输入分类名', 'warn'); return; }
  await tagCategoryAction('add', name);
  $('newTagCategory').value = '';
};
$('tagCategoryList').addEventListener('click', async ev => {
  const btn = ev.target.closest('button[data-catact]');
  if(!btn) return;
  const name = btn.dataset.cat;
  if(btn.dataset.catact === 'rename'){
    const newName = window.prompt('把分类「' + name + '」重命名为：', name);
    if(newName && newName.trim() && newName.trim() !== name){
      await tagCategoryAction('rename', name, newName.trim());
    }
  }else if(btn.dataset.catact === 'delete'){
    if(confirm('删除分类「' + name + '」？该分类下的标签会移动到「未分类」。')){
      await tagCategoryAction('delete', name);
    }
  }
});
$('tagInsertSelected').onclick = () => {
  const ids = [...document.querySelectorAll('#tagList .tag-pick:checked')].map(cb => cb.dataset.tagid);
  if(!ids.length){ toast('请先勾选标签', 'warn'); return; }
  const tags = ids.map(id => tagState.tags.find(t => t.id === id)).filter(Boolean);
  if(!tags.length) return;
  insertTagText(tags.map(t => t.text).join('，'), '');
  tags.forEach(t => {
    t.uses = (t.uses || 0) + 1;
    api('/api/tags/use', {id: t.id}).catch(() => {});
  });
  renderTagList();
};
$('tagUseSelection').onclick = () => {
  const el = $(tagState.target);
  if(!el) return;
  const sel = String(el.value).slice(el.selectionStart || 0, el.selectionEnd || 0).trim();
  if(!sel){ log('请先在 prompt 里选中一段文字', 'warn'); return; }
  $('tagText').value = sel;
  $('tagText').focus();
};
document.addEventListener('keydown', ev => {
  if(ev.key !== 'Escape') return;
  if(!$('videoModal').classList.contains('hidden')){ closeVideoPlayer(); return; }
  if($('lightbox').classList.contains('on')){ $('lightbox').classList.remove('on'); return; }
  if($('tagDrawer').classList.contains('on')) closeTagDrawer();
});

// ---------------- 批量队列 ----------------
let imgQueue = [], vidQueue = [], imgQueueRunning = false, vidQueueRunning = false;
let imgStopRequested = false, vidStopRequested = false;
function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }
function moderationError(msg){ return /sensitive|risk control|1026|1027|11140|11-128/i.test(String(msg || '')); }
function queueLabel(st){
  return {pending:'待生成', running:'生成中', completed:'完成', failed:'失败',
          skipped:'已跳过', submitting:'提交中', submitted:'已提交'}[st] || st;
}
function queueBadgeClass(st){
  return st === 'completed' ? 'ok' : st === 'failed' ? 'bad' : (st === 'running' || st === 'submitting') ? 'run' : '';
}
function renderImgQueue(){
  const box = $('imgQueueList');
  if(!imgQueue.length){ box.innerHTML = '<div class="hint">队列为空，点「从文本框导入」生成条目</div>'; }
  else box.innerHTML = imgQueue.map((item, i) =>
    '<div class="queue-item"><span class="idx">' + (i + 1) + '</span>'
    + '<span class="qtext">' + esc(item.text) + '</span>'
    + '<span class="badge ' + queueBadgeClass(item.status) + '">' + esc(queueLabel(item.status)) + '</span>'
    + (item.credit != null ? '<span class="hint">' + esc(item.credit) + ' 积分</span>' : '')
    + (item.error ? '<span class="hint" style="color:var(--bad)">' + esc(String(item.error).slice(0, 40)) + '</span>' : '')
    + (item.url ? '<a class="hint" href="' + esc(item.url) + '" target="_blank">文件</a>' : '')
    + '<button data-qact="remove" data-index="' + i + '">移除</button></div>').join('');
  updateImgQueueSummary();
}
function updateImgQueueSummary(){
  const per = imageModel().creditPerImage != null ? imageModel().creditPerImage : 5.77;
  const done = imgQueue.filter(i => i.status === 'completed').length;
  const fail = imgQueue.filter(i => i.status === 'failed').length;
  const pending = imgQueue.filter(i => i.status !== 'completed' && i.status !== 'skipped').length;
  $('imgQueueSummary').textContent = '共 ' + imgQueue.length + ' 条 · 完成 ' + done
    + ' · 失败 ' + fail + ' · 待生成 ' + pending
    + ' · 本批预估 ' + (pending * per).toFixed(1) + ' 积分';
}
function importImgQueue(){
  const lines = $('imgPrompt').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  imgQueue = lines.map(text => ({text, status:'pending', credit:null, error:'', filename:'', url:''}));
  renderImgQueue();
}
function toggleImgQueue(){
  const on = $('imgBatch').checked;
  $('imgQueuePanel').classList.toggle('hidden', !on);
  if(on && !imgQueue.length) importImgQueue();
  updateImgQueueSummary();
}
$('imgQueueImport').onclick = () => { if(imgQueueRunning) return; importImgQueue(); toast('已导入 ' + imgQueue.length + ' 条到队列', 'ok'); };
$('imgQueueStop').onclick = () => {
  if(!imgQueueRunning) return;
  imgStopRequested = true;
  toast('将在当前条目完成后停止本批', 'warn');
};
$('imgQueueClear').onclick = () => { if(imgQueueRunning) return; imgQueue = []; renderImgQueue(); };
$('imgQueueList').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-qact]'); if(!btn || imgQueueRunning) return;
  if(btn.dataset.qact === 'remove'){ imgQueue.splice(parseInt(btn.dataset.index, 10), 1); renderImgQueue(); }
});
$('imgBatch').addEventListener('change', toggleImgQueue);

function renderVidQueue(){
  const box = $('vidQueueList');
  if(!vidQueue.length){ box.innerHTML = '<div class="hint">队列为空，点「从文本框导入」生成条目</div>'; }
  else box.innerHTML = vidQueue.map((item, i) =>
    '<div class="queue-item"><span class="idx">' + (i + 1) + '</span>'
    + '<span class="qtext">' + esc(item.text) + '</span>'
    + '<span class="badge ' + queueBadgeClass(item.status) + '">' + esc(queueLabel(item.status)) + '</span>'
    + (item.taskId ? '<a class="hint" href="#jobs" target="_blank">' + esc(item.taskId) + '</a>' : '')
    + (item.error ? '<span class="hint" style="color:var(--bad)">' + esc(item.error.slice(0, 40)) + '</span>' : '')
    + '<button data-qact="remove" data-index="' + i + '">移除</button></div>').join('');
  updateVidQueueSummary();
}
function updateVidQueueSummary(){
  const per = videoModel().creditPerSecond != null ? videoModel().creditPerSecond
    : (videoModel().creditPerSecondCeiling != null ? videoModel().creditPerSecondCeiling : 26);
  const sec = parseInt($('vidSeconds').value || '5', 10);
  const pending = vidQueue.filter(item => item.status !== 'submitted' && item.status !== 'skipped').length;
  const submitted = vidQueue.filter(item => item.status === 'submitted').length;
  $('vidQueueSummary').textContent = '共 ' + vidQueue.length + ' 条 · 已提交 ' + submitted
    + ' · 待提交 ' + pending + ' · 本批约 ' + (pending * per * sec).toFixed(1) + ' 积分';
}
function importVidQueue(){
  const lines = $('vidPrompt').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  vidQueue = lines.map(text => ({text, status:'pending', taskId:'', error:''}));
  renderVidQueue();
}
function toggleVidQueue(){
  const on = $('vidBatch').checked;
  $('vidQueuePanel').classList.toggle('hidden', !on);
  if(on && !vidQueue.length) importVidQueue();
  updateVidQueueSummary();
}
$('vidQueueImport').onclick = () => { if(vidQueueRunning) return; importVidQueue(); toast('已导入 ' + vidQueue.length + ' 条到队列', 'ok'); };
$('vidQueueStop').onclick = () => {
  if(!vidQueueRunning) return;
  vidStopRequested = true;
  toast('将在当前条目完成后停止本批', 'warn');
};
$('vidQueueClear').onclick = () => { if(vidQueueRunning) return; vidQueue = []; renderVidQueue(); };
$('vidQueueList').addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-qact]'); if(!btn || vidQueueRunning) return;
  if(btn.dataset.qact === 'remove'){ vidQueue.splice(parseInt(btn.dataset.index, 10), 1); renderVidQueue(); }
});
$('vidBatch').addEventListener('change', toggleVidQueue);

// ---------------- 图片生成 ----------------
let imgTimer = null, imgStart = 0;
function startImageProgress(){
  imgStart = Date.now();
  $('imgProgress').classList.add('on');
  $('imgBar').style.width = '';
  $('imgBar').className = 'bar-fill indet';
  clearInterval(imgTimer);
  imgTimer = setInterval(() => {
    $('imgProgressText').textContent = '已用 ' + fmtElapsed((Date.now()-imgStart)/1000) + ' · 上游生成中（不提供百分比）';
  }, 200);
}
function finishImageProgress(ok, note){
  clearInterval(imgTimer); imgTimer = null;
  $('imgBar').className = 'bar-fill ' + (ok ? 'ok' : 'bad');
  $('imgBar').style.width = '100%';
  $('imgProgressText').textContent = note || (ok ? '完成' : '失败');
}
function readFile(file){
  return new Promise((res, rej) => {
    const fr = new FileReader();
    fr.onload = () => res(fr.result);
    fr.onerror = () => rej(new Error('文件读取失败'));
    fr.readAsDataURL(file);
  });
}
// ---------------- 变体生成 ----------------
const VARIANT_SLOTS = [
  {key:'构图', options:[
    '近景头像，脸部占据画面大部分',
    '胸口以上半身，正面构图',
    '侧脸回眸，肩膀朝向画面左侧',
    '低角度仰视，下巴微抬',
    '半身坐姿，身体略微前倾'
  ]},
  {key:'动作', options:[
    '头部向画面左侧轻轻倾斜，下巴微收',
    '一只手托住下巴，手指轻贴脸颊',
    '手指抵在唇边，做出“嘘”的手势',
    '双臂随意交叠在胸前',
    '回头看向镜头，头发甩向一侧'
  ]},
  {key:'表情', options:[
    '半睁眼从下往上看镜头，一侧嘴角轻微上扬',
    '平静地直视镜头，几乎不带表情',
    '挑眉，露出一点尖牙的坏笑',
    '微微眯眼，带一点挑逗的淡笑'
  ]},
  {key:'背景', options:[
    '纯白背景',
    '深灰黑色背景，边缘飘入几片粗糙粉色花瓣',
    '暗红色光晕背景，薄雾',
    '窗边逆光，背景简化成几块灰色色块'
  ]},
  {key:'光线', options:[
    '平光，无强烈阴影',
    '红色轮廓光从侧面打来',
    '顶部硬光，头发上有粗糙高光',
    '逆光，人物边缘有一圈浅色亮边'
  ]}
];
const EMMA_TEMPLATE = '一张极其随意、粗糙、简单的日系萌系动漫人物数字涂鸦，角色为《魔法少女的魔女审判》中的樱羽艾玛，{构图}。整体低完成度、稚拙、随手涂画；用极少的线条和色块表现角色，保留不规整的手绘痕迹。线稿用明显粗黑、粗细不均、会突然断开和错位的笔触；头发只用少量粗黑曲线，不画细碎发丝。上色为不均匀的大面积平涂，颜色可越过轮廓、留下白色空隙，高光是几笔粗糙白色块。{动作}。{表情}。白色短发，长度接近下巴，发尾与内侧带浅粉渐变；黑色贝雷帽、樱花发饰、黑色十字发夹；黑色白边制服、白衬衫、深色领结、黑 choker。{背景}。{光线}。画面必须粗糙、潦草、不精确，不要精修、不要细化五官和发丝、不要厚涂或丰富阴影。';
function renderVariantSlots(){
  const box = $('variantSlots');
  box.innerHTML = VARIANT_SLOTS.map(g =>
    '<div class="slot-group"><div class="slot-title">' + g.key + '</div>' +
    g.options.map((opt, i) => '<label class="slot-chip"><input type="checkbox" data-slot="' + g.key + '" value="' + i + '" checked>' + esc(opt) + '</label>').join('') +
    '</div>').join('');
  box.querySelectorAll('input').forEach(cb => cb.addEventListener('change', () => {
    $('variantPreview').classList.add('hidden');
    updateVariantCost();
  }));
}
function selectedSlot(key){
  const group = VARIANT_SLOTS.find(g => g.key === key);
  const boxes = [...document.querySelectorAll('#variantSlots input[data-slot="' + key + '"]:checked')];
  const vals = boxes.map(b => group.options[parseInt(b.value, 10)]);
  return vals.length ? vals : group.options.slice();
}
function buildVariantPrompt(combo){
  let core = $('variantCore').value.trim();
  if(!core) throw new Error('请先填写核心提示词');
  let replaced = false;
  Object.keys(combo).forEach(k => {
    const token = '{' + k + '}';
    if(core.includes(token)){
      core = core.split(token).join(combo[k]);
      replaced = true;
    }
  });
  if(!replaced){
    core += ' 变体要求：' + Object.keys(combo).map(k => k + '：' + combo[k]).join('；') + '。';
  }
  return core;
}
function collectVariants(){
  let count = Math.max(1, Math.min(30, parseInt($('variantCount').value || '6', 10)));
  const mode = $('variantMode').value;
  const keys = VARIANT_SLOTS.map(g => g.key);
  const pools = {};
  keys.forEach(k => { pools[k] = selectedSlot(k); });
  const combos = [];
  if(mode === 'all'){
    let acc = [{}];
    for(const k of keys){
      const next = [];
      for(const c of acc){
        for(const opt of pools[k]) next.push(Object.assign({}, c, {[k]: opt}));
      }
      acc = next;
      if(acc.length > 200) break;
    }
    acc.sort(() => Math.random() - 0.5);
    combos.push(...acc.slice(0, Math.min(20, count)));
    count = combos.length;
  }else{
    const seen = new Set();
    let guard = 0;
    while(combos.length < count && guard++ < count * 80){
      const c = {};
      keys.forEach(k => { c[k] = pools[k][Math.floor(Math.random() * pools[k].length)]; });
      const sig = keys.map(k => c[k]).join('|');
      if(seen.has(sig)) continue;
      seen.add(sig);
      combos.push(c);
    }
  }
  return combos.map(buildVariantPrompt);
}
function updateVariantCost(){
  const n = Math.max(1, Math.min(30, parseInt($('variantCount').value || '6', 10)));
  const per = imageModel().creditPerImage != null ? imageModel().creditPerImage : 5.77;
  $('variantCost').textContent = '约 ' + (n * per).toFixed(1) + ' 积分（' + n + ' 条）';
}
function fillVariants(autoSubmit){
  if(imgQueueRunning){
    $('variantHint').textContent = '批量生成进行中，不能替换队列；请等当前批次结束。';
    return;
  }
  try{
    const prompts = collectVariants();
    if(!prompts.length) throw new Error('没有生成任何组合');
    const append = $('variantAppend').checked;
    const existing = $('imgPrompt').value.trim();
    if(!append && existing && !confirm('变体列表会覆盖当前 prompt，继续？')) return;
    const list = append && existing ? [existing].concat(prompts) : prompts;
    $('imgPrompt').value = list.join('\n');
    $('imgBatch').checked = true;
    $('imgQueuePanel').classList.remove('hidden');
    importImgQueue();
    updateImageCost();
    $('variantHint').textContent = '已填入 ' + list.length + ' 条到生图 prompt；核对后点「生成图片」即可。';
    $('variantPreview').classList.remove('hidden');
    $('variantPreviewTitle').textContent = '已生成 ' + list.length + ' 条，已填入上方 prompt 框并开启批量模式：';
    $('variantList').textContent = list.map((p, i) => (i + 1) + '. ' + p).join('\n\n');
    $('variantPreview').scrollIntoView({behavior:'smooth', block:'center'});
    log('变体生成：' + list.length + ' 条已填入', 'ok');
    if(autoSubmit){
      $('imgGo').click();
    }
  }catch(e){
    $('variantHint').textContent = e.message;
    log('变体生成失败: ' + e.message, 'err');
  }
}
$('variantToggle').onclick = () => {
  $('variantPanel').classList.remove('hidden');
  if(!$('variantCore').value.trim()) $('variantCore').value = EMMA_TEMPLATE;
  $('variantPanel').scrollIntoView({behavior:'smooth', block:'start'});
};
$('variantClose').onclick = () => $('variantPanel').classList.add('hidden');
$('variantTemplate').onclick = () => {
  $('variantCore').value = EMMA_TEMPLATE;
  document.querySelectorAll('#variantSlots input').forEach(cb => { cb.checked = true; });
  $('variantCount').value = '6';
  $('variantPreview').classList.add('hidden');
  updateVariantCost();
  $('variantHint').textContent = '已载入艾玛模板，所有槽位已勾选。';
};
$('variantLoadPrompt').onclick = () => {
  const current = $('imgPrompt').value.trim();
  if(!current){ $('variantHint').textContent = '当前生图 prompt 为空，请先填写。'; return; }
  $('variantCore').value = current;
  $('variantPreview').classList.add('hidden');
  $('variantHint').textContent = '已载入当前 prompt；如果里面没有占位符，槽位会追加到末尾。';
};
$('variantMake').onclick = () => fillVariants(false);
$('variantSubmit').onclick = () => fillVariants(true);
$('variantGo').onclick = () => {
  const n = $('imgPrompt').value.split(/\r?\n/).filter(Boolean).length;
  if(!n){ $('variantHint').textContent = '没有可提交的 prompt'; return; }
  if(!$('imgBatch').checked){ $('imgBatch').checked = true; toggleImgQueue(); }
  $('imgGo').click();
};
$('variantCore').addEventListener('input', () => $('variantPreview').classList.add('hidden'));
$('variantCount').addEventListener('input', () => { $('variantPreview').classList.add('hidden'); updateVariantCost(); });
$('variantMode').addEventListener('change', () => { $('variantPreview').classList.add('hidden'); updateVariantCost(); });
renderVariantSlots();
$('variantCore').value = EMMA_TEMPLATE;
updateVariantCost();

async function generateOneImage(prompt, size, model){
  const d = await api('/api/image', {model, prompt, size, n: 1});
  const item = (d.data || [])[0] || {};
  const src = d.saved_url || (item.b64_json ? ('data:image/png;base64,' + item.b64_json) : '');
  if(!src) throw new Error('图片已生成但保存失败：' + (d.saved_error || '没有可用的本地文件'));
  return {d, item, src};
}
$('imgGo').onclick = async () => {
  const raw = $('imgPrompt').value.trim();
  if(!raw){ $('imgErr').textContent = '请填写画面描述'; return; }
  $('imgErr').textContent = ''; $('imgOut').innerHTML = '';
  $('imgGo').disabled = true;
  try{
    await ensureSaveDir();
    const size = imageSize('img');
    if($('imgBatch').checked){
      if(imgQueueRunning) return;
      if(!imgQueue.length) importImgQueue();
      if(!imgQueue.length) throw new Error('队列为空，请先在文本框里写 prompt 并点「从文本框导入」');
      const runQueue = imgQueue.filter(item => item.status !== 'completed' && item.status !== 'skipped');
      if(!runQueue.length) throw new Error('队列里没有待生成的条目；如需重跑，请点「从文本框导入」重置状态');
      if(runQueue.length > 30) throw new Error('单批最多 30 条，请分批生成');
      const model = $('imgModel').value;
      const per = imageModel().creditPerImage != null ? imageModel().creditPerImage : 5.77;
      if(!confirm('将生成 ' + runQueue.length + ' 张图片，预计 ' + (runQueue.length * per).toFixed(1) + ' 积分，继续？')) return;
      imgStopRequested = false;
      imgQueueRunning = true;
      startImageProgress();
      let last = null, total = 0, failures = 0, stopped = false;
      for(let i = 0; i < runQueue.length; i++){
        if(imgStopRequested) stopped = true;
        const item = runQueue[i];
        if(stopped){ item.status = 'skipped'; renderImgQueue(); continue; }
        item.status = 'running'; item.error = ''; renderImgQueue();
        $('imgStatus').textContent = '批量 ' + (i+1) + '/' + runQueue.length;
        try{
          const result = await generateOneImage(item.text, size, model);
          item.status = 'completed';
          item.credit = result.d.credit;
          item.filename = result.d.saved_name || '';
          item.url = result.d.saved_url || '';
          last = result;
          total += (typeof result.d.credit === 'number' ? result.d.credit : 0);
          if(result.d.job_id) selectedJobId = result.d.job_id;
          renderImgQueue();
          log('生图完成 ' + (i+1) + '/' + runQueue.length + '：积分 ' + (result.d.credit ?? '-') + '，保存 ' + (result.d.saved_name || '失败'), 'ok');
          loadHealth();
        }catch(lineErr){
          item.status = 'failed';
          item.error = lineErr.message;
          failures++;
          renderImgQueue();
          log('第 ' + (i+1) + ' 条失败: ' + lineErr.message, 'err');
          if(moderationError(lineErr.message)){
            stopped = true;
            log('检测到内容审核/风控错误，停止剩余批次', 'warn');
            toast('内容审核失败，已停止剩余批次', 'warn');
          }
        }
        if(i < runQueue.length - 1 && !stopped) await sleep(2000);
      }
      imgQueueRunning = false;
      if(last){
        const src = last.src;
        $('imgOut').innerHTML = '<img src="' + esc(src) + '" alt="result">'
          + '<div class="meta">批量完成 · 成功 ' + runQueue.filter(x => x.status === 'completed').length
          + ' 条 · 失败 ' + failures + ' 条 · 共 ' + total.toFixed(2) + ' 积分</div>';
      }
      finishImageProgress(!!last && failures === 0, last
        ? '批量完成 · 积分 ' + total.toFixed(2) + '（失败 ' + failures + ' 条）'
        : '批量失败：' + (runQueue[0] && runQueue[0].error || '未知错误'));
      if(!last) $('imgErr').textContent = '批量全部失败';
      toast('批量完成：成功 ' + runQueue.filter(x => x.status === 'completed').length + ' 条，失败 ' + failures + ' 条', failures ? 'warn' : 'ok');
      loadJobs();
      loadHealth();
      return;
    }
    startImageProgress();
    $('imgStatus').textContent = '生成中…';
    const result = await generateOneImage(raw, size, $('imgModel').value);
    if(result.d.job_id) selectedJobId = result.d.job_id;
    const src = result.src;
    $('imgOut').innerHTML = '<img src="' + esc(src) + '" alt="result">'
      + '<div class="meta">积分 ' + esc(result.d.credit ?? '-') + ' · 已保存：' + esc(result.d.saved_path || '未保存') + '</div>';
    finishImageProgress(true, '完成 · ' + fmtElapsed((Date.now()-imgStart)/1000) + ' · 积分 ' + (result.d.credit ?? '-'));
    log('生图完成：积分 ' + (result.d.credit ?? '-') + '，保存 ' + (result.d.saved_name || '失败'), 'ok');
    toast('生图完成', 'ok');
    loadJobs();
    loadHealth();
  }catch(e){
    $('imgErr').textContent = e.message;
    finishImageProgress(false, '失败 · ' + e.message);
    log('生图失败: ' + e.message, 'err');
    toast('生图失败: ' + e.message, 'err');
  }finally{
    imgQueueRunning = false;
    imgStopRequested = false;
    $('imgGo').disabled = false; $('imgStatus').textContent = '';
  }
};

// ---------------- 改图 ----------------
let editTimer = null, editStart = 0;
$('editGo').onclick = async () => {
  const prompt = $('editPrompt').value.trim();
  const files = Array.from($('editFiles').files || []);
  if(!prompt){ $('editErr').textContent = '请填写改动描述'; return; }
  if(!files.length){ $('editErr').textContent = '请选择至少一张原图'; return; }
  try{ validateImageFiles(files, '原图', 8); }
  catch(e){ $('editErr').textContent = e.message; return; }
  $('editErr').textContent = ''; $('editOut').innerHTML = '';
  $('editGo').disabled = true; $('editStatus').textContent = '生成中…';
  editStart = Date.now();
  $('editProgress').classList.add('on');
  $('editBar').style.width = '';
  $('editBar').className = 'bar-fill indet';
  clearInterval(editTimer);
  editTimer = setInterval(() => {
    $('editProgressText').textContent = '已用 ' + fmtElapsed((Date.now()-editStart)/1000) + ' · 上游生成中';
  }, 200);
  try{
    await ensureSaveDir();
    const size = imageSize('edit');
    const images = [];
    for(const file of files) images.push(await readFile(file));
    const d = await api('/api/edit', {model: $('editModel').value, prompt, size, image: images, n: 1});
    const item = (d.data || [])[0] || {};
    const src = d.saved_url || (item.b64_json ? ('data:image/png;base64,' + item.b64_json) : '');
    if(!src) throw new Error('图片已生成但保存失败：' + (d.saved_error || '没有可用的本地文件'));
    $('editOut').innerHTML = '<img src="' + esc(src) + '"><div class="meta">积分 '
      + esc(d.credit ?? '-') + ' · 已保存：' + esc(d.saved_path || '未保存') + '</div>';
    clearInterval(editTimer);
    $('editBar').className = 'bar-fill ok'; $('editBar').style.width = '100%';
    $('editProgressText').textContent = '完成 · ' + fmtElapsed((Date.now()-editStart)/1000);
    log('改图完成：积分 ' + (d.credit ?? '-') + '，保存 ' + (d.saved_name || '失败'), 'ok');
    loadJobs();
    loadHealth();
  }catch(e){
    $('editErr').textContent = e.message;
    clearInterval(editTimer);
    $('editBar').className = 'bar-fill bad'; $('editBar').style.width = '100%';
    $('editProgressText').textContent = '失败 · ' + e.message;
    log('改图失败: ' + e.message, 'err');
  }finally{
    $('editGo').disabled = false; $('editStatus').textContent = '';
  }
};

// ---------------- 生视频 ----------------
$('vidFirst').addEventListener('change', () => {
  const has = !!$('vidFirst').files[0];
  $('vidAspect').disabled = has;
  $('vidAspect').title = has ? '图生视频由首帧决定比例' : '';
});
$('vidGo').onclick = async () => {
  const raw = $('vidPrompt').value.trim();
  if(!raw){ $('vidErr').textContent = '请填写画面描述'; return; }
  $('vidErr').textContent = ''; $('vidGo').disabled = true;
  try{
    await ensureSaveDir();
    const firstFile = $('vidFirst').files[0];
    const lastFile = $('vidLast').files[0];
    const refFiles = Array.from($('vidRefs').files || []);
    const refMax = parseInt($('vidRefs').dataset.max || '0', 10);
    if(refFiles.length > refMax){ throw new Error('参考图最多 ' + refMax + ' 张'); }
    if(firstFile) validateImageFiles([firstFile], '首帧图', 1);
    if(lastFile) validateImageFiles([lastFile], '尾帧图', 1);
    if(refFiles.length) validateImageFiles(refFiles, '参考图', refMax || 0);
    const first = firstFile ? await readFile(firstFile) : null;
    const last = lastFile ? await readFile(lastFile) : null;
    const refs = [];
    for(const f of refFiles) refs.push(await readFile(f));
    const base = {
      model: $('vidModel').value,
      seconds: parseInt($('vidSeconds').value, 10),
      resolution: $('vidResolution').value,
      enable_audio: $('vidAudio').checked,
      negative_prompt: $('vidNegative').value.trim(),
      image: first || undefined,
      last_image: last || undefined,
      reference_images: refs.length ? refs : undefined
    };
    if(!first) base.aspect_ratio = $('vidAspect').value;
    if($('vidBatch').checked){
      if(vidQueueRunning) return;
      if(!vidQueue.length) importVidQueue();
      if(!vidQueue.length) throw new Error('队列为空，请先在文本框里写 prompt 并点「从文本框导入」');
      const runQueue = vidQueue.filter(item => item.status !== 'submitted' && item.status !== 'skipped');
      if(!runQueue.length) throw new Error('队列里没有待提交的条目；如需重跑，请点「从文本框导入」重置状态');
      if(runQueue.length > 20) throw new Error('单批最多 20 条视频，请分批提交');
      const per = videoModel().creditPerSecond != null ? videoModel().creditPerSecond
        : (videoModel().creditPerSecondCeiling != null ? videoModel().creditPerSecondCeiling : 26);
      const sec = parseInt($('vidSeconds').value || '5', 10);
      const shared = [];
      if(first) shared.push('首帧');
      if(last) shared.push('尾帧');
      if(refs.length) shared.push(refs.length + ' 张参考图');
      const extra = shared.length ? '\n注意：' + shared.join(' / ') + '会应用到所有条目。' : '';
      if(!confirm('将按队列依次提交 ' + runQueue.length + ' 条视频，预计 '
        + (runQueue.length * per * sec).toFixed(1) + ' 积分。' + extra + '\n继续？')) return;
      vidStopRequested = false;
      vidQueueRunning = true;
      let stopped = false, submitted = 0;
      for(let i = 0; i < runQueue.length; i++){
        if(vidStopRequested) stopped = true;
        const item = runQueue[i];
        if(stopped){ item.status = 'skipped'; renderVidQueue(); continue; }
        item.status = 'submitting'; item.error = ''; renderVidQueue();
        $('vidStatus').textContent = '批量 ' + (i+1) + '/' + runQueue.length;
        try{
          const d = await api('/api/video', Object.assign({}, base, {prompt: item.text}));
          if(!d.id) throw new Error('没有返回任务 ID');
          item.status = 'submitted';
          item.taskId = d.id;
          if(d.job_id) selectedJobId = d.job_id;
          submitted++;
          renderVidQueue();
          log('视频任务已提交 ' + (i+1) + '/' + runQueue.length + ': ' + d.id, 'ok');
          loadHealth();
        }catch(e){
          item.status = 'failed';
          item.error = e.message;
          renderVidQueue();
          log('第 ' + (i+1) + ' 条提交失败: ' + e.message, 'err');
          if(moderationError(e.message)){
            stopped = true;
            toast('内容审核失败，已停止剩余批次', 'warn');
          }
        }
        if(i < runQueue.length - 1 && !stopped) await sleep(3000);
      }
      vidQueueRunning = false;
      $('vidStatus').textContent = '已提交 ' + submitted + ' 条';
      toast('批量提交完成：' + submitted + ' 条', submitted ? 'ok' : 'warn');
      loadJobs();
      showView('jobs');
      return;
    }
    $('vidStatus').textContent = '提交中…';
    const d = await api('/api/video', Object.assign({}, base, {prompt: raw}));
    if(!d.id) throw new Error('没有返回任务 ID');
    if(d.job_id) selectedJobId = d.job_id;
    log('视频任务已提交: ' + d.id, 'ok');
    toast('视频任务已提交', 'ok');
    $('vidStatus').textContent = '任务 ' + d.id;
    loadJobs();
    loadHealth();
    showView('jobs');
  }catch(e){
    $('vidErr').textContent = e.message;
    $('vidStatus').textContent = '';
    log('提交视频失败: ' + e.message, 'err');
    toast('提交视频失败: ' + e.message, 'err');
  }finally{
    vidQueueRunning = false;
    vidStopRequested = false;
    $('vidGo').disabled = false;
  }
};

// ---------------- 通用 ----------------
$('vidSeconds').addEventListener('change', updateVideoCaps);
$('vidResolution').addEventListener('change', updateVideoCaps);

document.addEventListener('keydown', ev => {
  if((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter' && !ev.isComposing){
    if(!$('accessGate').classList.contains('hidden')) return;
    if($('tagDrawer').classList.contains('on')) return;
    ev.preventDefault();
    if(currentView === 'image') $('imgGo').click();
    else if(currentView === 'edit') $('editGo').click();
    else if(currentView === 'video') $('vidGo').click();
  }
});
document.addEventListener('dragover', ev => ev.preventDefault());
document.addEventListener('drop', ev => {
  ev.preventDefault();
  if(!ev.dataTransfer || !ev.dataTransfer.files.length) return;
  if(currentView === 'edit'){
    $('editFiles').files = ev.dataTransfer.files;
    renderFilePreview('editFiles', 'editFilePreview', 8);
    log('已通过拖拽加入 ' + ev.dataTransfer.files.length + ' 张原图', 'info');
  }else if(currentView === 'video'){
    $('vidFirst').files = ev.dataTransfer.files;
    $('vidFirst').dispatchEvent(new Event('change'));
    renderFilePreview('vidFirst', 'vidFirstPreview', 1);
    log('已通过拖拽加入首帧图', 'info');
  }
});
$('imgOut').addEventListener('click', ev => { if(ev.target.tagName === 'IMG') openLightbox(ev.target.src); });
$('editOut').addEventListener('click', ev => { if(ev.target.tagName === 'IMG') openLightbox(ev.target.src); });
function openLightbox(src){ $('lightboxImg').src = src; $('lightbox').classList.add('on'); }
$('lightbox').addEventListener('click', () => $('lightbox').classList.remove('on'));
window.addEventListener('hashchange', () => {
  const name = (location.hash || '#image').slice(1);
  if(VIEW_META[name] && name !== currentView) showView(name);
});

renderFilePreview('editFiles', 'editFilePreview', 8);
renderFilePreview('vidFirst', 'vidFirstPreview', 1);
renderFilePreview('vidLast', 'vidLastPreview', 1);
renderFilePreview('vidRefs', 'vidRefsPreview', 9);
let booted = false;
let timersStarted = false;
function boot(){
  if(booted) return;
  booted = true;
  loadConsoleHistory().then(() => log('工作台已就绪', 'ok'));
  loadConfig();
  loadHealth();
  loadModels();
  loadJobs();
  loadAudit();
  showView((location.hash || '#image').slice(1));
  if(!timersStarted){
    timersStarted = true;
    setInterval(loadJobs, 2500);
    setInterval(loadHealth, 60000);
  }
}
$('gateEnter').onclick = async () => {
  const pwd = $('gatePassword').value.trim();
  if(!pwd) return;
  accessPassword = pwd;
  try{
    await api('/api/config');
    $('accessGate').classList.add('hidden');
    $('gateErr').textContent = '';
    boot();
  }catch(e){
    accessPassword = '';
    $('gateErr').textContent = e.message || '密码不正确，或服务未启动';
  }
};
$('gatePassword').addEventListener('keydown', ev => {
  if(ev.key === 'Enter') $('gateEnter').click();
});
async function startApp(){
  if(ACCESS_REQUIRED){
    $('accessGate').classList.remove('hidden');
    return;
  }
  boot();
}
startApp();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))
        sys.stdout.flush()

    def _send(self, status, body, content_type="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self' blob:; img-src 'self' data: blob:; "
            "media-src 'self' blob:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'nonce-%s'; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'" % CSP_NONCE)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False))

    def _err(self, status, message):
        self._json(status, {"error": {"message": message}})

    def _header(self, name):
        return str(self.headers.get(name) or "")

    def _host_ok(self):
        host = self._header("Host").strip()
        if not host:
            return False
        if host.startswith("["):
            host = host[1:host.find("]")] if "]" in host else host
        else:
            host = host.split(":")[0]
        return host.lower() in ("127.0.0.1", "localhost", "::1")

    def _guard_api(self, post=False):
        cfg = load_config()
        if CONFIG_STATE["error"]:
            self.close_connection = True
            self._err(503, "studio-config.json 损坏，请先修复配置")
            return False
        if post:
            origin = self._header("Origin")
            if origin and origin not in ("http://127.0.0.1:8790", "http://localhost:8790"):
                self.close_connection = True
                self._err(403, "cross-origin request rejected")
                return False
        token = self._header("X-Studio-Token")
        if (not token.isascii()
                or not hmac.compare_digest(token.encode("ascii"), STUDIO_TOKEN.encode("ascii"))):
            self.close_connection = True
            self._err(401, "missing or invalid studio token")
            return False
        if post and not self._allow_post():
            self.close_connection = True
            self._err(429, "too many requests, slow down")
            return False
        stored = cfg.get("access_password_hash") or ""
        if stored:
            given = self._header("X-Studio-Access")
            if not given or not verify_access_password(given, stored):
                self.close_connection = True
                self._err(401, "access password required")
                return False
        return True

    def _allow_post(self):
        ip = self.client_address[0] if getattr(self, "client_address", None) else "local"
        now = time.time()
        with POST_LOCK:
            attempts = [t for t in POST_WINDOW.get(ip, []) if now - t < 60]
            if len(attempts) >= POST_LIMIT:
                POST_WINDOW[ip] = attempts
                return False
            attempts.append(now)
            POST_WINDOW[ip] = attempts
        return True

    def _read_json(self):
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("缺少 Content-Length")
        try:
            length = int(raw_length)
        except ValueError:
            raise ValueError("Content-Length 无效")
        if length <= 0:
            return {}
        if length > MAX_BODY:
            self.close_connection = True
            raise ValueError("请求体过大")
        raw = self.rfile.read(length)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("gb18030", "replace")
        data = json.loads(text or "{}")
        if not isinstance(data, dict):
            raise ValueError("JSON 请求体必须是对象")
        return data

    def _send_file(self, fp):
        try:
            size = os.path.getsize(fp)
        except OSError:
            self._err(404, "file not found")
            return
        ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
        start, end, status = 0, size - 1, 200
        rng = self.headers.get("Range")
        if rng:
            m = re.match(r"bytes=(\d*)-(\d*)", rng.strip())
            if m:
                a, b = m.group(1), m.group(2)
                if a:
                    start = int(a)
                    end = int(b) if b else size - 1
                elif b:
                    start = max(0, size - int(b))
                    end = size - 1
                end = min(end, size - 1)
                if start >= size or start > end:
                    self.send_response(416)
                    self.send_header("Content-Range", "bytes */%d" % size)
                    self.send_header("Content-Length", "0")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Referrer-Policy", "no-referrer")
                    self.send_header("X-Frame-Options", "DENY")
                    self.end_headers()
                    return
                status = 206
        length = end - start + 1
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(length))
        if status == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; img-src 'self' data:; media-src 'self'; "
            "style-src 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        try:
            with open(fp, "rb") as fh:
                fh.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = fh.read(min(65536, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            self.close_connection = True

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if not self._host_ok():
            self._err(403, "unexpected host")
            return
        if path.startswith("/api/") and not self._guard_api(post=False):
            return
        if path == "/":
            html = PAGE.replace("__PAGE_VERSION__", SERVER_STARTED)
            html = html.replace("__STUDIO_TOKEN__", STUDIO_TOKEN)
            html = html.replace("__CSP_NONCE__", CSP_NONCE)
            cfg = load_config()
            html = html.replace("__ACCESS_REQUIRED__",
                                "true" if cfg.get("access_password_hash") else "false")
            self._send(200, html, "text/html; charset=utf-8")
            return
        if path == "/api/config":
            cfg = load_config()
            self._json(200, {"save_dir": cfg["save_dir"], "version": SERVER_STARTED,
                             "access_required": bool(cfg.get("access_password_hash"))})
            return
        if path == "/api/models":
            status, _, body = gateway("/v1/media/models", timeout=30)
            self._send(status, body)
            return
        if path == "/api/jobs":
            with STATE_LOCK:
                jobs = [public_job(j) for j in JOBS]
            self._json(200, {"jobs": jobs})
            return
        if path.startswith("/api/job/"):
            job = find_job(urllib.parse.unquote(path[len("/api/job/"):]))
            if not job:
                self._err(404, "no such job")
            else:
                self._json(200, public_job(job))
            return
        if path == "/api/logs":
            with LOG_LOCK:
                logs = list(LOG_ENTRIES)
            self._json(200, {"logs": logs})
            return
        if path == "/api/tags":
            with TAG_LOCK:
                self._json(200, load_tags())
            return
        if path == "/api/health":
            self._json(200, collect_health())
            return
        if path == "/api/gallery":
            qs = urllib.parse.parse_qs(parsed.query)
            try:
                limit = max(1, min(2000, int((qs.get("limit") or ["300"])[0])))
            except ValueError:
                limit = 300
            try:
                offset = max(0, min(1000000, int((qs.get("offset") or ["0"])[0])))
            except ValueError:
                offset = 0
            self._json(200, list_gallery(limit, offset))
            return
        if path == "/api/audit":
            qs = urllib.parse.parse_qs(parsed.query)
            try:
                limit = max(1, min(500, int((qs.get("limit") or ["100"])[0])))
            except ValueError:
                limit = 100
            self._json(200, {"entries": read_audit(limit)})
            return
        if path.startswith("/files/"):
            name = verify_file_signature(parsed)
            if not name:
                self._err(403, "file link invalid or expired")
                return
            fp = resolve_saved_file(name)
            if not fp:
                self._err(404, "file not found")
                return
            self._send_file(fp)
            return
        if path.startswith("/api/video/") and path.endswith("/content"):
            task_id = path[len("/api/video/"):-len("/content")].strip("/")
            if not task_id:
                self._err(404, "no such task")
                return
            status, _, body = gateway(
                "/v1/videos/%s/content" % urllib.parse.quote(task_id, safe=""),
                timeout=900, max_bytes=MAX_VIDEO_BYTES)
            if len(body) > MAX_VIDEO_BYTES:
                self._err(413, "video too large")
                return
            ctype = "video/mp4" if status == 200 else "application/json; charset=utf-8"
            self._send(status, body, ctype)
            return
        if path.startswith("/api/video/"):
            task_id = path[len("/api/video/"):].strip("/")
            if not task_id:
                self._err(404, "no such task")
                return
            status, _, body = gateway(
                "/v1/videos/%s" % urllib.parse.quote(task_id, safe=""), timeout=30)
            self._send(status, body)
            return
        self._err(404, "not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._host_ok():
            self._err(403, "unexpected host")
            return
        if path.startswith("/api/") and not self._guard_api(post=True):
            return
        try:
            payload = self._read_json()
        except Exception as exc:
            self._err(400, str(exc))
            return

        if path == "/api/config":
            try:
                with CONFIG_LOCK:
                    raw = load_config_raw()
                    cfg = load_config()
                    if "save_dir" in payload and payload.get("save_dir") is not None:
                        value = set_save_dir(payload.get("save_dir"))
                    else:
                        value = str(raw.get("save_dir") or cfg["save_dir"])
                        value = os.path.abspath(os.path.expanduser(value))
                    cfg["save_dir"] = value
                    if "access_password" in payload:
                        cfg["access_password_hash"] = set_access_password(payload.get("access_password"))
                    cfg.pop("panel_password", None)
                    save_config(cfg)
                slog("ok", "保存目录改为: %s" % value)
                audit("config_save", "save_dir=%s access=%s" % (
                    value, "on" if cfg.get("access_password_hash") else "off"))
                self._json(200, {"save_dir": value, "version": SERVER_STARTED,
                                 "access_required": bool(cfg.get("access_password_hash"))})
            except Exception as exc:
                self._err(400, str(exc))
            return

        if path == "/api/refresh-balance":
            try:
                bal = refresh_upstream_balance(
                    payload.get("panel_password") or payload.get("password"))
                audit("balance_refresh", "balance=%s" % bal.get("balance"))
                self._json(200, {"balance": bal.get("balance"),
                                 "updated_at": bal.get("updated_at"),
                                 "source": "upstream"})
            except Exception as exc:
                self._err(500, str(exc))
            return

        if path == "/api/open-folder":
            cfg = load_config()
            try:
                if os.name == "nt":
                    os.startfile(cfg["save_dir"])  # noqa: S606
                else:
                    subprocess.Popen(["xdg-open", cfg["save_dir"]])
                audit("open_folder", cfg["save_dir"])
                self._json(200, {"ok": True, "save_dir": cfg["save_dir"]})
            except Exception as exc:
                self._err(500, str(exc))
            return

        if path == "/api/open-config":
            try:
                if os.name == "nt":
                    os.startfile(HERE)  # noqa: S606
                else:
                    subprocess.Popen(["xdg-open", HERE])
                audit("open_config", HERE)
                self._json(200, {"ok": True, "dir": HERE})
            except Exception as exc:
                self._err(500, str(exc))
            return

        if path == "/api/reveal":
            filename = os.path.basename(str(payload.get("filename") or ""))
            candidate = str(payload.get("path") or "")
            target = candidate if candidate and os.path.isfile(candidate) else ""
            if not target:
                target = os.path.join(load_config()["save_dir"], filename)
            if not target or not os.path.isfile(target):
                self._err(404, "文件不存在")
                return
            save_dir = load_config()["save_dir"]
            allowed = _is_under(target, save_dir)
            if not allowed:
                with STATE_LOCK:
                    allowed = any(
                        j.get("path") and os.path.normcase(os.path.abspath(j["path"]))
                        == os.path.normcase(os.path.abspath(target))
                        for j in JOBS)
            if not allowed:
                self._err(403, "只能打开保存目录或任务记录里的文件")
                return
            try:
                if os.name == "nt":
                    subprocess.Popen(["explorer", "/select,%s" % os.path.normpath(target)])
                else:
                    subprocess.Popen(["xdg-open", os.path.dirname(target)])
                audit("reveal", target)
                self._json(200, {"ok": True})
            except Exception as exc:
                self._err(500, str(exc))
            return

        if path == "/api/jobs/clear":
            delete_files = payload.get("delete_files", False)
            if not isinstance(delete_files, bool):
                self._err(400, "delete_files 必须是布尔值")
                return
            clear_finished_jobs(delete_files)
            self._json(200, {"ok": True})
            return

        if path == "/api/jobs/delete":
            try:
                delete_job(payload.get("id") or "")
                self._json(200, {"ok": True})
            except Exception as exc:
                self._err(400, str(exc))
            return

        if path == "/api/tags":
            try:
                tag = upsert_tag(payload)
                slog("ok", "保存标签: %s（%s）" % (tag.get("text", "")[:40], tag.get("category")))
                audit("tag_save", "%s | %s" % (tag.get("category"), tag.get("text", "")[:80]))
                self._json(200, {"ok": True, "tag": tag})
            except Exception as exc:
                self._err(400, str(exc))
            return

        if path == "/api/tags/delete":
            try:
                delete_tag(payload.get("id") or "")
                audit("tag_delete", payload.get("id") or "")
                self._json(200, {"ok": True})
            except Exception as exc:
                self._err(400, str(exc))
            return

        if path == "/api/tags/use":
            try:
                tag = use_tag(payload.get("id") or "")
                self._json(200, {"ok": True, "tag": tag})
            except Exception as exc:
                self._err(400, str(exc))
            return

        if path == "/api/tags/import":
            try:
                result = import_tags(payload)
                audit("tag_import", "added=%d skipped=%d" % (
                    result["added"], result["skipped"]))
                self._json(200, result)
            except Exception as exc:
                self._err(400, str(exc))
            return

        if path == "/api/tag-categories":
            try:
                data = tag_category_action(payload)
                audit("tag_category", "%s %s" % (payload.get("action"), payload.get("name")))
                self._json(200, {"ok": True, "categories": data["categories"]})
            except Exception as exc:
                self._err(400, str(exc))
            return

        if path == "/api/logs/clear":
            clear_logs()
            audit("logs_clear", "")
            self._json(200, {"ok": True})
            return

        if path == "/api/rename-artifacts":
            try:
                self._json(200, rename_artifacts())
            except Exception as exc:
                self._err(500, str(exc))
            return

        if path == "/api/favorites":
            try:
                name = payload.get("name") or ""
                fav = payload.get("favorite")
                if not isinstance(fav, bool):
                    raise ValueError("favorite 必须是布尔值")
                favorite = set_favorite(name, fav)
                audit("favorite", "%s favorite=%s" % (name, favorite))
                self._json(200, {"ok": True, "favorite": favorite})
            except ValueError as exc:
                self._err(400, str(exc))
            except Exception as exc:
                self._err(500, str(exc))
            return

        if path == "/api/gallery/delete":
            try:
                self._json(200, delete_gallery_item(payload.get("name")))
            except ValueError as exc:
                self._err(400, str(exc))
            except Exception as exc:
                self._err(500, str(exc))
            return

        if path == "/api/sync-history":
            try:
                added = sync_gateway_history()
                self._json(200, {"added": added})
            except Exception as exc:
                self._err(500, str(exc))
            return

        if path == "/api/image":
            self._handle_image(payload, edit=False)
            return

        if path == "/api/edit":
            self._handle_image(payload, edit=True)
            return

        if path == "/api/video":
            self._handle_video(payload)
            return

        if path.startswith("/api/video/") and path.endswith("/cancel"):
            task_id = urllib.parse.unquote(
                path[len("/api/video/"):-len("/cancel")]).strip("/")
            self._handle_cancel(task_id)
            return

        if path.startswith("/api/job/") and path.endswith("/save"):
            job_id = urllib.parse.unquote(
                path[len("/api/job/"):-len("/save")]).strip("/")
            self._handle_resave(job_id)
            return

        self._err(404, "not found")

    # ------------------------------------------------------------ media

    def _handle_image(self, payload, edit):
        try:
            prompt = payload.get("prompt")
            model = payload.get("model")
            size = payload.get("size") or "1024x1024"
            if not isinstance(prompt, str) or not prompt.strip():
                raise ValueError("prompt 必须是非空字符串")
            if not isinstance(model, str) or not model.strip():
                raise ValueError("model 必须是非空字符串")
            if not isinstance(size, str):
                raise ValueError("size 必须是字符串")
            if edit and not isinstance(payload.get("image"), list):
                raise ValueError("image 必须是图片数组")
        except ValueError as exc:
            self._err(400, str(exc))
            return
        kind = "edit" if edit else "generate"
        job = new_job(type="image", model=model, prompt=prompt, status="running",
                      request={"kind": "edit" if edit else "image", "model": model,
                               "prompt": prompt, "size": size,
                               "images": bool(payload.get("image"))})
        slog("info", "提交%s：%s | %s" % ("改图" if edit else "生图", model,
                                          prompt[:40]))
        audit("image_submit", "%s | %s | %s" % ("edit" if edit else "image",
                                                 model, prompt[:120]))
        if edit:
            body = {"model": model, "prompt": prompt, "size": size,
                    "image": payload.get("image") or [], "n": 1,
                    "response_format": "url"}
            status, _, data = gateway("/v1/images/edits", body=body, timeout=600)
        else:
            body = {"model": model, "prompt": prompt, "size": size,
                    "n": 1, "response_format": "url"}
            status, _, data = gateway("/v1/images/generations", body=body, timeout=600)
        if status != 200:
            msg = _error_message(data)
            update_job(job["id"], status="failed", error=msg)
            slog("err", "%s失败: %s" % ("改图" if edit else "生图", msg))
            self._send(status, data)
            return
        try:
            obj = json.loads(data.decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("上游返回不是 JSON 对象")
            item = extract_image(obj)
            if not isinstance(item, dict):
                raise ValueError("上游 data[0] 不是对象")
        except Exception as exc:
            msg = "上游返回格式异常: %s" % exc
            update_job(job["id"], status="failed", error=msg)
            slog("err", "%s失败: %s" % ("改图" if edit else "生图", msg))
            self._json(502, {"error": {"message": msg}, "job_id": job["id"]})
            return
        source_url = item.get("url") if isinstance(item.get("url"), str) else None
        if source_url:
            source_url = source_url[:4096]
        try:
            path, name = save_image_result(item, prompt, "edit" if edit else "image")
            obj["saved_path"] = path
            obj["saved_name"] = name
            obj["saved_url"] = file_url(name)
            update_job(job["id"], status="completed", credit=obj.get("credit"),
                       path=path, filename=name,
                       source_url=source_url,
                       save_dir_used=os.path.dirname(path))
            slog("ok", "图片已保存: %s（积分 %s）" % (name, obj.get("credit")))
        except Exception as exc:
            update_job(job["id"], status="completed", credit=obj.get("credit"),
                       save_error=str(exc), source_url=source_url)
            obj["saved_error"] = str(exc)
            slog("err", "图片保存失败: %s" % exc)
        obj["job_id"] = job["id"]
        self._json(200, obj)

    def _handle_video(self, payload):
        try:
            model = payload.get("model")
            prompt = payload.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                raise ValueError("prompt 必须是非空字符串")
            if not isinstance(model, str) or not model.strip():
                raise ValueError("model 必须是非空字符串")
            seconds = payload.get("seconds") or 5
            if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
                raise ValueError("seconds 必须是数字")
        except ValueError as exc:
            self._err(400, str(exc))
            return
        body = {"model": model, "prompt": prompt, "seconds": seconds}
        for key in ("resolution", "aspect_ratio", "negative_prompt", "enable_audio"):
            if payload.get(key) not in (None, ""):
                body[key] = payload[key]
        for key in ("image", "last_image"):
            if payload.get(key):
                body[key] = payload[key]
        if payload.get("reference_images"):
            body["reference_images"] = payload["reference_images"]
        job = new_job(type="video", model=model, prompt=prompt, status="queued",
                      request={"kind": "video", "model": model, "prompt": prompt,
                               "seconds": body["seconds"],
                               "resolution": body.get("resolution"),
                               "aspect_ratio": body.get("aspect_ratio"),
                               "negative_prompt": body.get("negative_prompt"),
                               "has_image": bool(body.get("image")),
                               "has_last": bool(body.get("last_image")),
                               "ref_count": len(body.get("reference_images") or [])})
        slog("info", "提交视频：%s %s 秒 | %s" % (model, body["seconds"], prompt[:40]))
        audit("video_submit", "%s | %ss | %s" % (model, body["seconds"], prompt[:120]))
        status, _, data = gateway("/v1/videos", body=body, timeout=300)
        if status not in (200, 201, 202):
            msg = _error_message(data)
            update_job(job["id"], status="failed", error=msg)
            slog("err", "视频提交失败: %s" % msg)
            self._send(status, data)
            return
        try:
            obj = json.loads(data.decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("上游返回不是 JSON 对象")
        except Exception as exc:
            msg = "上游返回格式异常: %s" % exc
            update_job(job["id"], status="failed", error=msg)
            self._json(502, {"error": {"message": msg}, "job_id": job["id"]})
            return
        task_id = obj.get("id")
        if task_id:
            task_id = str(task_id)
            st = normalize_status(obj.get("status") or "queued")
            update_job(job["id"], task_id=task_id, status=st,
                       request=dict(job["request"], task_id=task_id))
            start_watcher(job["id"])
            obj["status"] = st
            obj["job_id"] = job["id"]
        else:
            update_job(job["id"], status="failed", error="上游未返回任务 ID")
            obj["error"] = {"message": "上游未返回任务 ID"}
            obj["job_id"] = job["id"]
        self._json(status, obj)

    def _handle_cancel(self, task_id):
        task_id = str(task_id or "").strip()
        if not task_id:
            self._err(400, "缺少任务 ID")
            return
        status, _, data = gateway(
            "/v1/videos/%s/cancel" % urllib.parse.quote(task_id, safe=""),
            method="POST", timeout=30)
        if status not in (200, 202):
            self._send(status, data)
            return
        job = find_job_by_task(task_id)
        if job:
            update_job(job["id"], status="cancelled", error="已取消")
            slog("warn", "已取消视频任务: %s" % task_id)
            audit("video_cancel", task_id)
        self._send(status, data)

    def _handle_resave(self, job_id):
        job = find_job(job_id)
        if not job:
            self._err(404, "任务不存在")
            return
        if job.get("status") in ACTIVE_STATUSES:
            self._err(409, "任务仍在进行中，不能重试保存")
            return
        try:
            if job.get("type") == "video" and job.get("task_id"):
                path, name, used = save_video(job["task_id"], job.get("prompt") or "")
                update_job(job_id, path=path, filename=name, save_dir_used=used,
                           save_error=None)
                slog("ok", "重新保存视频: %s" % name)
            elif job.get("type") == "image" and job.get("source_url"):
                item = {"url": job["source_url"]}
                path, name = save_image_result(
                    item, job.get("prompt") or "",
                    "edit" if (job.get("request") or {}).get("kind") == "edit" else "image")
                update_job(job_id, path=path, filename=name,
                           save_dir_used=os.path.dirname(path), save_error=None)
                slog("ok", "重新保存图片: %s" % name)
            else:
                raise RuntimeError("没有可用的源文件或链接")
            updated = find_job(job_id) or {}
            self._json(200, {"ok": True, "filename": updated.get("filename"),
                             "url": file_url(updated.get("filename") or "")})
        except Exception as exc:
            self._err(500, str(exc))


class StudioServer(ThreadingHTTPServer):
    allow_reuse_address = False


def _already_running():
    try:
        resp = OPENER.open("http://127.0.0.1:%d/" % LISTEN[1], timeout=2)
        resp.read()
        return resp.status == 200
    except Exception:
        return False


def main():
    if not API_KEY:
        print("找不到可用的 API Key，请先在看板创建。")
        sys.exit(1)
    if _already_running():
        print("WorkBuddy 媒体工作台 已经在运行: http://127.0.0.1:%d/" % LISTEN[1])
        print("如需重启，先运行 media-studio-stop.cmd。")
        sys.exit(0)
    cfg = load_config()
    os.makedirs(cfg["save_dir"], exist_ok=True)
    LOG_ENTRIES.extend(load_logs())
    migrate_config()
    migrate_tags()
    load_jobs()
    slog("ok", "WorkBuddy 媒体工作台启动 · 保存目录 %s" % cfg["save_dir"])
    print("WorkBuddy 媒体工作台（Kusylit's Studio）")
    print("  http://127.0.0.1:%d/" % LISTEN[1])
    print("  网关 %s" % GATEWAY)
    print("  保存目录 %s" % cfg["save_dir"])
    StudioServer(LISTEN, Handler).serve_forever()


if __name__ == "__main__":
    main()
