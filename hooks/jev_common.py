#!/usr/bin/env python3
"""Jev hook 共享工具：配置解析、HTTP 请求、安全缓存、state 预算控制与会话上下文管理。

PreToolUse / PostToolUse / Stop / 指令扫描共用此基础库。
"""

import collections
import hashlib
import json
import os
import re
import time
import urllib.request

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.claude/hooks/jev-gate.json")
DEFAULT_LOG_PATH = os.path.expanduser("~/Library/Logs/jev-gate.log")
DEFAULT_CACHE_DIR = os.path.expanduser("~/.cache/jev-gate")

CONFIG_PATH = os.environ.get("JEV_CONFIG_PATH", DEFAULT_CONFIG_PATH)
LOG_PATH = os.environ.get("JEV_LOG_PATH", DEFAULT_LOG_PATH)
CACHE_DIR = os.environ.get("JEV_CACHE_DIR", DEFAULT_CACHE_DIR)
UNTRUSTED_DIR = os.path.join(CACHE_DIR, "untrusted")

DEFAULTS = {
    "endpoint": "http://127.0.0.1:3425/v1/systemone",
    "token": "magpie",
    "model": "typesafe/jev-latest",
    "timeout": 8,
    "cache_seconds": 120,
    "post": {
        "enabled": True,
        "tools": ["WebFetch", "WebSearch", "Read", "Bash", "Grep", "Task", "mcp__*"],
        "min_chars": 300,
        "max_chars": 6000,
        "max_tokens": 8000,
        "directed_threshold": 0.60,
        "kind_threshold": 0.60,
        "cache_seconds": 600,
        "excerpt_chars": 1200,
    },
    "stop": {
        "enabled": True,
        "threshold": 0.70,
        "max_chars": 6000,
        "max_tokens": 8000,
        "max_tool_results": 8,
        "min_answer_chars": 60,
    },
    "instructions": {
        "enabled": True,
        "serious_threshold": 0.45,
        "unrelated_threshold": 0.80,
        "max_chars": 12000,
        "max_tokens": 12000,
        "cache_seconds": 86400,
        "max_skills": 200,
    },
    "user_prompt_count": 3,
    "user_prompt_chars": 600,
    "untrusted_count": 3,
    "untrusted_chars": 800,
}


def deep_merge(base, override):
    """递归合并配置，避免局部覆盖将整段默认值清除。"""
    out = json.loads(json.dumps(base))
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def resolve_config_path(explicit_path=None):
    """自适应查找配置文件路径。"""
    if explicit_path:
        return explicit_path
    if os.environ.get("JEV_CONFIG_PATH"):
        return os.environ["JEV_CONFIG_PATH"]
    # 查找脚本同级目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_cfg = os.path.join(script_dir, "jev-gate.json")
    if os.path.exists(local_cfg):
        return local_cfg
    # 查找上级 config 目录
    parent_cfg = os.path.join(os.path.dirname(script_dir), "config", "jev-gate.json")
    if os.path.exists(parent_cfg):
        return parent_cfg
    return DEFAULT_CONFIG_PATH


def load_config(path=None, defaults=None):
    target_path = resolve_config_path(path)
    cfg = json.loads(json.dumps(defaults or DEFAULTS))
    try:
        with open(target_path, encoding="utf-8") as f:
            cfg = deep_merge(cfg, json.load(f))
    except Exception:
        pass
    return cfg


def tool_wanted(tool, tools):
    for pattern in tools:
        if pattern == "*" or pattern == tool:
            return True
        if pattern.endswith("*") and tool.startswith(pattern[:-1]):
            return True
    return False


def truncate(value, limit):
    if isinstance(value, str):
        if len(value) <= limit:
            return value
        return value[:limit] + f"…[{len(value) - limit} chars elided]"
    if isinstance(value, dict):
        return {k: truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [truncate(v, limit) for v in value]
    return value


def head_tail(text, limit):
    """保留首尾，避免因过度截断漏掉隐藏在结尾的恶意指令。"""
    if len(text) <= limit:
        return text
    head = int(limit * 0.7)
    tail = limit - head
    marker = f"\n…[{len(text) - limit} chars elided]…\n"
    return text[:head] + marker + (text[-tail:] if tail else "")


def estimate_tokens(text):
    if not text:
        return 0
    ascii_n = sum(1 for ch in text if ord(ch) < 128)
    non_ascii = len(text) - ascii_n
    return int((ascii_n / 3.5 + non_ascii) * 1.1) + 1


def shrink_strings(value, factor):
    if isinstance(value, str):
        if len(value) <= 64:
            return value
        n = max(64, int(len(value) * factor))
        if n >= len(value):
            return value
        head = int(n * 0.8)
        tail = n - head
        marker = f"…[{len(value) - n} chars elided]…"
        return value[:head] + marker + (value[-tail:] if tail else "")
    if isinstance(value, dict):
        return {k: shrink_strings(v, factor) for k, v in value.items()}
    if isinstance(value, list):
        return [shrink_strings(v, factor) for v in value]
    return value


def fit_state(state, max_tokens):
    tokens = estimate_tokens(json.dumps(state, ensure_ascii=False))
    if tokens <= max_tokens:
        return state, tokens, False
    out = state
    factor = max_tokens / max(1, tokens)
    for _ in range(6):
        out = shrink_strings(out, factor * 0.85)
        tokens = estimate_tokens(json.dumps(out, ensure_ascii=False))
        if tokens <= max_tokens:
            break
        factor = max_tokens / max(1, tokens)
    return out, tokens, True


def cache_key(model, state, questions):
    raw = json.dumps(
        {"model": model, "state": state, "questions": questions},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get_cache_dir():
    return os.environ.get("JEV_CACHE_DIR", CACHE_DIR)


def cache_get(key, ttl, cache_dir=None):
    target_dir = cache_dir or get_cache_dir()
    path = os.path.join(target_dir, key + ".json")
    try:
        os.chmod(target_dir, 0o700)
        if time.time() - os.path.getmtime(path) <= ttl:
            with open(path, encoding="utf-8") as f:
                os.fchmod(f.fileno(), 0o600)
                return json.load(f)
    except Exception:
        pass
    return None


def cache_put(key, data, cache_dir=None):
    target_dir = cache_dir or get_cache_dir()
    os.makedirs(target_dir, mode=0o700, exist_ok=True)
    os.chmod(target_dir, 0o700)
    path = os.path.join(target_dir, key + ".json")
    tmp = path + f".{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def ask_jev(cfg, state, questions, timeout=None):
    body = json.dumps(
        {"model": cfg["model"], "state": state, "questions": questions},
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        cfg["endpoint"],
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {cfg['token']}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout or cfg["timeout"]) as r:
        return json.loads(r.read().decode("utf-8"))


def answer_noul(answers, key):
    return float(((answers.get("answers") or {}).get(key) or {}).get("noul") or 0)


def answer_score(answers, key):
    item = (answers.get("answers") or {}).get(key) or {}
    return float(item.get("score") or 0), float(item.get("confidence") or 0)


def answer_choice(answers, key):
    item = (answers.get("answers") or {}).get(key) or {}
    return item.get("choice") or "", item.get("probabilities") or {}


def get_log_path():
    return os.environ.get("JEV_LOG_PATH", LOG_PATH)


def log_entry(entry, log_path=None):
    target_path = log_path or get_log_path()
    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def print_json(obj):
    print(json.dumps(obj, ensure_ascii=False))


def safe_sid(session_id):
    sid = str(session_id or "default")
    return re.sub(r"[^A-Za-z0-9_.-]", "_", sid)[:120]


def session_path(kind, session_id):
    return os.path.join(get_cache_dir(), kind, safe_sid(session_id) + ".jsonl")


def read_jsonl_tail(path, max_lines):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = list(collections.deque(f, maxlen=max_lines))
    except Exception:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def append_jsonl(path, obj):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        os.chmod(path, 0o600)
    except Exception:
        pass


def read_untrusted(session_id, cfg):
    count = int(cfg.get("untrusted_count", 3))
    max_chars = int(cfg.get("untrusted_chars", 800))
    path = session_path("untrusted", session_id)
    out = []
    for item in reversed(read_jsonl_tail(path, max(count * 3, 10))):
        excerpt = item.get("excerpt") or ""
        if not excerpt:
            continue
        out.append(head_tail(excerpt, max_chars))
        if len(out) >= count:
            break
    return list(reversed(out))


def recent_user_prompts(payload, cfg):
    """只提取真实人类用户发送的 Prompt，剔除 tool_result 及 system-reminder。"""
    path = payload.get("transcript_path")
    if not path or not os.path.exists(path):
        return []
    count = int(cfg.get("user_prompt_count", 3))
    max_chars = int(cfg.get("user_prompt_chars", 600))
    out = []
    for event in reversed(read_jsonl_tail(path, 500)):
        text = ""
        if event.get("type") == "last-prompt":
            text = event.get("lastPrompt") or ""
        elif event.get("type") == "user":
            content = (event.get("message") or {}).get("content")
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text = "\n".join(
                    b.get("text", "")
                    for b in content
                    if isinstance(b, dict) and b.get("type") == "text"
                )
        if not text:
            continue
        text = re.sub(
            r"<system-reminder>.*?</system-reminder>", "", text, flags=re.DOTALL
        ).strip()
        if not text or text in out:
            continue
        out.append(text[:max_chars])
        if len(out) >= count:
            break
    return list(reversed(out))


def collect_text(value, out, depth=0):
    """递归收集工具返回结果中的文本，供 PostToolUse 扫描注入。"""
    if depth > 8:
        return
    if isinstance(value, str):
        if value:
            out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            collect_text(v, out, depth + 1)
    elif isinstance(value, list):
        for v in value:
            collect_text(v, out, depth + 1)
