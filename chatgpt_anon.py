"""
chatgpt_anon.py — ChatGPT 匿名(unauth)模式客户端

对齐 chatgpt.com 真实前端抓包链路(backend-anon)。相对通用实现的关键修正:

  1. PoW 算法: FNV-1a + murmur3 fmix32(32-bit hex),而非 sha3_512
     - answer = base64(JSON.stringify(config)) + "~S"
     - config[3] = nonce, config[9] = 经过毫秒数(非 nonce>>1)
     - difficulty 是 hex 字符串前缀字典序比较
  2. finalize 字段名: proofofwork / turnstile(非 proof_token / turnstile_token)
  3. 域名: backend-anon
  4. client 版本: prod-5e453451adb2de3afe642039d5230eb40e1f57b9 / build 7436895
  5. device-id 与 cookie oai-did 绑定,会话内稳定(指纹自洽)
  6. conversation: 去掉 partial_query,加 x-oai-turn-trace-id / no_auth_ad_preferences
     流请求的 x-openai-target-path 用 /backend-api/f/conversation(与 URL 的 backend-anon 不同,真实如此)

真实链路:
  POST /backend-anon/sentinel/chat-requirements/prepare   {p}
       -> prepare_token, proofofwork{seed,difficulty,required}, turnstile{required,dx}
  POST /backend-anon/sentinel/chat-requirements/finalize  {prepare_token, proofofwork, turnstile}
       -> token
  POST /backend-anon/f/conversation/prepare               -> conduit_token (JWT)
  POST /backend-anon/f/conversation  (SSE)                带 3 个 OpenAI-Sentinel-* 头

依赖: pip install curl_cffi
用法:
  python chatgpt_anon.py
  python chatgpt_anon.py --token-only
  python chatgpt_anon.py --model auto
"""

import argparse
import base64
import json
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, Dict, Iterator, Optional

import curl_cffi.requests as requests

# ---------------------------------------------------------------------------
# 常量(抓包对齐)
# ---------------------------------------------------------------------------

BASE_URL = "https://chatgpt.com"
ANON_API = BASE_URL + "/backend-anon"
CLIENT_VERSION = "prod-5e453451adb2de3afe642039d5230eb40e1f57b9"
CLIENT_BUILD_NUMBER = "7436895"
SENTINEL_SDK_FALLBACK = BASE_URL + "/backend-api/sentinel/sdk.js"

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) "
    "Gecko/20100101 Firefox/133.0"
)
# 重要:必须用 firefox133(或 safari)的 TLS 指纹。
# 实测 CF 对 chatgpt.com 的 Managed Challenge 放行 firefox/safari,
# 拦截所有 chrome* 指纹(chrome120/124/131/136 全 403)。
# Firefox 不发送 Sec-Ch-Ua 系列客户端提示,故不设置这些头。

# 会话级 device id,同步写入 cookie oai-did,保持指纹自洽
DEVICE_ID = str(uuid.uuid4())


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _utf8_b64(s: str) -> str:
    """UTF-8 safe base64,等价 JS: btoa(unescape(encodeURIComponent(s))) 或 TextEncoder+btoa"""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# PoW 哈希: FNV-1a + murmur3 fmix32(对应 sdk.js 的 hash 函数)
# 输出 8 位 hex,32-bit。注意:不是 sha3_512。
# ---------------------------------------------------------------------------

def _fnv1a_fmix32(text: str) -> str:
    h = 2166136261  # FNV offset basis
    for ch in text:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF  # Math.imul(h, 16777619) >>> 0
    # murmur3 fmix32 avalanche
    h ^= h >> 16
    h = (h * 2246822507) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 3266489909) & 0xFFFFFFFF
    h ^= h >> 16
    return format(h & 0xFFFFFFFF, "08x")


# ---------------------------------------------------------------------------
# 时间字符串(Date.toString() 风格,本地时区)
# ---------------------------------------------------------------------------

def _date_to_string() -> str:
    now = datetime.now()
    aware = now.astimezone()
    offset_sec = aware.utcoffset().total_seconds()
    sign = "+" if offset_sec >= 0 else "-"
    oh = int(abs(offset_sec) // 3600)
    om = int((abs(offset_sec) % 3600) // 60)
    tzname = aware.tzname() or ""
    return (
        now.strftime("%a %b %d %Y %H:%M:%S ")
        + f"GMT{sign}{oh:02d}{om:02d} ({tzname})"
    )


# ---------------------------------------------------------------------------
# PoW config(25 字段,对齐真实 p token / proof token 结构)
# 索引 [3] = nonce,[9] = elapsed_ms —— 求解时动态写入
# ---------------------------------------------------------------------------

_NAVIGATOR_KEYS = [
    "registerProtocolHandler−function registerProtocolHandler() { [native code] }",
    "storage−[object StorageManager]",
    "locks−[object LockManager]",
    "appCodeName−Mozilla",
    "permissions−[object Permissions]",
    "share−function share() { [native code] }",
    "webdriver−false",
    "managed−[object NavigatorManagedData]",
    "canShare−function canShare() { [native code] }",
    "vendor−Google Inc.",
    "mediaDevices−[object MediaDevices]",
    "vibrate−function vibrate() { [native code] }",
    "storageBuckets−[object StorageBucketManager]",
    "mediaCapabilities−[object MediaCapabilities]",
    "cookieEnabled−true",
    "virtualKeyboard−[object VirtualKeyboard]",
    "product−Gecko",
    "presentation−[object Presentation]",
    "onLine−true",
    "mimeTypes−[object MimeTypeArray]",
    "credentials−[object CredentialsContainer]",
    "serviceWorker−[object ServiceWorkerContainer]",
    "keyboard−[object Keyboard]",
    "gpu−[object GPU]",
    "serial−[object Serial]",
    "pdfViewerEnabled−true",
    "language−zh-CN",
    "geolocation−[object Geolocation]",
    "userAgentData−[object NavigatorUAData]",
    "getUserMedia−function getUserMedia() { [native code] }",
    "sendBeacon−function sendBeacon() { [native code] }",
    "hardwareConcurrency−32",
    "getGamepads−function getGamepads() { [native code] }",
    "getInterestGroupAdAuctionData−function getInterestGroupAdAuctionData() { [native code] }",
    "windowControlsOverlay−[object WindowControlsOverlay]",
]

_WINDOW_KEYS = [
    "__oai_so_t0", "closure_lm_203958", "onselectstart",
    "0", "window", "self", "document", "name", "location",
    "customElements", "history", "navigation", "innerWidth", "innerHeight",
    "scrollX", "scrollY", "visualViewport", "screenX", "screenY",
    "outerWidth", "outerHeight", "devicePixelRatio", "screen", "chrome",
    "navigator", "onresize", "performance", "crypto", "indexedDB",
    "sessionStorage", "localStorage", "scheduler", "alert", "atob", "btoa",
    "fetch", "matchMedia", "postMessage", "queueMicrotask",
    "requestAnimationFrame", "setInterval", "setTimeout", "caches",
    "__NEXT_DATA__", "__BUILD_MANIFEST", "__NEXT_PRELOADREADY",
]

_DOCUMENT_KEYS = ["location", "__reactContainer$fzelfjyxej8", "_reactListening5dehydibo78"]

_SCREENS = [[1920, 1080], [1440, 900], [2560, 1440], [3840, 2160], [1680, 1050]]
_CORES = [8, 10, 12, 16]


def _build_pow_config(
    user_agent: str,
    script_source: Optional[str],
    client_version: str,
) -> list:
    screen = random.choice(_SCREENS)
    return [
        sum(screen),                                    # 0  screen width + height
        _date_to_string(),                              # 1  Date.toString()
        4395630592,                                     # 2  magic
        1,                                              # 3  nonce(求解时覆盖)
        user_agent,                                     # 4
        script_source or SENTINEL_SDK_FALLBACK,         # 5  随机一个已加载 script src
        client_version,                                 # 6
        "zh-CN",                                        # 7
        "zh-CN,zh",                                     # 8
        0,                                              # 9  elapsed_ms(求解时覆盖)
        random.choice(_NAVIGATOR_KEYS),                 # 10
        random.choice(_DOCUMENT_KEYS),                  # 11
        random.choice(_WINDOW_KEYS),                    # 12
        time.perf_counter() * 1000,                     # 13
        _new_uuid(),                                    # 14
        "",                                             # 15
        random.choice(_CORES),                          # 16
        time.time() * 1000 - time.perf_counter() * 1000,  # 17
        0, 0, 0, 0, 0, 0, 0,                            # 18-24
    ]


# ---------------------------------------------------------------------------
# PoW 求解:返回 base64(json(config)) + "~S"(即 sdk.js 的 i + "~S")
# ---------------------------------------------------------------------------

def _solve_pow(seed: str, difficulty: str, config: list, limit: int = 500000) -> Optional[str]:
    if not difficulty:
        return None
    diff_len = len(difficulty)
    cfg = list(config)  # 拷贝,不动原 config
    start = time.perf_counter()
    for nonce in range(limit):
        cfg[3] = nonce
        cfg[9] = round((time.perf_counter() - start) * 1000)
        serialized = _utf8_b64(json.dumps(cfg, separators=(",", ":"), ensure_ascii=False))
        h = _fnv1a_fmix32(seed + serialized)
        if h[:diff_len] <= difficulty:  # hex 字符串前缀字典序比较
            return serialized + "~S"
    return None


def _build_requirements_token(config: list) -> str:
    """legacy p token: gAAAAAC + base64(json(config))"""
    return "gAAAAAC" + _utf8_b64(json.dumps(config, separators=(",", ":"), ensure_ascii=False))


def _build_proof_token(seed: str, difficulty: str, config: list) -> str:
    answer = _solve_pow(seed, difficulty, config)
    if answer is None:
        # sdk.js 求解失败 fallback: prefix + base64("e")
        return "gAAAAAB" + _utf8_b64("e")
    return "gAAAAAB" + answer


# ---------------------------------------------------------------------------
# turnstile 求解器(dx → atob → XOR(key) → JSON.parse → 字节码解释器)
# key 用 requirements token(p token)。复用自主流逆向实现。
# ---------------------------------------------------------------------------

class _OrderedMap:
    def __init__(self) -> None:
        self.keys: list = []
        self.values: Dict[str, Any] = {}

    def add(self, key: str, value: Any) -> None:
        if key not in self.values:
            self.keys.append(key)
        self.values[key] = value


def _turnstile_to_str(value: Any) -> str:
    if value is None:
        return "undefined"
    if isinstance(value, float):
        return str(value)
    if isinstance(value, str):
        special = {
            "window.Math": "[object Math]",
            "window.Reflect": "[object Reflect]",
            "window.performance": "[object Performance]",
            "window.localStorage": "[object Storage]",
            "window.Object": "function Object() { [native code] }",
            "window.Reflect.set": "function set() { [native code] }",
            "window.performance.now": "function () { [native code] }",
            "window.Object.create": "function create() { [native code] }",
            "window.Object.keys": "function keys() { [native code] }",
            "window.Math.random": "function random() { [native code] }",
        }
        return special.get(value, value)
    if isinstance(value, list) and all(isinstance(i, str) for i in value):
        return ",".join(value)
    return str(value)


def _xor_string(text: str, key: str) -> str:
    if not key:
        return text
    return "".join(chr(ord(ch) ^ ord(key[i % len(key)])) for i, ch in enumerate(text))


def _solve_turnstile(dx: str, key: str) -> Optional[str]:
    try:
        decoded = base64.b64decode(dx).decode()
        token_list = json.loads(_xor_string(decoded, key))
    except Exception:
        return None

    pm: Dict[Any, Any] = {}
    start_time = time.time()
    result = ""

    def f1(e, t): pm[e] = _xor_string(_turnstile_to_str(pm[e]), _turnstile_to_str(pm[t]))

    def f2(e, t): pm[e] = t

    def f3(e):
        nonlocal result
        result = base64.b64encode(e.encode()).decode()

    def f5(e, t):
        cur, inc = pm[e], pm[t]
        if isinstance(cur, (list, tuple)):
            pm[e] = list(cur) + [inc]; return
        if isinstance(cur, (str, float)) or isinstance(inc, (str, float)):
            pm[e] = _turnstile_to_str(cur) + _turnstile_to_str(inc); return
        pm[e] = "NaN"

    def f6(e, t, n):
        tv, nv = pm[t], pm[n]
        if isinstance(tv, str) and isinstance(nv, str):
            v = f"{tv}.{nv}"
            pm[e] = "https://chatgpt.com/" if v == "window.document.location" else v

    def f7(e, *args):
        target = pm[e]
        vals = [pm[a] for a in args]
        if isinstance(target, str) and target == "window.Reflect.set":
            obj, k, v = vals
            obj.add(str(k), v)
        elif callable(target):
            target(*vals)

    def f8(e, t): pm[e] = pm[t]

    def f14(e, t): pm[e] = json.loads(pm[t])

    def f15(e, t): pm[e] = json.dumps(pm[t])

    def f17(e, t, *args):
        ca = [pm[a] for a in args]
        target = pm[t]
        if target == "window.performance.now":
            pm[e] = (time.time_ns() - int(start_time * 1e9) + random.random()) / 1e6
        elif target == "window.Object.create":
            pm[e] = _OrderedMap()
        elif target == "window.Object.keys":
            if ca and ca[0] == "window.localStorage":
                pm[e] = [
                    "STATSIG_LOCAL_STORAGE_INTERNAL_STORE_V4",
                    "STATSIG_LOCAL_STORAGE_STABLE_ID",
                    "client-correlated-secret",
                    "oai/apps/capExpiresAt",
                    "oai-did",
                    "STATSIG_LOCAL_STORAGE_LOGGING_REQUEST",
                    "UiState.isNavigationCollapsed.1",
                ]
        elif target == "window.Math.random":
            pm[e] = random.random()
        elif callable(target):
            pm[e] = target(*ca)

    def f18(e): pm[e] = base64.b64decode(_turnstile_to_str(pm[e])).decode()

    def f19(e): pm[e] = base64.b64encode(_turnstile_to_str(pm[e]).encode()).decode()

    def f20(e, t, n, *args):
        if pm[e] == pm[t]:
            target = pm[n]
            if callable(target):
                target(*[pm[a] for a in args])

    def f21(*_): return

    def f23(e, t, *args):
        if pm[e] is not None and callable(pm[t]):
            pm[t](*args)

    def f24(e, t, n):
        tv, nv = pm[t], pm[n]
        if isinstance(tv, str) and isinstance(nv, str):
            pm[e] = f"{tv}.{nv}"

    pm.update({
        1: f1, 2: f2, 3: f3, 5: f5, 6: f6, 7: f7, 8: f8, 9: token_list, 10: "window",
        14: f14, 15: f15, 16: key, 17: f17, 18: f18, 19: f19, 20: f20, 21: f21, 23: f23, 24: f24,
    })

    for token in token_list:
        try:
            fn = pm.get(token[0])
            if callable(fn):
                fn(*token[1:])
        except Exception:
            continue
    return result or None


# ---------------------------------------------------------------------------
# HTML bootstrap: 解析首页 script src 列表 + data-build
# ---------------------------------------------------------------------------

class _ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.sources: list = []
        self.data_build = ""

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        d = dict(attrs)
        src = d.get("src")
        if not src:
            return
        self.sources.append(src)
        m = re.search(r"c/[^/]*/_", src)
        if m:
            self.data_build = m.group(0)


def _parse_resources(html: str):
    p = _ScriptSrcParser()
    p.feed(html)
    sources = p.sources or [SENTINEL_SDK_FALLBACK]
    data_build = p.data_build
    if not data_build:
        m = re.search(r'<html[^>]*data-build="([^"]*)"', html)
        if m:
            data_build = m.group(1)
    return sources, data_build


# ---------------------------------------------------------------------------
# session + bootstrap
# ---------------------------------------------------------------------------

def _proxy_from_env() -> Optional[str]:
    return (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("ALL_PROXY")
        or os.environ.get("HTTP_PROXY")
    )


def _build_session() -> requests.Session:
    proxy = _proxy_from_env()
    session_kwargs: Dict[str, Any] = {"impersonate": "firefox133"}
    if proxy:
        session_kwargs["proxies"] = {"http": proxy, "https": proxy}
    s = requests.Session(**session_kwargs)
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Origin": BASE_URL,
        "Referer": BASE_URL + "/",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "OAI-Device-Id": DEVICE_ID,
        "OAI-Language": "zh-CN",
        "OAI-Client-Version": CLIENT_VERSION,
        "OAI-Client-Build-Number": CLIENT_BUILD_NUMBER,
    })
    # device-id 同步到 cookie oai-did,保持指纹自洽
    s.cookies.set("oai-did", DEVICE_ID, domain="chatgpt.com")
    return s


def _bootstrap(session: requests.Session):
    resp = session.get(
        BASE_URL + "/",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
        },
        timeout=30,
    )
    resp.raise_for_status()
    sources, data_build = _parse_resources(resp.text)
    return sources or [SENTINEL_SDK_FALLBACK], data_build


def _target_headers(path: str) -> Dict[str, str]:
    return {"X-OpenAI-Target-Path": path, "X-OpenAI-Target-Route": path}


# ---------------------------------------------------------------------------
# sentinel prepare / finalize
# ---------------------------------------------------------------------------

@dataclass
class SentinelToken:
    token: str
    proof_token: str = ""
    turnstile_token: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


def _sentinel(
    session: requests.Session,
    script_source: Optional[str],
) -> SentinelToken:
    config = _build_pow_config(USER_AGENT, script_source, CLIENT_VERSION)
    p_token = _build_requirements_token(config)

    path = "/backend-anon/sentinel/chat-requirements/prepare"
    resp = session.post(
        ANON_API + "/sentinel/chat-requirements/prepare",
        headers={"Content-Type": "application/json", **_target_headers(path)},
        json={"p": p_token},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    prepare_token = data.get("prepare_token", "")

    if (data.get("arkose") or {}).get("required"):
        raise RuntimeError("arkose required (not supported)")

    # proof token 与 p token 复用同一份基础 config(仅 [3]nonce / [9]elapsed 不同)
    proof_token = ""
    pow_info = data.get("proofofwork") or {}
    if pow_info.get("required"):
        proof_token = _build_proof_token(
            pow_info.get("seed", ""),
            pow_info.get("difficulty", ""),
            config,
        )

    turnstile_token = ""
    ts_info = data.get("turnstile") or {}
    if ts_info.get("required") and ts_info.get("dx"):
        turnstile_token = _solve_turnstile(ts_info["dx"], p_token) or ""

    # finalize 字段名是 proofofwork / turnstile(抓包确认,非 proof_token / turnstile_token)
    path = "/backend-anon/sentinel/chat-requirements/finalize"
    resp = session.post(
        ANON_API + "/sentinel/chat-requirements/finalize",
        headers={"Content-Type": "application/json", **_target_headers(path)},
        json={
            "prepare_token": prepare_token,
            "proofofwork": proof_token,
            "turnstile": turnstile_token,
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get("token", "")
    if not token:
        raise RuntimeError(f"missing sentinel token: {data}")

    return SentinelToken(
        token=token,
        proof_token=proof_token,
        turnstile_token=turnstile_token,
        raw=data,
    )


# ---------------------------------------------------------------------------
# conversation
# ---------------------------------------------------------------------------

def _build_message(text: str, role: str = "user") -> Dict[str, Any]:
    return {
        "id": _new_uuid(),
        "author": {"role": role},
        "create_time": time.time(),
        "content": {"content_type": "text", "parts": [text]},
        "metadata": {
            "selected_github_repos": [],
            "selected_all_github_repos": False,
            "serialization_metadata": {"custom_symbol_offsets": []},
        },
    }


def _extract_slug(event: Dict[str, Any], current: str) -> str:
    """从 SSE 事件提取 resolved_model_slug(出现在 user message echo 的 metadata 里)。
    通常在 assistant 文字之前就到达,可用于 CLI 显示实际模型名。"""
    for cand in (event, event.get("v")):
        if isinstance(cand, dict):
            msg = cand.get("message")
            if isinstance(msg, dict):
                slug = (msg.get("metadata") or {}).get("resolved_model_slug")
                if isinstance(slug, str) and slug:
                    return slug
    if isinstance(event.get("v"), list):
        for item in event["v"]:
            if isinstance(item, dict):
                found = _extract_slug(item, "")
                if found:
                    return found
    return current


def _prepare_conversation(
    session: requests.Session,
    model: str,
    conversation_id: str = "",
) -> str:
    path = "/backend-anon/f/conversation/prepare"
    body: Dict[str, Any] = {
        "action": "next",
        "fork_from_shared_post": False,
        "parent_message_id": "client-created-root",
        "model": model,
        "client_prepare_state": "none",
        "timezone_offset_min": -480,
        "timezone": "Asia/Shanghai",
        "conversation_mode": {"kind": "primary_assistant"},
        "system_hints": [],
        "supports_buffering": True,
        "supported_encodings": ["v1"],
        "client_contextual_info": {"app_name": "chatgpt.com"},
    }
    if conversation_id:
        body["conversation_id"] = conversation_id

    resp = session.post(
        ANON_API + "/f/conversation/prepare",
        headers={
            "Content-Type": "application/json",
            "Accept": "*/*",
            "X-Conduit-Token": "no-token",
            **_target_headers(path),
        },
        json=body,
        timeout=60,
    )
    resp.raise_for_status()
    conduit_token = str(resp.json().get("conduit_token") or "")
    if not conduit_token:
        raise RuntimeError(f"missing conduit_token: {resp.text}")
    return conduit_token


def _iter_sse(response: Any) -> Iterator[str]:
    for raw_line in response.iter_lines():
        if not raw_line:
            continue
        line = raw_line.decode("utf-8", errors="ignore") if isinstance(raw_line, bytes) else str(raw_line)
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload:
            yield payload


def _extract_text(event: Dict[str, Any], current: str) -> str:
    for candidate in (event, event.get("v")):
        if not isinstance(candidate, dict):
            continue
        msg = candidate.get("message")
        if not isinstance(msg, dict):
            continue
        if (msg.get("author") or {}).get("role") != "assistant":
            continue
        parts = (msg.get("content") or {}).get("parts") or []
        text = "".join(p for p in parts if isinstance(p, str))
        if text:
            return text

    if event.get("p") == "/message/content/parts/0":
        op, v = event.get("o"), str(event.get("v") or "")
        if op == "append":
            return current + v
        if op == "replace":
            return v

    if event.get("o") == "patch" and isinstance(event.get("v"), list):
        text = current
        for item in event["v"]:
            if isinstance(item, dict):
                text = _extract_text(item, text)
        return text

    v = event.get("v")
    if isinstance(v, str) and not event.get("p") and not event.get("o") and current:
        return current + v

    return current


def _stream_conversation(
    session: requests.Session,
    sentinel: SentinelToken,
    conduit_token: str,
    messages: list,
    model: str,
    conversation_id: str = "",
) -> Iterator[tuple]:
    # 注意:URL 是 backend-anon,但 x-openai-target-path 用 /backend-api/f/conversation(抓包确认)
    path_target = "/backend-api/f/conversation"
    payload: Dict[str, Any] = {
        "action": "next",
        "messages": messages,
        "parent_message_id": "client-created-root",
        "model": model,
        "client_prepare_state": "success",
        "timezone_offset_min": -480,
        "timezone": "Asia/Shanghai",
        "conversation_mode": {"kind": "primary_assistant"},
        "enable_message_followups": True,
        "system_hints": [],
        "supports_buffering": True,
        "supported_encodings": ["v1"],
        "client_contextual_info": {
            "is_dark_mode": False,
            "time_since_loaded": 1080,
            "page_height": 919,
            "page_width": 1200,
            "pixel_ratio": 1,
            "screen_height": 1080,
            "screen_width": 1920,
            "app_name": "chatgpt.com",
        },
        "no_auth_ad_preferences": {
            "personalization_enabled": True,
            "history_enabled": True,
            "bazaar_consent_set": False,
        },
        "paragen_cot_summary_display_override": "allow",
        "force_parallel_switch": "auto",
    }
    if conversation_id:
        payload["conversation_id"] = conversation_id

    headers = {
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "X-Conduit-Token": conduit_token,
        "X-OAI-Turn-Trace-Id": _new_uuid(),
        "OAI-Telemetry": "[1,null]",
        "OpenAI-Sentinel-Chat-Requirements-Token": sentinel.token,
        "OpenAI-Sentinel-Proof-Token": sentinel.proof_token,
        "OpenAI-Sentinel-Turnstile-Token": sentinel.turnstile_token,
        **_target_headers(path_target),
    }

    resp = session.post(ANON_API + "/f/conversation", headers=headers, json=payload, timeout=300, stream=True)
    resp.raise_for_status()

    current_text = ""
    active_cid = conversation_id
    model_slug = ""
    try:
        for payload_str in _iter_sse(resp):
            if payload_str == "[DONE]":
                break
            try:
                event = json.loads(payload_str)
            except Exception:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("type") in ("stream_handoff", "resume_conversation_token", "delta_encoding"):
                continue
            cid = event.get("conversation_id") or ""
            if cid:
                active_cid = cid
            model_slug = _extract_slug(event, model_slug)
            new_text = _extract_text(event, current_text)
            if new_text != current_text:
                yield new_text[len(current_text):], active_cid, model_slug
                current_text = new_text
    finally:
        resp.close()


# ---------------------------------------------------------------------------
# 高层 API
# ---------------------------------------------------------------------------

def get_sentinel_token(session: Optional[requests.Session] = None) -> SentinelToken:
    own = session is None
    sess = session or _build_session()
    try:
        sources, _ = _bootstrap(sess)
        return _sentinel(sess, random.choice(sources))
    finally:
        if own:
            sess.close()


def ask(prompt: str, model: str = "auto") -> str:
    """单轮便捷调用:发一条消息,返回完整回复文本。"""
    session = _build_session()
    try:
        sources, _ = _bootstrap(session)
        script_source = random.choice(sources)
        sentinel = _sentinel(session, script_source)
        conduit = _prepare_conversation(session, model)
        messages = [_build_message(prompt)]
        chunks = []
        for delta, _cid, _slug in _stream_conversation(session, sentinel, conduit, messages, model):
            chunks.append(delta)
        return "".join(chunks)
    finally:
        session.close()


def chat(model: str = "auto") -> None:
    print(f"[ChatGPT 匿名]  model={model}")
    print("输入消息回车发送,空行或 Ctrl-C 退出。\n")

    session = _build_session()
    print("Bootstrap...", end=" ", flush=True)
    sources, _ = _bootstrap(session)
    print("ok")

    conversation_id = ""
    history: list = []

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not user_input:
            break

        history.append(_build_message(user_input))

        try:
            sentinel = _sentinel(session, random.choice(sources))
        except Exception as e:
            print(f"[sentinel error] {e}")
            break

        try:
            conduit = _prepare_conversation(session, model, conversation_id)
        except Exception as e:
            print(f"[prepare error] {e}")
            break

        assistant_text = ""
        header_done = False
        model_slug = ""
        try:
            for delta, cid, slug in _stream_conversation(
                session, sentinel, conduit, history, model, conversation_id
            ):
                if slug and not model_slug:
                    model_slug = slug
                if not header_done:
                    label = f"Assistant({model_slug})" if model_slug else "Assistant"
                    print(f"{label}: ", end="", flush=True)
                    header_done = True
                print(delta, end="", flush=True)
                assistant_text += delta
                if cid:
                    conversation_id = cid
        except Exception as e:
            if not header_done:
                print("Assistant: ", end="")
            print(f"\n[stream error] {e}")
        finally:
            if not header_done:
                print("Assistant: (无响应)")
            print()

        if assistant_text:
            history.append(_build_message(assistant_text, "assistant"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ChatGPT 匿名模式客户端")
    parser.add_argument("--model", default="auto", help="模型 slug,例如 auto / gpt-4o-mini(默认 auto)")
    parser.add_argument("--token-only", action="store_true", help="只获取并打印 sentinel token,不进入对话")
    parser.add_argument("--ask", default=None, help="单轮问答:直接返回该问题的回复")
    args = parser.parse_args()

    if args.token_only:
        r = get_sentinel_token()
        print("=== SentinelToken ===")
        print(f"token           : {r.token}")
        print(f"proof_token     : {r.proof_token or '(not required)'}")
        print(f"turnstile_token : {r.turnstile_token or '(not required)'}")
    elif args.ask:
        print(ask(args.ask, model=args.model))
    else:
        chat(model=args.model)
