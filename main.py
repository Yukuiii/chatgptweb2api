"""
standalone: ChatGPT CLI — generates sentinel tokens and holds an interactive conversation

Dependencies (pip): curl_cffi

Usage:
    python get_sentinel_token.py
    python get_sentinel_token.py --access-token <token> --model auto
"""

import argparse
import base64
import hashlib
import json
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any, Dict, Iterator, Optional, Sequence

import curl_cffi.requests as requests

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

BASE_URL = "https://chatgpt.com"
DEFAULT_POW_SCRIPT = f"{BASE_URL}/backend-api/sentinel/sdk.js"
CLIENT_VERSION = "prod-a194cd50d4416d3c0b47c740f206b12ce60f5887"
CLIENT_BUILD_NUMBER = "6708908"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
)
SEC_CH_UA = '"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"'

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _new_uuid() -> str:
    return str(uuid.uuid4())

# ---------------------------------------------------------------------------
# HTML bootstrap parser — extract script src list and data-build
# ---------------------------------------------------------------------------

class _ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.script_sources: list[str] = []
        self.data_build = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag != "script":
            return
        attrs_dict = dict(attrs)
        src = attrs_dict.get("src")
        if not src:
            return
        self.script_sources.append(src)
        match = re.search(r"c/[^/]*/_", src)
        if match:
            self.data_build = match.group(0)

def _parse_pow_resources(html: str) -> tuple[list[str], str]:
    parser = _ScriptSrcParser()
    parser.feed(html)
    sources = parser.script_sources or [DEFAULT_POW_SCRIPT]
    data_build = parser.data_build
    if not data_build:
        m = re.search(r'<html[^>]*data-build="([^"]*)"', html)
        if m:
            data_build = m.group(1)
    return sources, data_build

# ---------------------------------------------------------------------------
# proof-of-work
# ---------------------------------------------------------------------------

def _legacy_parse_time() -> str:
    now = datetime.now(timezone(timedelta(hours=-5)))
    return now.strftime("%a %b %d %Y %H:%M:%S") + " GMT-0500 (Eastern Standard Time)"

def _build_pow_config(
    user_agent: str,
    script_sources: Optional[Sequence[str]] = None,
    data_build: str = "",
) -> list[Any]:
    navigator_key = random.choice([
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
        "doNotTrack",
        "serial−[object Serial]",
        "pdfViewerEnabled−true",
        "language−zh-CN",
        "geolocation−[object Geolocation]",
        "userAgentData−[object NavigatorUAData]",
        "getUserMedia−function getUserMedia() { [native code] }",
        "sendBeacon−function sendBeacon() { [native code] }",
        "hardwareConcurrency−32",
        "windowControlsOverlay−[object WindowControlsOverlay]",
    ])
    window_key = random.choice([
        "0", "window", "self", "document", "name", "location",
        "customElements", "history", "navigation", "innerWidth", "innerHeight",
        "scrollX", "scrollY", "visualViewport", "screenX", "screenY",
        "outerWidth", "outerHeight", "devicePixelRatio", "screen", "chrome",
        "navigator", "onresize", "performance", "crypto", "indexedDB",
        "sessionStorage", "localStorage", "scheduler", "alert", "atob", "btoa",
        "fetch", "matchMedia", "postMessage", "queueMicrotask",
        "requestAnimationFrame", "setInterval", "setTimeout", "caches",
        "__NEXT_DATA__", "__BUILD_MANIFEST", "__NEXT_PRELOADREADY",
    ])
    document_keys = ["__reactContainer$fzelfjyxej8", "_reactListening5dehydibo78", "location"]
    cores = [8, 16, 24, 32]
    script_source = random.choice(list(script_sources)) if script_sources else None
    screen = [[1920, 1080], [1440, 900], [2560, 1440], [3840, 2160]]
    return [
        sum(random.choices(screen, k=1)[0]),
        _legacy_parse_time(),
        4294705152,
        1,
        user_agent,
        script_source,
        data_build,
        "en-US",
        "en-US,es-US,en,es",
        random.random(),
        navigator_key,
        random.choice(document_keys),
        window_key,
        time.perf_counter() * 1000,
        _new_uuid(),
        "",
        random.choice(cores),
        time.time() * 1000 - (time.perf_counter() * 1000),
        0, 0, 0, 0, 0, 0,
        0,  # 0 = edge/chrome, 1 = firefox
    ]

def _pow_generate(seed: str, difficulty: str, config: list[Any], limit: int = 500000) -> tuple[str, bool]:
    target = bytes.fromhex(difficulty)
    diff_len = len(difficulty) // 2
    seed_bytes = seed.encode()
    static_1 = (json.dumps(config[:3], separators=(",", ":"), ensure_ascii=False)[:-1] + ",").encode()
    static_2 = ("," + json.dumps(config[4:9], separators=(",", ":"), ensure_ascii=False)[1:-1] + ",").encode()
    static_3 = ("," + json.dumps(config[10:], separators=(",", ":"), ensure_ascii=False)[1:]).encode()
    for i in range(limit):
        final_json = static_1 + str(i).encode() + static_2 + str(i >> 1).encode() + static_3
        encoded = base64.b64encode(final_json)
        digest = hashlib.sha3_512(seed_bytes + encoded).digest()
        if digest[:diff_len] <= target:
            return encoded.decode(), True
    fallback = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + base64.b64encode(f'"{seed}"'.encode()).decode()
    return fallback, False

def _build_legacy_requirements_token(
    user_agent: str,
    script_sources: Optional[Sequence[str]] = None,
    data_build: str = "",
) -> str:
    config = _build_pow_config(user_agent, script_sources=script_sources, data_build=data_build)
    return "gAAAAAC" + base64.b64encode(
        json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode()
    ).decode()

def _build_proof_token(
    seed: str,
    difficulty: str,
    user_agent: str,
    script_sources: Optional[Sequence[str]] = None,
    data_build: str = "",
) -> str:
    config = _build_pow_config(user_agent, script_sources=script_sources, data_build=data_build)
    answer, solved = _pow_generate(seed, difficulty, config)
    if not solved:
        raise RuntimeError(f"failed to solve proof token: difficulty={difficulty}")
    return "gAAAAAB" + answer

# ---------------------------------------------------------------------------
# turnstile solver
# ---------------------------------------------------------------------------

class _OrderedMap:
    def __init__(self) -> None:
        self.keys: list[str] = []
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
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return ",".join(value)
    return str(value)

def _xor_string(text: str, key: str) -> str:
    if not key:
        return text
    return "".join(chr(ord(ch) ^ ord(key[i % len(key)])) for i, ch in enumerate(text))

def _solve_turnstile_token(dx: str, p: str) -> Optional[str]:
    try:
        decoded = base64.b64decode(dx).decode()
        token_list = json.loads(_xor_string(decoded, p))
    except Exception:
        return None

    process_map: Dict[Any, Any] = {}
    start_time = time.time()
    result = ""

    def func_1(e: float, t: float) -> None:
        process_map[e] = _xor_string(_turnstile_to_str(process_map[e]), _turnstile_to_str(process_map[t]))

    def func_2(e: float, t: Any) -> None:
        process_map[e] = t

    def func_3(e: str) -> None:
        nonlocal result
        result = base64.b64encode(e.encode()).decode()

    def func_5(e: float, t: float) -> None:
        current = process_map[e]
        incoming = process_map[t]
        if isinstance(current, (list, tuple)):
            process_map[e] = list(current) + [incoming]
            return
        if isinstance(current, (str, float)) or isinstance(incoming, (str, float)):
            process_map[e] = _turnstile_to_str(current) + _turnstile_to_str(incoming)
            return
        process_map[e] = "NaN"

    def func_6(e: float, t: float, n: float) -> None:
        tv = process_map[t]
        nv = process_map[n]
        if isinstance(tv, str) and isinstance(nv, str):
            value = f"{tv}.{nv}"
            process_map[e] = "https://chatgpt.com/" if value == "window.document.location" else value

    def func_7(e: float, *args: float) -> None:
        target = process_map[e]
        values = [process_map[arg] for arg in args]
        if isinstance(target, str) and target == "window.Reflect.set":
            obj, key_name, val = values
            obj.add(str(key_name), val)
        elif callable(target):
            target(*values)

    def func_8(e: float, t: float) -> None:
        process_map[e] = process_map[t]

    def func_14(e: float, t: float) -> None:
        process_map[e] = json.loads(process_map[t])

    def func_15(e: float, t: float) -> None:
        process_map[e] = json.dumps(process_map[t])

    def func_17(e: float, t: float, *args: float) -> None:
        call_args = [process_map[arg] for arg in args]
        target = process_map[t]
        if target == "window.performance.now":
            elapsed_ns = time.time_ns() - int(start_time * 1e9)
            process_map[e] = (elapsed_ns + random.random()) / 1e6
        elif target == "window.Object.create":
            process_map[e] = _OrderedMap()
        elif target == "window.Object.keys":
            if call_args and call_args[0] == "window.localStorage":
                process_map[e] = [
                    "STATSIG_LOCAL_STORAGE_INTERNAL_STORE_V4",
                    "STATSIG_LOCAL_STORAGE_STABLE_ID",
                    "client-correlated-secret",
                    "oai/apps/capExpiresAt",
                    "oai-did",
                    "STATSIG_LOCAL_STORAGE_LOGGING_REQUEST",
                    "UiState.isNavigationCollapsed.1",
                ]
        elif target == "window.Math.random":
            process_map[e] = random.random()
        elif callable(target):
            process_map[e] = target(*call_args)

    def func_18(e: float) -> None:
        process_map[e] = base64.b64decode(_turnstile_to_str(process_map[e])).decode()

    def func_19(e: float) -> None:
        process_map[e] = base64.b64encode(_turnstile_to_str(process_map[e]).encode()).decode()

    def func_20(e: float, t: float, n: float, *args: float) -> None:
        if process_map[e] == process_map[t]:
            target = process_map[n]
            if callable(target):
                target(*[process_map[arg] for arg in args])

    def func_21(*_: Any) -> None:
        return

    def func_23(e: float, t: float, *args: float) -> None:
        if process_map[e] is not None and callable(process_map[t]):
            process_map[t](*args)

    def func_24(e: float, t: float, n: float) -> None:
        tv = process_map[t]
        nv = process_map[n]
        if isinstance(tv, str) and isinstance(nv, str):
            process_map[e] = f"{tv}.{nv}"

    process_map.update({
        1: func_1, 2: func_2, 3: func_3, 5: func_5, 6: func_6,
        7: func_7, 8: func_8, 9: token_list, 10: "window",
        14: func_14, 15: func_15, 16: p, 17: func_17,
        18: func_18, 19: func_19, 20: func_20, 21: func_21,
        23: func_23, 24: func_24,
    })

    for token in token_list:
        try:
            fn = process_map.get(token[0])
            if callable(fn):
                fn(*token[1:])
        except Exception:
            continue
    return result or None

# ---------------------------------------------------------------------------
# result dataclass
# ---------------------------------------------------------------------------

@dataclass
class SentinelTokenResult:
    token: str
    proof_token: str = ""
    turnstile_token: str = ""
    so_token: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def as_headers(self) -> Dict[str, str]:
        h = {"OpenAI-Sentinel-Chat-Requirements-Token": self.token}
        if self.proof_token:
            h["OpenAI-Sentinel-Proof-Token"] = self.proof_token
        if self.turnstile_token:
            h["OpenAI-Sentinel-Turnstile-Token"] = self.turnstile_token
        if self.so_token:
            h["OpenAI-Sentinel-SO-Token"] = self.so_token
        return h

# ---------------------------------------------------------------------------
# session + bootstrap
# ---------------------------------------------------------------------------

def _build_session(access_token: str = "") -> requests.Session:
    session = requests.Session(impersonate="firefox133")
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Origin": BASE_URL,
        "Referer": BASE_URL + "/",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Priority": "u=1, I",
        "Sec-Ch-Ua": SEC_CH_UA,
        "Sec-Ch-Ua-Arch": '"x86"',
        "Sec-Ch-Ua-Bitness": '"64"',
        "Sec-Ch-Ua-Full-Version": '"143.0.3650.96"',
        "Sec-Ch-Ua-Full-Version-List": (
            '"Microsoft Edge";v="143.0.3650.96", '
            '"Chromium";v="143.0.7499.147", '
            '"Not A(Brand";v="24.0.0.0"'
        ),
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Model": '""',
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Ch-Ua-Platform-Version": '"19.0.0"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "OAI-Device-Id": _new_uuid(),
        "OAI-Session-Id": _new_uuid(),
        "OAI-Language": "zh-CN",
        "OAI-Client-Version": CLIENT_VERSION,
        "OAI-Client-Build-Number": CLIENT_BUILD_NUMBER,
    })
    if access_token:
        session.headers["Authorization"] = f"Bearer {access_token}"
    return session

def _bootstrap(session: requests.Session) -> tuple[list[str], str]:
    resp = session.get(
        BASE_URL + "/",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
        timeout=30,
    )
    resp.raise_for_status()
    sources, data_build = _parse_pow_resources(resp.text)
    return sources or [DEFAULT_POW_SCRIPT], data_build

def _fetch_sentinel(
    session: requests.Session,
    script_sources: list[str],
    data_build: str,
    access_token: str = "",
) -> SentinelTokenResult:
    p_token = _build_legacy_requirements_token(USER_AGENT, script_sources, data_build)

    path = "/backend-api/sentinel/chat-requirements/prepare"
    resp = session.post(
        BASE_URL + path,
        headers={"Content-Type": "application/json", "X-OpenAI-Target-Path": path, "X-OpenAI-Target-Route": path},
        json={"p": p_token},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    prepare_token = data.get("prepare_token", "")

    if (data.get("arkose") or {}).get("required"):
        raise RuntimeError("sentinel endpoint requires arkose token (not implemented)")

    proof_token = ""
    proof_info = data.get("proofofwork") or {}
    if proof_info.get("required"):
        proof_token = _build_proof_token(
            proof_info.get("seed", ""),
            proof_info.get("difficulty", ""),
            USER_AGENT,
            script_sources=script_sources,
            data_build=data_build,
        )

    turnstile_token = ""
    turnstile_info = data.get("turnstile") or {}
    if turnstile_info.get("required") and turnstile_info.get("dx"):
        turnstile_token = _solve_turnstile_token(turnstile_info["dx"], p_token) or ""

    path = "/backend-api/sentinel/chat-requirements/finalize"
    resp = session.post(
        BASE_URL + path,
        headers={"Content-Type": "application/json", "X-OpenAI-Target-Path": path, "X-OpenAI-Target-Route": path},
        json={"prepare_token": prepare_token, "proof_token": proof_token, "turnstile_token": turnstile_token},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    token = data.get("token", "")
    if not token:
        raise RuntimeError(f"missing sentinel token in response: {data}")

    return SentinelTokenResult(
        token=token,
        proof_token=proof_token,
        turnstile_token=turnstile_token,
        so_token=data.get("so_token", ""),
        raw=data,
    )

def get_sentinel_token(access_token: str = "") -> SentinelTokenResult:
    """Convenience: bootstrap + fetch sentinel token. Returns SentinelTokenResult."""
    session = _build_session(access_token)
    sources, data_build = _bootstrap(session)
    return _fetch_sentinel(session, sources, data_build, access_token)

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
            "developer_mode_connector_ids": [],
            "selected_sources": [],
            "selected_github_repos": [],
            "selected_all_github_repos": False,
            "serialization_metadata": {"custom_symbol_offsets": []},
        },
    }

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
    """Extract assistant text from a raw SSE event, accumulating into `current`."""
    # Full message snapshot (most events carry the whole text in message.content.parts)
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

    # JSON-patch style incremental updates
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

    # Plain string delta appended directly
    v = event.get("v")
    if isinstance(v, str) and not event.get("p") and not event.get("o") and current:
        return current + v

    return current

def _prepare_conversation(
    session: requests.Session,
    first_user_text: str,
    model: str,
    conversation_id: str = "",
    access_token: str = "",
) -> str:
    """POST /backend-api/f/conversation/prepare → conduit_token."""
    path = "/backend-api/f/conversation/prepare"
    tz = "Asia/Shanghai" if access_token else "America/Los_Angeles"
    tz_offset = -480 if access_token else 420
    body: Dict[str, Any] = {
        "action": "next",
        "fork_from_shared_post": False,
        "parent_message_id": "client-created-root",
        "model": model,
        "client_prepare_state": "none",
        "timezone_offset_min": tz_offset,
        "timezone": tz,
        "conversation_mode": {"kind": "primary_assistant"},
        "system_hints": [],
        "partial_query": {
            "id": _new_uuid(),
            "author": {"role": "user"},
            "content": {"content_type": "text", "parts": [first_user_text]},
        },
        "supports_buffering": True,
        "supported_encodings": ["v1"],
        "client_contextual_info": {"app_name": "chatgpt.com"},
    }
    if conversation_id:
        body["conversation_id"] = conversation_id
    resp = session.post(
        BASE_URL + path,
        headers={
            "Content-Type": "application/json",
            "Accept": "*/*",
            "X-Conduit-Token": "no-token",
            "X-OpenAI-Target-Path": path,
            "X-OpenAI-Target-Route": path,
        },
        json=body,
        timeout=60,
    )
    resp.raise_for_status()
    conduit_token = str(resp.json().get("conduit_token") or "")
    if not conduit_token:
        raise RuntimeError(f"missing conduit_token: {resp.text}")
    return conduit_token

def _stream_conversation(
    session: requests.Session,
    sentinel: SentinelTokenResult,
    conduit_token: str,
    messages: list[Dict[str, Any]],
    model: str,
    conversation_id: str = "",
    access_token: str = "",
) -> Iterator[tuple[str, str]]:
    """Yield (text_delta, conversation_id) until the stream ends."""
    path = "/backend-api/f/conversation"
    tz = "Asia/Shanghai" if access_token else "America/Los_Angeles"
    tz_offset = -480 if access_token else 420
    payload: Dict[str, Any] = {
        "action": "next",
        "messages": messages,
        "parent_message_id": "client-created-root",
        "model": model,
        "client_prepare_state": "success",
        "timezone_offset_min": tz_offset,
        "timezone": tz,
        "conversation_mode": {"kind": "primary_assistant"},
        "enable_message_followups": True,
        "system_hints": [],
        "supports_buffering": True,
        "supported_encodings": ["v1"],
        "client_contextual_info": {
            "is_dark_mode": False,
            "time_since_loaded": 120,
            "page_height": 900,
            "page_width": 1400,
            "pixel_ratio": 2,
            "screen_height": 1440,
            "screen_width": 2560,
            "app_name": "chatgpt.com",
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
        "X-OpenAI-Target-Path": path,
        "X-OpenAI-Target-Route": path,
        **sentinel.as_headers(),
    }

    resp = session.post(BASE_URL + path, headers=headers, json=payload, timeout=300, stream=True)
    resp.raise_for_status()

    current_text = ""
    active_cid = conversation_id

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
            if event.get("type") in ("stream_handoff", "resume_conversation_token"):
                continue
            cid = event.get("conversation_id") or ""
            if cid:
                active_cid = cid
            new_text = _extract_text(event, current_text)
            if new_text != current_text:
                yield new_text[len(current_text):], active_cid
                current_text = new_text
    finally:
        resp.close()

# ---------------------------------------------------------------------------
# interactive chat
# ---------------------------------------------------------------------------

def chat(access_token: str = "", model: str = "auto") -> None:
    mode = "authenticated" if access_token else "anonymous"
    print(f"[ChatGPT CLI]  model={model}  mode={mode}")
    print("Type a message and press Enter. Empty line or Ctrl-C to quit.\n")

    session = _build_session(access_token)

    print("Bootstrapping...", end=" ", flush=True)
    sources, data_build = _bootstrap(session)
    print("ok")

    conversation_id = ""
    history: list[Dict[str, Any]] = []

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not user_input:
            break

        history.append(_build_message(user_input))

        # Fresh sentinel token every turn (they are short-lived)
        try:
            sentinel = _fetch_sentinel(session, sources, data_build, access_token)
        except Exception as e:
            print(f"[sentinel error] {e}")
            break

        try:
            conduit_token = _prepare_conversation(
                session, user_input, model, conversation_id, access_token
            )
        except Exception as e:
            print(f"[prepare error] {e}")
            break

        print("Assistant: ", end="", flush=True)
        assistant_text = ""
        try:
            for delta, cid in _stream_conversation(
                session, sentinel, conduit_token, history, model, conversation_id, access_token
            ):
                print(delta, end="", flush=True)
                assistant_text += delta
                if cid:
                    conversation_id = cid
        except Exception as e:
            print(f"\n[stream error] {e}")
        finally:
            print()

        if assistant_text:
            history.append(_build_message(assistant_text, "assistant"))

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ChatGPT CLI powered by sentinel token generation")
    parser.add_argument("--access-token", default="", help="Bearer access token (omit for anonymous)")
    parser.add_argument("--model", default="auto", help="Model slug, e.g. gpt-4o, auto (default: auto)")
    parser.add_argument(
        "--token-only",
        action="store_true",
        help="Just print the sentinel token and exit (no interactive chat)",
    )
    args = parser.parse_args()

    if args.token_only:
        result = get_sentinel_token(access_token=args.access_token)
        print("=== SentinelTokenResult ===")
        print(f"token          : {result.token}")
        print(f"proof_token    : {result.proof_token or '(not required)'}")
        print(f"turnstile_token: {result.turnstile_token or '(not required)'}")
        print(f"so_token       : {result.so_token or '(not present)'}")
        print()
        print("=== Headers ===")
        for k, v in result.as_headers().items():
            print(f"{k}: {v}")
    else:
        chat(access_token=args.access_token, model=args.model)