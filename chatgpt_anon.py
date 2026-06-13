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


def _solve_turnstile(
    dx: str,
    key: str,
    script_sources: Optional[list] = None,
) -> Optional[str]:
    """turnstile token 求解器 —— 完整对齐 sdk.js 的 Et/Pn 字节码解释器(opcode 0-35)。

    流程:dx → base64 → XOR(key) → JSON.parse 得指令队列 → 队列驱动解释器执行。
    浏览器对象(window/document/Math/Reflect/...)用"路径字符串 + special 映射 + 调用 dispatch"模拟,
    因为 Python 侧无真实 DOM。opcode 语义逐条对照 reference/sentinel_sdk.js 的 Et 函数(657-815 行)。

    XOR key = p token(requirements token)。已实测验证:
    真实 SDK 中 Pn(dx, req) 用 key = $(requirements) 做 XOR(见 sentinel_sdk.js:1015/1161),
    而 $(requirements) 的序列化结果就等于我们的 p token,故直接复用 p_token 一致。
    """
    try:
        decoded = base64.b64decode(dx).decode()
        token_list = json.loads(_xor_string(decoded, key))
    except Exception:
        return None

    pm: Dict[Any, Any] = {}
    start_time = time.time()
    box = {"result": None, "done": False}  # H(3) 成功 / V(4) 失败 写入

    _LOCALSTORAGE_KEYS = [
        "STATSIG_LOCAL_STORAGE_INTERNAL_STORE_V4",
        "STATSIG_LOCAL_STORAGE_STABLE_ID",
        "client-correlated-secret",
        "oai/apps/capExpiresAt",
        "oai-did",
        "STATSIG_LOCAL_STORAGE_LOGGING_REQUEST",
        "UiState.isNavigationCollapsed.1",
    ]

    def _to_str(v: Any) -> str:
        return _turnstile_to_str(v)

    def _to_num(v: Any) -> float:
        if isinstance(v, bool):
            return 1.0 if v else 0.0
        if isinstance(v, (int, float)):
            return float(v)
        try:
            return float(v)
        except (TypeError, ValueError):
            return float("nan")

    def _js_add(a: Any, b: Any) -> Any:
        """JS 的 +:两侧均数字(且非 bool)则加法,否则字符串拼接"""
        if isinstance(a, bool) or isinstance(b, bool):
            return _to_str(a) + _to_str(b)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a + b
        return _to_str(a) + _to_str(b)

    def _prop(obj: Any, k: Any) -> Any:
        """K/Q 的 obj[key]:字符串走路径拼接(window/document 等),容器走真实取值"""
        if obj is None:
            return None
        ks = _to_str(k)
        if isinstance(obj, str):
            joined = f"{obj}.{ks}"
            return "https://chatgpt.com/" if joined == "window.document.location" else joined
        if isinstance(obj, _OrderedMap):
            return obj.values.get(ks)
        if isinstance(obj, dict):
            return obj.get(ks)
        if isinstance(obj, list):
            try:
                return obj[int(k)]
            except (ValueError, IndexError):
                return None
        return f"{_to_str(obj)}.{ks}"

    def _call(target: Any, args: list) -> Any:
        """Y/ut/ot 的调用 dispatch:对 window.* 路径 special-case,否则 callable"""
        if isinstance(target, str):
            if target == "window.Math.random":
                return random.random()
            if target == "window.performance.now":
                return (time.time_ns() - int(start_time * 1e9) + random.random()) / 1e6
            if target == "window.Object.create":
                return _OrderedMap()
            if target == "window.Object.keys":
                a = args[0] if args else None
                if _to_str(a) == "window.localStorage":
                    return list(_LOCALSTORAGE_KEYS)
                if isinstance(a, _OrderedMap):
                    return list(a.keys)
                if isinstance(a, dict):
                    return list(a.keys())
                if isinstance(a, list):
                    return [str(i) for i in range(len(a))]
                return []
            if target == "window.Reflect.set":
                obj, kk, vv = (args + [None, None, None])[:3]
                if isinstance(obj, _OrderedMap):
                    obj.add(_to_str(kk), vv)
                return None
            if target == "window.btoa":
                return base64.b64encode(_to_str(args[0] if args else "").encode()).decode()
            if target == "window.atob":
                try:
                    return base64.b64decode(_to_str(args[0] if args else "")).decode()
                except Exception:
                    return ""
            if target == "window.JSON.stringify":
                try:
                    return json.dumps(args[0] if args else None)
                except Exception:
                    return "null"
            if target == "window.JSON.parse":
                try:
                    return json.loads(_to_str(args[0] if args else "null"))
                except Exception:
                    return None
            return None  # 其它未知 window 方法 → undefined
        if callable(target):
            try:
                return target(*args)
            except Exception:
                return None
        return None

    # ---- opcode 处理函数(逐条对齐 sdk.js Et)----
    def op0(*args):  # W(664): 递归求解子 dx,复用当前 key
        sub = args[0] if args else None
        if isinstance(sub, str) and sub:
            saved = pm.get(9)
            try:
                pm[9] = json.loads(_xor_string(base64.b64decode(sub).decode(), key))
                _run()
            except Exception:
                pass
            finally:
                pm[9] = saved

    def op1(n, e):  # z(665): XOR 两寄存器
        pm[n] = _xor_string(_to_str(pm.get(n)), _to_str(pm.get(e)))

    def op2(t, n):  # B(666): set 字面量(n 是值本身)
        pm[t] = n

    def op3(t):  # H(774): 成功 → btoa(t)
        if not box["done"]:
            box["done"] = True
            box["result"] = base64.b64encode(_to_str(t).encode()).decode()

    def op4(t):  # V(777): 失败 → btoa(t)
        if not box["done"]:
            box["done"] = True
            box["result"] = base64.b64encode(_to_str(t).encode()).decode()

    def op5(n, e):  # Z(667): 数组 push / JS +
        cur = pm.get(n)
        if isinstance(cur, list):
            cur.append(pm.get(e))
        else:
            pm[n] = _js_add(cur, pm.get(e))

    def op6(n, e, r):  # K(690): obj[key]
        pm[n] = _prop(pm.get(e), pm.get(r))

    def op7(n, *e):  # Y(691): 调用 pm[n](pm[e_i]...)
        _call(pm.get(n), [pm.get(x) for x in e])

    def op8(n, e):  # X(715): copy
        pm[n] = pm.get(e)

    def op11(n, e):  # et(717): document.scripts 正则匹配取第一个 src
        pattern = _to_str(pm.get(e))
        found = None
        try:
            rx = re.compile(pattern)
        except re.error:
            rx = None
        for src in (script_sources or []):
            if rx and rx.search(src):
                found = src
                break
        pm[n] = found

    def op12(n):  # rt(725): 解释器自身
        pm[n] = pm

    def op13(n, e, *r):  # ot(707): try call(sdk 原样传 r,不 map 取值)
        try:
            _call(pm.get(e), list(r))
        except Exception:
            pm[n] = "error"

    def op14(n, e):  # ct(726): JSON.parse
        pm[n] = json.loads(_to_str(pm.get(e)))

    def op15(n, e):  # it(727): JSON.stringify(JS 语义:整数 float 去小数)
        v = pm.get(e)
        if isinstance(v, float) and v.is_integer():
            v = int(v)
        pm[n] = json.dumps(v)

    def op17(n, e, *r):  # ut(692): async try call,结果存 pm[n]
        try:
            pm[n] = _call(pm.get(e), [pm.get(x) for x in r])
        except Exception as ex:
            pm[n] = str(ex)

    def op18(n):  # at(728): atob
        pm[n] = base64.b64decode(_to_str(pm.get(n))).decode()

    def op19(n):  # ft(729): btoa
        pm[n] = base64.b64encode(_to_str(pm.get(n)).encode()).decode()

    def op20(n, e, r, *o):  # dt(730): pm[n]===pm[e] 则调 pm[r]
        if pm.get(n) == pm.get(e):
            _call(pm.get(r), [pm.get(x) for x in o])

    def op21(n, e, r, o, *c):  # ht(731): abs(pm[n]-pm[e])>pm[r] 则调 pm[o]
        if abs(_to_num(pm.get(n)) - _to_num(pm.get(e))) > _to_num(pm.get(r)):
            _call(pm.get(o), [pm.get(x) for x in c])

    def op22(n, e):  # pt(747): 嵌套子队列执行
        saved = pm.get(9)
        pm[9] = list(e) if isinstance(e, list) else []
        try:
            _run()
        except Exception:
            pass
        pm[n] = _to_str(box["result"])
        pm[9] = saved

    def op23(n, e, *r):  # lt(734): pm[n] !== undefined 则调 pm[e]
        if pm.get(n) is not None:
            _call(pm.get(e), list(r))

    def op24(n, e, r):  # Q(735): obj[key].bind(obj) —— 路径模拟同 K
        pm[n] = _prop(pm.get(e), pm.get(r))

    def op25(*a):  # mt(763): noop
        pass

    def op26(*a):  # wt(762): noop
        pass

    def op27(n, e):  # yt(672): 数组移除 / 数值减
        cur = pm.get(n)
        if isinstance(cur, list):
            try:
                cur.remove(pm.get(e))
            except ValueError:
                pass
        else:
            pm[n] = _to_num(cur) - _to_num(pm.get(e))

    def op28(*a):  # gt(761): noop
        pass

    def op29(n, e, r):  # vt(677): 小于
        pm[n] = pm.get(e) < pm.get(r)

    def op30(t, n, e, r):  # bt(782): 创建闭包存 pm[t],调用时执行子队列返回 pm[n]
        is_arr = isinstance(r, list)
        params = (e if is_arr else []) or []
        body = (r if is_arr else e) or []

        def _closure(*args):
            saved = pm.get(9)
            if is_arr:
                for idx, reg in enumerate(params):
                    if idx < len(args):
                        pm[reg] = args[idx]
            pm[9] = list(body)
            try:
                _run()
            except Exception:
                pass
            res = pm.get(n)
            pm[9] = saved
            return res

        pm[t] = _closure

    def op33(n, e, r):  # kt(678): 乘法
        pm[n] = _to_num(pm.get(e)) * _to_num(pm.get(r))

    def op34(n, e):  # Ct(736): Promise.resolve(同步近似)
        pm[n] = pm.get(e)

    def op35(n, e, r):  # St(684): 除法(除 0 → 0)
        d = _to_num(pm.get(r))
        pm[n] = 0.0 if d == 0 else _to_num(pm.get(e)) / d

    # 数据寄存器:tt(9)=指令队列 / nt(10)=window / st(16)=XOR key;其余为 opcode 处理函数
    pm[9] = token_list
    pm[10] = "window"
    pm[16] = key
    pm.update({
        0: op0, 1: op1, 2: op2, 3: op3, 4: op4, 5: op5, 6: op6, 7: op7, 8: op8,
        11: op11, 12: op12, 13: op13, 14: op14, 15: op15, 17: op17, 18: op18,
        19: op19, 20: op20, 21: op21, 22: op22, 23: op23, 24: op24,
        25: op25, 26: op26, 27: op27, 28: op28, 29: op29, 30: op30,
        33: op33, 34: op34, 35: op35,
    })

    def _run():
        """Pt():队列驱动执行,直到队列空或 H/V 置 done"""
        while not box["done"]:
            queue = pm.get(9)
            if not isinstance(queue, list) or not queue:
                break
            instr = queue.pop(0)
            if not isinstance(instr, (list, tuple)) or not instr:
                continue
            op = instr[0]
            # op 可以是整数(固定 opcode 0-35)或浮点(动态寄存器,存之前 X 复制进去的函数)。
            # 例:[8,19.26,8] 把 X 函数存到 pm[19.26];后续 [19.26,...] 的 op=19.26 引用它。
            fn = pm.get(op)
            if callable(fn):
                try:
                    fn(*instr[1:])
                except Exception:
                    continue

    try:
        _run()
    except Exception:
        pass

    return box["result"]


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
    script_sources: Optional[list] = None,
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
        turnstile_token = _solve_turnstile(ts_info["dx"], p_token, script_sources=script_sources) or ""

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
        return _sentinel(sess, random.choice(sources), script_sources=sources)
    finally:
        if own:
            sess.close()


def ask(prompt: str, model: str = "auto") -> str:
    """单轮便捷调用:发一条消息,返回完整回复文本。"""
    session = _build_session()
    try:
        sources, _ = _bootstrap(session)
        script_source = random.choice(sources)
        sentinel = _sentinel(session, script_source, script_sources=sources)
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
            sentinel = _sentinel(session, random.choice(sources), script_sources=sources)
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
