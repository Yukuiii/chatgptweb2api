# ChatGPT Sentinel SDK 参考源码

本目录存放从 chatgpt.com 抓取的 sentinel SDK 源码,用于逆向分析 `main.py` / `chatgpt_anon.py` 的 token 生成逻辑。

## 文件

- **`sentinel_sdk.js`** —— 来自 `https://chatgpt.com/sentinel/<版本>/sdk.js`(经 prettier 美化,非原始压缩版,行号便于阅读)。版本快照:`20260423af3c`(2026-06 抓取)。
  - 注意:真实入口 `/backend-api/sentinel/sdk.js` 只是 915 字节的 bootstrap stub,它会再注入 `/sentinel/<版本>/sdk.js` 才是完整实现。

## 关键位置(美化版行号)

| 逻辑 | 行号 | 说明 |
|---|---|---|
| **PoW 算法** | 352-369 | FNV-1a + murmur3 fmix32(32-bit hex),**不是 sha3_512**。`config[3]=nonce`、`config[9]=elapsed_ms`,answer = `base64(json(config)) + "~S"`,difficulty 是 hex 字符串前缀字典序比较 |
| **turnstile 求解器 `Et`**(`At` 解释器) | 657 | dx → atob → XOR(key) → JSON.parse → 字节码执行 |
| **turnstile 求解器 `Pn`**(`Cn` 解释器) | 1010 | 与 `At` 等价的平行实现,真正被 token() 调用 |
| **XOR 函数 `Rt` / `Rn`** | 648 / 1171 | `charCodeAt(o) ^ key.charCodeAt(o % len)` |
| **opcode 常量表** | 592-625 / 902-925 | `At` 与 `Cn` 两套,数值一致 |
| **token 打包 `ve`** | 1697 | `{p, t, c, id}` → JSON.stringify |

## 说明

- 这是 OpenAI 的客户端代码,仅作逆向研究 / 学习参考。
- 真实版本号(`20260423af3c`)会随站点更新而变化;本文件是某一时刻的快照。
- `chatgpt_anon.py` 的 PoW(FNV-1a)、proof 格式(`~S`)、turnstile 解释器均对照本文件实现并端到端验证通过。
