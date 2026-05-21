# llm_scan_rules.yaml — 配置文件使用说明

## 概述

`llm_scan_rules.yaml` 是 `scan_llm.py` 的外部规则配置文件，包含扫描器四个阶段（Phase 0–3）的全部指纹规则、探测路径、并发参数和模型提取逻辑。修改此文件即可调整扫描行为，**无需改动任何 Python 代码**。

### 文件位置与加载优先级

```
scan_llm.py 启动时的配置解析顺序：

1. --config path/to/custom.yaml   ← 命令行指定文件（最高优先）
2. llm_scan_rules.yaml            ← 与 scan_llm.py 同目录（默认）
3. scan_config._build_hardcoded_default()  ← 纯 Python 兜底（文件缺失时）
```

使用示例：

```bash
# 使用默认配置（同目录的 llm_scan_rules.yaml）
python3 scan_llm.py --input targets.csv

# 使用自定义规则文件（如测试环境精简规则）
python3 scan_llm.py --input targets.csv --config rules_test.yaml
```

---

## 顶层结构

```yaml
version: 1       # schema 版本号，当前固定为 1

runtime: ...     # 并发、超时、重试等运行参数
phase0:  ...     # 非 HTTP 排除指纹
phase1:  ...     # LLM 指纹探测规则
phase2:  ...     # 部署工具识别规则
phase3:  ...     # 模型信息提取规则
```

---

## 一、runtime — 运行参数

控制各阶段的并发度、超时和重试，**不影响指纹逻辑**。

```yaml
runtime:
  phase0:
    concurrency: 500   # 同时处理的目标数
    timeout: 3         # 单次连接超时（秒）
    retries: 1         # 超时后重试次数
  phase1:
    concurrency: 300
    timeout: 5
  phase2:
    concurrency: 200
    timeout: 5
    max_extra_gets: 3  # Phase 2 每个目标最多可发起的额外 GET 请求数
  phase3:
    concurrency: 100
    timeout: 10
    retries: 1
```

**`max_extra_gets`** 是 Phase 2 的关键限流参数。每个目标在 Phase 2 中最多发起 3 次额外 GET（不包括 Phase 1 已缓存的路径），防止对每个目标发送过多请求。

**调优建议：**
- 网络条件差时降低并发（`concurrency`）和减小 `max_extra_gets`
- 目标响应慢时增大 `timeout`
- 减少 `retries` 可提升整体速度，轻微增加漏报率

---

## 二、phase0 — 非 HTTP 排除指纹

Phase 0 对每个 IP:Port 发送 `GET /`，收到响应后用此段配置过滤掉非 HTTP 协议，避免后续阶段在数据库、SSH 等协议上浪费时间。

### 2.1 non_http_prefixes

响应原始字节（raw bytes）以下列前缀开头则立即排除。

```yaml
phase0:
  non_http_prefixes:
    - "-ERR"      # Redis 错误回复
    - "+OK"       # Redis 内联 OK
    - "+PONG"     # Redis PING 响应
    - "SSH-2.0"   # SSH-2 协议握手
    - "* OK"      # IMAP 欢迎行
    - "* BYE"     # IMAP 告别行
    - "220 "      # SMTP/FTP 就绪（注意末尾有空格）
```

**添加新协议指纹：** 直接在列表中追加该协议 banner 的起始字节序列（UTF-8 字符串，引擎自动 encode）。

```yaml
    - "HTTP/1."   # 示例：若某协议会伪装成 HTTP 可用此排除特定版本
```

### 2.2 binary_threshold

响应前 512 字节中不可打印字符的占比阈值，超过则视为二进制协议（数据库、自定义协议等）排除。

```yaml
  binary_threshold: 0.30   # 30% 不可打印字节 → 排除
```

取值范围 `(0.0, 1.0)`。越小越严格（越多响应被排除）；越大越宽松。

---

## 三、phase1 — LLM 指纹探测

Phase 1 在 HTTP 存活的目标上依次探测多个路径，根据响应内容判定是否为 LLM 服务。

判定结果（`is_llm` 字段）：
- `确认` — 命中 API 特征，确实是 LLM 服务
- `疑似` — 只见到前端页面特征，可能是有 UI 的 LLM
- `否` — 未发现任何 LLM 特征

### 3.1 probe_paths — 探测路径（有序）

```yaml
phase1:
  probe_paths:
    - /v1/models      # 优先级 1：OpenAI 兼容 API
    - /api/tags       # 优先级 2：Ollama
    - /api/version    # 优先级 3：Ollama 版本
    - /info           # 优先级 4：TGI
    - /health         # 优先级 5：探测但无确认规则（见下）
    - /docs           # 优先级 6：Swagger/OpenAPI 文档
    - /               # 最后：检查前端页面特征
```

路径按列表顺序依次请求，**一旦命中「确认」规则立即停止**，不继续请求后续路径。`/` 的响应在 Phase 0 已缓存，此处直接复用，不重复请求。

**调整顺序：** 可将高命中率的路径上移以减少平均请求数。

**添加新路径：** 在列表中插入后，在 `confirm_rules` 中同时添加对应规则，否则该路径只会被请求但不会触发确认。

### 3.2 confirm_rules — 确认规则

每条规则将一个路径映射到一个匹配条件。条件满足（且状态码匹配）时，目标被标记为 `确认`。

```yaml
  confirm_rules:
    - path: /v1/models
      when_status: 200          # 200 | any
      match:
        type: json_all           # 所有子规则必须同时满足
        rules:
          - { field: object, op: eq, value: list }   # JSON["object"] == "list"
          - { field: data,   op: exists }             # JSON["data"] 存在

    - path: /api/tags
      when_status: 200
      match:
        type: json_has_key
        key: models              # JSON 顶层有 "models" 键

    - path: /docs
      when_status: any           # 任意状态码均检查 body
      match:
        type: body_substring_any
        values:
          - /v1/chat/completions
          - /v1/embeddings
          - /api/generate
```

**`when_status`** 取值：
- 整数（如 `200`）：仅当响应状态码等于该值时才执行匹配
- `any`：任意状态码均执行匹配

> **注意：`/health` 路径有意不设确认规则。** 该路径会被请求并缓存，但其响应过于通用（任何 Web 服务都可能返回 `{"status":"ok"}`），单独作为 LLM 确认依据容易误报。llama.cpp 的识别通过 Phase 2 的 `/props` 端点完成。

### 3.3 suspect — 疑似检测

当所有 API 路径均未确认，但 `GET /` 的响应 body 包含前端框架特征时，标记为 `疑似`。

```yaml
  suspect:
    keywords:                    # 任意一个关键词出现（大小写不敏感）即为疑似
      - gradio
      - streamlit
      - open-webui
      - __gradio_mode__
      - _stcore
    extra_predicates:            # 额外复合条件（满足任一即可）
      - type: body_all_substrings_ci
        values: [chat, model]    # body 中同时出现 "chat" 和 "model"
```

**`extra_predicates`** 支持所有 match type（见第六节），每条 predicate 与 keywords 是 OR 关系。

### 3.4 guards — 前端保护规则

解决「根页面明显是前端 UI，但同时有 `/api/version` 可访问」时的歧义：此时 `/api/version` 命中不应上升为「确认」，应降级为「疑似」。

```yaml
  guards:
    - description: "frontend UI overrides weak API-only signal"
      root_contains_any:              # 根页面 body 包含以下任一关键词
        - "open webui"
        - "open-webui"
        - "__gradio_mode__"
        - "gradio-app"
        - "_stcore"
        - "streamlit"
      downgrade_for_paths:            # 对这些路径的确认结果执行降级
        - /api/version
```

**执行时机：** 某个 confirm_rule 命中后立即检查所有 guards。若当前命中路径在 `downgrade_for_paths` 中，且根页面包含 `root_contains_any` 中的任一字符串，则将 `确认` 降级为 `疑似`。

---

## 四、phase2 — 部署工具识别

Phase 2 在 `确认` 和 `疑似` 目标上进一步识别具体使用的部署框架。

**核心规则：工具按列表顺序评估，第一个匹配成功即返回。** 因此列表顺序即优先级。

### 4.1 工具条目格式

```yaml
phase2:
  tools:
    - name: ollama               # deploy_tool 输出值
      scope: [confirmed]         # 适用范围：confirmed / suspect / 两者均有
      requires_cached_ok: /v1/models   # 可选：该路径必须已在缓存中且状态 200
      match:                     # 主匹配条件
        source: "cached:/api/tags"
        type: json_has_key
        key: models
      version_from:              # 可选：从此处提取 deploy_version
        source: "cached_or_get:/api/version"
        type: json_field
        field: version
      supplements:               # 可选：主匹配失败后依次尝试的补充探测
        - source: "get:/metrics"
          type: body_substring
          value: "vllm_"
```

**字段说明：**

| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | 是 | 匹配成功时写入 `deploy_tool` 列的值 |
| `scope` | 是 | `confirmed`、`suspect` 或两者皆有 |
| `match` | 是（`always` 除外） | 主匹配条件，含 `source` 和匹配逻辑 |
| `requires_cached_ok` | 否 | 前置条件：指定路径必须已在 Phase 1 缓存且状态码为 200；不满足则跳过此工具 |
| `version_from` | 否 | 主匹配成功后额外提取版本号，写入 `deploy_version` 列 |
| `supplements` | 否 | 主匹配失败时按序尝试的补充探测列表；每条有独立 `source` 和匹配逻辑 |

### 4.2 source 前缀语言

`match.source` 和 `supplements[].source` 决定如何获取用于匹配的响应体：

| 前缀格式 | 行为 | 是否消耗 extra_gets |
|----------|------|---------------------|
| `root` | 读取 Phase 0 缓存的 `GET /` 响应 | 否 |
| `cached:/path` | 读取 Phase 1 探测缓存，无则跳过 | 否 |
| `get:/path` | 总是发起新 GET 请求 | **是** |
| `cached_or_get:/path` | 有缓存则读缓存，否则发 GET | 仅缓存缺失时消耗 |

**`疑似` 目标限制：** `疑似` 目标只处理 `source: root` 的工具（纯缓存读取，不发新请求）。`confirmed` 目标处理全部工具。

### 4.3 requires_cached_ok 前置条件

用于将多个工具归入「同一入口」的逻辑组。当 `/v1/models` 在 Phase 1 返回 200 时，`requires_cached_ok: /v1/models` 的工具才会被尝试：

```
/v1/models 缓存 200 ──→ 尝试 vllm（owned_by 检查）
                    ──→ 尝试 vllm（/metrics 补充）
                    ──→ 尝试 llama.cpp（/props）
                    ──→ 尝试 fastchat（/docs）
                    ──→ 尝试 xinference（/docs）
                    ──→ 尝试 localai（/docs）
                    ──→ 兜底 未知-OpenAI兼容（always）
```

同时，当带有 `requires_cached_ok` 的工具最终匹配成功时，引擎会自动为该前置路径补充一条证据（证据去重，不会重复添加）。

### 4.4 添加新部署工具

在工具列表中插入一条记录，选择合适位置（即优先级）：

```yaml
    # 示例：添加 Triton Inference Server 的指纹
    - name: triton
      scope: [confirmed]
      match:
        source: "cached_or_get:/v2/health/ready"
        type: body_substring_ci
        value: '"ready":true'
```

---

## 五、phase3 — 模型信息提取

Phase 3 只处理 `确认` 目标，从缓存或主动 POST 中提取模型名称。

### 5.1 cache_sources — 缓存优先提取

按列表顺序检查 Phase 1/2 已缓存的路径，取第一个能提取出非空结果的源：

```yaml
phase3:
  cache_sources:
    - path: /v1/models
      extract:
        type: json_list_field    # 从列表字段中批量提取
        list_key: data           # JSON["data"] 是列表
        item_field: id           # 每项取 item["id"]

    - path: /api/tags
      extract:
        type: json_list_field
        list_key: models
        item_field: name

    - path: /info
      extract:
        type: json_field         # 提取单个字段
        field: model_id
```

### 5.2 post_probes — POST 主动探测

缓存源均无结果时，按序发送 POST 请求：

```yaml
  post_probes:
    - path: /v1/chat/completions
      method: POST
      body:                      # 请求 JSON body（原样序列化发送）
        model: test
        messages:
          - role: user
            content: hi
        max_tokens: 1
      on_success:                # 状态码在列表内 → 走此提取逻辑
        status: [200]
        extract:
          type: json_field
          field: model           # 从响应的 JSON["model"] 取模型名
      on_error:                  # 错误响应中往往包含可用模型列表
        status: [400, 404, 422]
        extract:
          type: error_regex
          regex: '"([a-zA-Z0-9_\-./: ]+)"'   # 正则捕获组
          filter:                              # 过滤候选值
            min_len: 3
            max_len: 80
            must_contain_any_char: ["/", ":", "-"]   # 至少含一个这样的字符
```

**`error_regex` filter 字段说明：**

| 字段 | 说明 |
|------|------|
| `min_len` | 捕获结果最小长度（不含边界，即 `>`） |
| `max_len` | 捕获结果最大长度（不含边界，即 `<`） |
| `must_contain_any_char` | 捕获结果必须包含列表中至少一个字符 |

### 5.3 fallback_literal

所有来源均无结果时写入 `model_info` 的占位值：

```yaml
  fallback_literal: "未知"
```

---

## 六、match type 完整参考

所有 `match.type` 和 `extract.type` 的取值由 `scan_config.py` 中的 `eval_match` / `extract_models` 函数解释。

### 匹配类型（用于 confirm_rules、phase2 match/supplements、suspect predicates）

#### 字符串匹配（操作解码后的 body 字符串）

| type | 必填字段 | 语义 |
|------|---------|------|
| `body_substring` | `value: str` | `value in body`（区分大小写） |
| `body_substring_ci` | `value: str` | `value.lower() in body.lower()`（不区分大小写） |
| `body_substring_any` | `values: [str]` | `any(v in body for v in values)` |
| `body_substring_any_ci` | `values: [str]` | 任一 value 不区分大小写出现在 body 中 |
| `body_all_substrings_ci` | `values: [str]` | 所有 value 均不区分大小写出现在 body 中 |
| `body_any_of` | `conditions: [match]` | 任一子条件（完整 match 对象）为真 |

#### JSON 匹配（操作解析后的 JSON 对象；body 无法解析则返回 false）

| type | 必填字段 | 语义 |
|------|---------|------|
| `json_has_key` | `key: str` | `key` 存在于 JSON 顶层 dict |
| `json_all_keys_exist` | `keys: [str]` | 所有 key 均存在于 JSON 顶层 dict |
| `json_field_eq` | `field: str`, `value: any` | `json[field] == value` |
| `json_nested_contains_ci` | `json_path: str`, `value: str` | 点分路径（如 `data.0.owned_by`）的值包含 value（不区分大小写） |
| `json_all` | `rules: [{field, op, value?}]` | 所有子规则同时满足；`op` 为 `exists`（存在）或 `eq`（等于） |

#### 其他

| type | 必填字段 | 语义 |
|------|---------|------|
| `raw_prefix` | `value: str` | 原始响应字节以 value 开头（Phase 0 专用） |
| `always` | — | 无条件返回 true（兜底匹配） |

### 提取类型（用于 phase3 cache_sources 和 post_probes）

| type | 必填字段 | 语义 |
|------|---------|------|
| `json_list_field` | `list_key: str`, `item_field: str` | `[item[item_field] for item in json[list_key]]` |
| `json_field` | `field: str` | `json[field]` 单值 |
| `error_regex` | `regex: str`, `filter?: {}` | 正则从错误消息字段提取，可选 filter 过滤 |

---

## 七、常见场景示例

### 场景 1：加快扫描速度

减少并发和超时，缩小 Phase 1 探测路径：

```yaml
runtime:
  phase0:
    concurrency: 200
    timeout: 2
    retries: 0
  phase1:
    concurrency: 150
    timeout: 3
  phase2:
    max_extra_gets: 1    # 减少额外请求

phase1:
  probe_paths:            # 只保留最高命中率的路径
    - /v1/models
    - /api/tags
    - /
```

### 场景 2：添加新 LLM 框架指纹（以 Triton Inference Server 为例）

在 `phase2.tools` 的合适位置插入（放在 tgi 之后）：

```yaml
    - name: triton
      scope: [confirmed]
      match:
        source: "cached_or_get:/v2/health/ready"
        type: body_substring_ci
        value: '"ready":true'
```

同时在 `phase1.confirm_rules` 添加该路径的确认规则，并在 `probe_paths` 中加入 `/v2/health/ready`。

### 场景 3：调低前端保护力度

若希望 `/api/version` + 前端页面也算「确认」，删除对应 guard 条目即可：

```yaml
phase1:
  guards: []    # 清空所有保护规则
```

### 场景 4：新增 Phase 0 协议排除（如 MySQL 握手）

```yaml
phase0:
  non_http_prefixes:
    - "-ERR"
    # ... 原有前缀 ...
    - "\x4a\x00\x00\x00"   # MySQL 握手包头（4 字节长度前缀，J=0x4a 表示 74 字节）
```

> 注意：YAML 不支持原始字节，复杂二进制前缀建议用 ASCII 可见字符部分或转换为 latin-1 字符串。

---

## 八、配置验证

启动时自动验证（`yaml.safe_load` 解析 + 数据类构造），配置格式错误时扫描器拒绝启动并打印详细错误：

```
$ python3 scan_llm.py --config bad_rules.yaml
Failed to load config: 'name'  ← 缺少必填字段 name
```

**手动验证：**

```bash
python3 -c "
from scan_config import load_config
from pathlib import Path
cfg = load_config(Path('llm_scan_rules.yaml'))
print('OK, version=%d, phase2 tools=%d' % (cfg.version, len(cfg.phase2.tools)))
"
```

---

## 九、文件与模块关系

```
llm_scan_rules.yaml       ← 本文件（人类可读规则，唯一修改入口）
        │
        ▼  yaml.safe_load
scan_config.py            ← 加载器 + 匹配引擎
  ├── load_config()       ← 解析 YAML → ScanConfig
  ├── get_default_config()← 优先读 YAML，回退硬编码
  ├── eval_match()        ← 12 种匹配算子
  └── extract_models()    ← 3 种提取算子
        │
        ▼  import
scan_llm.py               ← 主扫描器，Phase 0–3 均通过 cfg 读取规则
```

新增指纹 → 只改 `llm_scan_rules.yaml`  
新增匹配算子 → 同时改 `scan_config.py` 的 `eval_match`  
调整扫描流程 → 改 `scan_llm.py`
