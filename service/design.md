# LLM 探测后台 Server 设计(table 触发 → table 回填)

## 背景

原 `TEST/` 下的一组按文件流水的 Python 脚本(`ip_ping_check → ip_port_scan → expand_scan_ports → scan_llm`),输入是 CSV/XLS,中间产物是 CSV、JSON 缓存。

`运营商AI算力监测平台.sql` 提供了一套 IP 探测的业务表(`probe_task / probe_pending_resource / probe_host / probe_endpoint / probe_asset_port / probe_asset_ip / asset_llm`),已经按"任务—主机—端点—资产"分层,字段中带好了状态机。

本服务把这几个脚本封装成常驻后台 server:

- **触发**:平台/前端在 `probe_task` 插入一行 `status='PENDING'` 的任务,并在 `probe_pending_resource` 写入待探资源(IP 段 / 单 IP / IP+端口)
- **执行**:server 自动认领任务,跑完 4 个阶段(展开 → ping+nmap → 端点展开 → LLM 指纹)
- **回填**:所有中间与最终结果写回对应表(`probe_host` / `probe_endpoint` / `probe_asset_port` / `asset_llm`),`probe_task` 上更新进度与最终状态

工程独立打包于 `service/` 目录,**所需的原脚本被复制到 `service/vendor/`**,与上游 `TEST/` 解耦。

## 表 ↔ 脚本映射

| 阶段 | 原脚本 | 输入表 | 输出/更新表 | 进度字段 |
|---|---|---|---|---|
| 0 受理 | (新增 expander) | `probe_pending_resource` | `probe_host`(每 IP 一行,`host_phase=PENDING_SCAN`) | `probe_task.host_total` |
| 1 存活+端口 | `ip_ping_check` + `ip_port_scan` | `probe_host` WHERE `host_phase IN (PENDING_SCAN, SCANNING)` | `probe_host.open_ports_json / scan_start_time / scan_end_time / probe_info`,`host_phase → PROBING` 或 `VERDICT_DONE`(无端口) | `probe_task.host_finished` |
| 2 端点展开 | `expand_scan_ports` | `probe_host.open_ports_json`(`PROBING`)| `probe_endpoint`(每 ip:port 一行,`endpoint_status=PENDING`) | `probe_task.endpoint_total` |
| 3 LLM 指纹 | `scan_llm` | `probe_endpoint` WHERE `endpoint_status='PENDING'` | `probe_endpoint.endpoint_status / probe_*_time`,**写** `probe_asset_port`(指纹+判定),UPSERT 全局 `asset_llm` | `probe_task.endpoint_finished` |
| 4 收尾 | (新增 finalizer) | 上面 4 张表 | `probe_task.status = SUCCESS / PARTIAL / FAILED`,`probe_host.host_phase = VERDICT_DONE` | — |

`probe_host` / `probe_endpoint` 的状态字段已经覆盖原脚本的 cache(`port_scan_cache.json` / `llm_scan_checkpoint.jsonl`),DB 即真源——本地 JSON 缓存全部丢弃,断点续跑靠 SQL 查询「状态尚未推进的行」。

`probe_asset_ip` 是**人工复核表**(SQL 注释里都没提自动写入),server 不主动写。

## 推荐方案

### 触发方式:DB 轮询 + 可选 REST

- 主路径:server 每 5s 扫一次 `SELECT * FROM probe_task WHERE status='PENDING' ORDER BY id LIMIT N`,用 `UPDATE probe_task SET status='RUNNING'` 抢占式认领(行锁 + 状态条件保证多实例安全)
- 可选辅助:`POST /tasks/{id}/wake` HTTP 端点立即唤醒一次轮询
- 不引 MQ:DB 已是真源,5s 轮询足够

### 进程模型:单进程多阶段流水线

```
TaskOrchestrator (asyncio)
 ├─ Stage1Worker  ping + nmap   (executor,因为是子进程 + 阻塞 IO)
 ├─ Stage2Worker  端点展开       (executor,纯 SQL)
 └─ Stage3Worker  scan_llm      (asyncio + aiohttp)
```

每个 task 串行跑 4 阶段;阶段内部按 batch 并发。多任务并发上限 `max_concurrent_tasks=1`(默认串行)避免 nmap 撞机。

### 规则源:复用 `vendor/llm_scan_rules.yaml`

`vendor/scan_config.py` 与 YAML 一字不动,server 直接 `import scan_config` 复用现有匹配引擎。`config_llm_*` 三张配置表本期只供前端管理界面使用,不接入引擎。

### 状态/断点全部走 DB

抛弃所有本地 JSON 缓存。重启后:

- `SELECT FROM probe_host WHERE host_phase IN ('PENDING_SCAN','SCANNING')` 自动续扫
- `SELECT FROM probe_endpoint WHERE endpoint_status IN ('PENDING','RUNNING')` 自动续探
- `RUNNING` 状态视为「上次未完成」,启动时由 orchestrator 重置回 `PENDING/PENDING_SCAN`
- 幂等:`probe_asset_port` 用 `(task_id, host_ip, port)` 唯一键 UPSERT,`asset_llm` 用 `(host_ip, port)` 唯一键 UPSERT

## 目录结构

```
service/
├── README.md
├── design.md                  # 本文档
├── requirements.txt
├── config.example.yaml
├── vendor/                    # 原 TEST/ 脚本快照(只读复用)
│   ├── ip_port_scan.py
│   ├── scan_llm.py
│   ├── scan_config.py
│   ├── ip_ping_check.py
│   └── llm_scan_rules.yaml
└── llm_detect/
    ├── __init__.py
    ├── main.py                # 入口
    ├── settings.py            # 加载 config.yaml
    ├── db.py                  # 连接池
    ├── repo/                  # task/host/endpoint/asset
    ├── stages/                # stage1~stage4
    ├── adapters/              # nmap_runner / llm_prober
    └── http_api.py            # 可选 wake/health
```

### 核心复用点

- `vendor/scan_config.py` + `vendor/llm_scan_rules.yaml` 不动一个字符
- `from ip_ping_check import expand_range, ping_one`(经 `bootstrap_test_path()` 注入 `sys.path` 后可直接 import)
- `vendor/scan_llm.py` 里的 `phase0_protocol / phase1_fingerprint / phase2_deploy / phase3_model / TargetState` 直接 import,跳过 `run_pipeline`(它绑了 CSV)
- nmap 调用在 `llm_detect/adapters/nmap_runner.py` 里写一份纯函数版本(接受 `List[ip]` 返回 `Dict[ip, List[port]]`),不依赖 `ip_port_scan.py` 的 argparse/CSV

## 关键 SQL

```sql
-- 抢占任务
UPDATE probe_task SET status='RUNNING', start_time=NOW(), updater=:worker, update_date=NOW()
WHERE id = (
  SELECT id FROM (
    SELECT id FROM probe_task WHERE status='PENDING' ORDER BY id LIMIT 1
  ) t
) AND status='PENDING';

-- 阶段1完成一个 host
UPDATE probe_host
SET host_phase = CASE WHEN :open_ports_json IS NULL OR JSON_LENGTH(:open_ports_json)=0
                      THEN 'VERDICT_DONE' ELSE 'PROBING' END,
    open_ports_json = :open_ports_json,
    scan_start_time = :start, scan_end_time = NOW(),
    probe_info = :probe_info
WHERE task_id=:task_id AND host_ip=:ip;

-- 阶段3 写 asset(UPSERT 保证幂等)
INSERT INTO probe_asset_port (task_id, host_ip, port, probe_shape, app_type_code,
                              asset_verdict, verdict_rule_json, fingerprint_json, detect_time)
VALUES (:task_id, :ip, :port, :shape, :app_type, :verdict, :rule, :fp, NOW())
ON DUPLICATE KEY UPDATE asset_verdict=VALUES(asset_verdict),
                        fingerprint_json=VALUES(fingerprint_json),
                        verdict_rule_json=VALUES(verdict_rule_json),
                        detect_time=NOW();

INSERT INTO asset_llm (host_ip, port, probe_shape, app_type_code, asset_verdict,
                       detect_source, fingerprint_json, verdict_rule_json, detect_time)
VALUES (:ip, :port, :shape, :app_type, :verdict, 'IP_PROBE', :fp, :rule, NOW())
ON DUPLICATE KEY UPDATE asset_verdict=VALUES(asset_verdict),
                        fingerprint_json=VALUES(fingerprint_json),
                        verdict_rule_json=VALUES(verdict_rule_json),
                        detect_source = IF(detect_source='REPORT_DETECT','BOTH',detect_source),
                        detect_time=NOW();
```

## 验证方式

1. **集成**:手工 `INSERT probe_task(status='PENDING')` + `INSERT probe_pending_resource(resource_type='IP_SEGMENT', resource_value='192.168.1.0/24')`,启动 server,观察:
   - `probe_host.host_phase` 由 `PENDING_SCAN→SCANNING→PROBING→VERDICT_DONE`
   - `probe_endpoint.endpoint_status` 由 `PENDING→RUNNING→SUCCESS`
   - `probe_task.status='SUCCESS'`,`asset_llm` 出现新增行
2. **断点**:跑到一半 Ctrl-C,重启 server,验证未完成行自动续跑,UPSERT 不重复
3. **对比**:同一段 IP 用旧脚本 CSV 流水线跑一遍,与 server 写入的 `asset_llm` 行做 diff,`asset_verdict` 应一致
