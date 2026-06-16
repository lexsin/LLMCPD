# service

把原 `TEST/` 下的 IP→端口→LLM 指纹流水线脚本封装成常驻后台 server,用 SQL 表(`probe_task` / `probe_pending_resource` / `probe_host` / `probe_endpoint` / `probe_asset_port` / `asset_llm`)做输入输出。

设计文档见 [design.md](./design.md)。

## 工程布局

```
service/                              ← 工程根
├── README.md
├── design.md
├── requirements.txt
├── config.example.yaml
├── vendor/                           ← 原 TEST/ 下被复用的 4 个脚本 + 规则
│   ├── ip_port_scan.py
│   ├── scan_llm.py
│   ├── scan_config.py
│   ├── ip_ping_check.py
│   └── llm_scan_rules.yaml
└── llm_detect/                   ← Python 包
    ├── main.py                       # 入口 `python -m llm_detect.main`
    ├── settings.py                   # YAML → dataclass
    ├── db.py                         # MySQL 连接池
    ├── orchestrator.py               # 5s 轮询 → 抢占 → 串跑 4 阶段 → 收尾
    ├── http_api.py                   # 可选 wake/health
    ├── repo/                         # task / host / endpoint / asset
    ├── adapters/                     # nmap_runner / llm_prober(import vendor/)
    ├── stages/                       # stage1~stage4
    └── tests/                        # AST + 纯函数 smoke
```

`vendor/` 是从 `TEST/` 拷贝过来的快照,**与上游脚本同步时手工 diff/复制**(没有 git submodule)。

## 触发与回填一图流

```
平台前端                             service
  │  INSERT probe_task(PENDING)      │
  │  INSERT probe_pending_resource   │
  └──────────────►                   │
                                     │  每 5s 轮询 probe_task
                                     │  抢占 → 串跑 4 阶段
                                     │   ├ stage1: 展开 IP 段 → probe_host
                                     │   ├ stage2: ping(默认跳过) + nmap → probe_host.open_ports_json
                                     │   ├ stage3: 展开 → probe_endpoint
                                     │   └ stage4: scan_llm → probe_asset_port + UPSERT asset_llm
                                     │  收尾:probe_task.status = SUCCESS
```

## 安装

```bash
cd service
python -m venv .venv
.venv\Scripts\activate            # Windows
# Linux: source .venv/bin/activate
pip install -r requirements.txt
```

需要系统装好 `nmap`(命令行 `nmap` 在 PATH 里),Linux 下端口扫描需要 root 跑 SYN。

## 配置

```bash
cp config.example.yaml config.yaml
# 编辑 database / orchestrator / stages 段
```

## 启动

```bash
python -m llm_detect.main --config config.yaml
```

或开 HTTP wake/health 端点(`http_api.enabled: true`):

```bash
python -m llm_detect.main --config config.yaml --http
```

## 提交一个任务做端到端验证

```sql
-- 1) 创建任务
INSERT INTO probe_task (task_name, biz_date, param_json, status)
VALUES ('demo', CURDATE(), '{"nmapProfile":"DEFAULT_LLM_TOP200"}', 'PENDING');
SET @tid = LAST_INSERT_ID();

-- 2) 喂资源(支持 IP_SEGMENT / SINGLE_IP / IP_PORT)
INSERT INTO probe_pending_resource (task_id, resource_type, resource_value)
VALUES (@tid, 'SINGLE_IP', '127.0.0.1');

-- 3) 等 server 跑完
SELECT id, status, host_total, host_finished, endpoint_total, endpoint_finished, end_time
FROM probe_task WHERE id=@tid;

-- 4) 看资产
SELECT host_ip, port, asset_verdict, probe_shape, app_type_code
FROM probe_asset_port WHERE task_id=@tid;

SELECT host_ip, port, asset_verdict, detect_source, alive_status
FROM asset_llm
WHERE (host_ip, port) IN (SELECT host_ip, port FROM probe_asset_port WHERE task_id=@tid);
```

## 断点续跑

随时 `Ctrl+C`,重启后 server 会:

- 把 `RUNNING/SCANNING/PROBING` 状态的行重置回 `PENDING/PENDING_SCAN`(由 `orchestrator.reset_running_on_startup` 控制)
- 继续从最早未完成的 host / endpoint 开始

## nmap 调优(stage1_scan 段)

| 配置项 | 默认 | 作用 |
| --- | --- | --- |
| `skip_ping` | `true` | 跳过 ping,直接 nmap(默认开,因为运营商网段常屏蔽 ICMP) |
| `nmap_batch_size` | 100 | 每批扫描的 IP 数,0 表示不分批 |
| `nmap_parallel_workers` | 1 | 多进程并行扫批数;>1 时启 `ProcessPoolExecutor`,单批 segfault 不影响其他批 |
| `nmap_stats_every` | `60s` | nmap `--stats-every`,设为 `null` 关闭进度刷屏 |
| `nmap_anomaly_threshold` | 20 | 单 IP 开放端口数超过此值时视为异常,触发 `-sV --version-intensity 0` 复核(防火墙吞 SYN 的假阳性会扫出几十甚至上百端口);设 `0` 关闭 |
| `nmap_verify_workers` | 4 | 异常端口复核的线程并发数 |

异常端口复核流程沿用原脚本的 `verify_anomalous_ports`:对触发阈值的 IP 用 `-sV` 重扫已开端口,把 nmap 标为 `tcpwrapped` 的端口剔除掉。复核失败/超时时保留原 SYN 结果,不会把 IP 误判为完全无端口。

### 低开放率确认(low-open-confirm,默认关闭)

针对运营商低开放率大段(防火墙整段吞 SYN 的场景):一批扫完后,若开放 IP 占比 < 阈值或开放 IP 数 < 阈值,认为**整批被防火墙吃了**,触发抽样复扫。

| 配置项 | 默认 | 作用 |
| --- | --- | --- |
| `low_open_enabled` | `false` | 总开关。报备 IP 段一般用不到;扫运营商互联网段时建议开 |
| `low_open_rate_threshold` | `0.005` | 开放 IP 占比 < 0.5% 触发 |
| `low_open_min_open_ips` | `5` | 或开放 IP 数 < 5 触发 |
| `low_open_sample_size` | `50` | 抽样复扫的 IP 数 |
| `low_open_expand_rate_threshold` | `0.01` | 抽样新发现率 ≥ 1% 时扩到全批 |
| `low_open_extra_ports` | `""` | 扩展端口列表(逗号分隔),空=不扫扩展 |
| `low_open_min_rate` / `_max_retries` / `_host_timeout` | `1000`/`2`/`300s` | 复扫的 nmap 参数(比正常扫描更慢更准) |

执行顺序:**low-open-confirm → 异常端口复核 → 写 DB**(与原脚本 `make_flush_batch` 一致)。

## 手动模式(CSV 流水线,与 `TEST/` 体验一致)

`vendor/` 下的 4 个 .py 与 `TEST/` 完全一致(逐字节快照),自带 argparse 入口。需要单独跑某段 IP、不想入库时,直接命令行:

```bash
cd service

# 1) 展开 IP + 可选 ping
python vendor/ip_ping_check.py --data-dir data/x.xls --col-start START_IP --col-end END_IP --skip-ping

# 2) 端口扫描(488 端口)
sudo python vendor/ip_port_scan.py --input data/x_result.csv --batch-size 100 --resume

# 3) 端口展开
python vendor/expand_scan_ports.py --input data/x_result_scan_result.csv --output data/x_expanded.csv

# 4) LLM 指纹
python vendor/scan_llm.py --input data/x_expanded.csv --output data/x_llm.csv --resume
```

CLI 参数、cache.json(`port_scan_cache.json` / `llm_scan_checkpoint.jsonl`)、`--resume` 断点 —— 行为与 [`TEST/README.md`](../TEST/README.md) 描述完全一致。

**适用场景**:调试规则、临时扫一段不想入库、对比新旧 server 输出。

**不适用**:常规生产扫描(走后台 server,DB 触发)。

## 与原脚本的关系

- `vendor/scan_config.py` 与 `vendor/llm_scan_rules.yaml` 一字不动直接复用
- `vendor/ip_ping_check.py` 的 `expand_range / ping_one` 直接 import
- `vendor/scan_llm.py` 的 `phase0_protocol / phase1_fingerprint / phase2_deploy / phase3_model / TargetState / _apply_service_classification` 直接 import,跳过 `run_pipeline`(它绑了 CSV)
- `vendor/ip_port_scan.py` 的 `run_nmap_scan / verify_anomalous_ports / maybe_confirm_low_open_batch` 与 `NmapOptions / LowOpenConfirmConfig / SCAN_PORTS` 直接 import
- nmap 调用在 `llm_detect/adapters/nmap_runner.py` 里包了一层薄壳,接受 `List[ip]` 返回 `Dict[ip, List[port]]`,把 CSV 输入换成 DB 输出

## 同步上游

如果 `TEST/` 下的脚本有更新,需要把 `vendor/` 同步过来:

```bash
cp <upstream-test>/{ip_port_scan,scan_llm,scan_config,ip_ping_check}.py service/vendor/
cp <upstream-test>/llm_scan_rules.yaml                                   service/vendor/
```

变更后跑一次 smoke 验证 import 链没断:

```bash
python -m llm_detect.tests.smoke
```
