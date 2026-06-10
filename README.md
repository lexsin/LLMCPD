# IP 资产扫描与 LLM 服务识别

本目录包含一套 Python 脚本：从 Excel/CSV 中的 IP 段展开、存活检测、端口扫描，到对开放端口进行 LLM/推理服务指纹识别。

脚本目录默认工作根路径为 `/home/lx`（即各脚本所在目录）；相对路径均相对于该目录解析，绝对路径可直接使用。

---

## 依赖与环境


| 组件                        | 用途                                                                  |
| ------------------------- | ------------------------------------------------------------------- |
| Python 3                  | 所有脚本                                                                |
| [nmap](https://nmap.org/) | 端口扫描（`ip_port_scan.py`、`ip_port_scan_sv.py`、`ip_full_port_scan.py`） |
| root / sudo               | SYN 扫描（`-sS`）需要                                                     |
| aiohttp                   | `scan_llm.py` 异步 HTTP 探测                                            |
| pyyaml                    | `scan_config.py` / `scan_llm.py` 规则配置                               |
| pandas + xlrd             | `ip_ping_check.py` 读取 `.xls`                                        |


```bash
pip install aiohttp pyyaml pandas xlrd
```

---

## 推荐流水线

```mermaid
flowchart LR
  xls[data/*.xls 或 CSV]
  ping[ip_ping_check.py]
  result1["*_result.csv"]
  port[ip_port_scan.py]
  scan_result["*_scan_result.csv"]
  expand[expand_scan_ports.py]
  expanded["每行 ip+port"]
  llm[scan_llm.py]
  llm_out["*_llm.csv"]
  xls --> ping --> result1 --> port --> scan_result --> expand --> expanded --> llm --> llm_out
```



**可选分支：**

- `ip_port_scan_sv.py`：对已扫描结果做 nmap 服务版本识别（`-sV`）
- `ip_full_port_scan.py`：对部分 IP 做全端口抽样扫描（`-p-`）

**库模块（无命令行）：** `scan_config.py` — 供 `scan_llm.py` 加载 YAML/内置指纹规则。

---

## 脚本一览


| 脚本                     | 功能简述                                     |
| ---------------------- | ---------------------------------------- |
| `ip_ping_check.py`     | 展开起止 IP，可选 ping，输出每 IP 一行                |
| `ip_port_scan.py`      | nmap 扫描 488 个常见/LLM 相关端口，合并 `open_ports` |
| `expand_scan_ports.py` | 将 `open_ports` 展开为每行一个 `(ip, port)`      |
| `scan_llm.py`          | 对 ip:port 做 HTTP 指纹，识别是否 LLM 及部署框架       |
| `ip_port_scan_sv.py`   | 对已有开放端口做 nmap 服务版本探测                     |
| `ip_full_port_scan.py` | 抽样全端口扫描，写入 `all_open_ports`              |
| `scan_config.py`       | 扫描规则配置与匹配引擎（被 `scan_llm.py` 引用）          |


---

## 1. ip_ping_check.py

将 Excel/CSV 中的 **起始 IP / 终止 IP** 展开为单 IP 行，并可对每个地址执行 ping。

### 输入

- `data/` 下 `.csv`、`.xls`、`.xlsx`，或 `--data-dir` 指定单个文件
- 列名由参数指定（默认 `START_IP`、`END_IP`）

### 输出

- 同目录（或 `--output-dir`）：`{原文件名}_result.csv`
- 列：`起始IP`、`终止IP`、`ip`、`ping`（可选 `接入单位` 等，取决于 `--col-unit`）

### 常用命令

```bash
# 处理 data 目录下全部表格
python3 ip_ping_check.py --data-dir data --col-start START_IP --col-end END_IP

# 只处理单个 xls
python3 ip_ping_check.py --data-dir data/990000762670.xls --col-start START_IP --col-end END_IP

# 只展开 IP，不 ping（供后续直接端口扫描）
python3 ip_ping_check.py --data-dir data/990000762670.xls --col-start START_IP --col-end END_IP --skip-ping

# 展开后按 IP 去重（多段重复 IP 只保留一行，适合直接给 ip_port_scan）
python3 ip_ping_check.py --data-dir data/990000762670.xls --col-start START_IP --col-end END_IP --skip-ping --dedup-ip
```

### 参数


| 参数             | 默认                | 说明                     |
| -------------- | ----------------- | ---------------------- |
| `--data-dir`   | `data`            | 输入目录或单个文件              |
| `--output-dir` | 与输入同目录            | 输出目录                   |
| `--col-start`  | `START_IP`        | 起始 IP 列名               |
| `--col-end`    | `END_IP`          | 终止 IP 列名               |
| `--col-unit`   | 无                 | 可选单位列，写入输出             |
| `--skip-ping`  | 关                 | 跳过 ping，`ping` 列为空     |
| `--dedup-ip`   | 关                 | 展开后对 IP 去重，每个 IP 只输出一行 |
| `--workers`    | `32`              | ping 并发线程数             |
| `--timeout`    | `4.0`             | 单次 ping 超时（秒）          |
| `--limit`      | 无                 | 每个文件只处理前 N 行源数据        |
| `--max-expand` | `256`             | 单段最多展开地址数，超出只保留首尾      |
| `--cache`      | `ping_cache.json` | ping 结果缓存              |


---

## 2. ip_port_scan.py

对 CSV 中 **每个唯一 IP** 用 nmap 扫描 **488 个指定端口**（非全端口），将开放端口写入 `open_ports`（分号分隔）。

- **IPv4 / IPv6 自动分扫**：IPv6 使用 `nmap -6`（两段串行：先 v4 再 v6）
- **分批扫描**：默认每批 100 IP，打印 IP 级进度与 ETA
- **每批落盘**：每批完成后更新 `port_scan_cache.json` 并重写输出 CSV
- `**--resume`**：跳过 cache 中已有记录，继续未扫 IP
- **多批并行**：`--parallel-workers N` 用进程池同时跑多批 nmap；落盘仍在主线程串行（与 resume 兼容）

### 输入

- CSV 需含列 `**ip`**（通常来自 `*_result.csv`）

### 输出

- 默认与输入同目录：`{输入文件名}_scan_result.csv`
- 在原有列基础上增加/更新 `**open_ports`**

### 常用命令

```bash
# 基本扫描
sudo python3 ip_port_scan.py --input data/990000762670_result.csv

# 断点续扫（跳过 cache 中已有 IP，例如只补扫 IPv6）
sudo python3 ip_port_scan.py --input data/990000762670_result.csv --resume

# 指定输出、每批 200 IP
sudo python3 ip_port_scan.py \
  --input data/990000762670_result.csv \
  --output data/990000762670_scan_result.csv \
  --batch-size 200

# 多批并行（建议先试 2，观察网络/机器负载）
sudo python3 ip_port_scan.py \
  --input data/990000762670_result.csv \
  --batch-size 100 \
  --parallel-workers 2 \
  --resume
```

### 参数


| 参数                   | 默认                       | 说明                                       |
| -------------------- | ------------------------ | ---------------------------------------- |
| `--input`            | `IPs_1_result.csv`       | 输入 CSV                                   |
| `--output`           | `{stem}_scan_result.csv` | 输出 CSV（默认同目录）                            |
| `--xml`              | `scan.xml`               | 派生 `scan_v4.xml`、`scan_v6.xml`           |
| `--ip-list`          | `ips_scan.txt`           | 全量 IP 列表备份                               |
| `--cache`            | `port_scan_cache.json`   | 端口结果缓存（断点依据）                             |
| `--batch-size`       | `100`                    | 每批 IP 数；`0` 表示不分批                        |
| `--parallel-workers` | `1`                      | 并行 nmap 批次数；建议 2~4                       |
| `--merge-xml`        | 见说明                      | 强制合并批次 XML；默认 workers=1 合并，workers>1 不合并 |
| `--resume`           | 关                        | 跳过 cache 中已有 IP                          |
| `--stats-every`      | `60s`                    | nmap 进度统计间隔；`0` 关闭                       |
| `--skip-scan`        | 关                        | 不跑 nmap，仅从已有 XML 合并                      |
| `--keep-batch-files` | 关                        | 保留 `scan_v4_batch_*.xml` 等               |
| `--limit`            | 无                        | 只取前 N 个唯一 IP                             |


### 注意

- 必须使用 **sudo**（SYN 扫描）；并行子进程继承 root
- 扫描端口数量固定为 **488**（见脚本内 `SCAN_PORTS`）
- 中断后：cache 与 CSV 在每批结束后已更新，可用 `**--resume`** 继续
- `**--parallel-workers > 1`** 提高瞬时 SYN 压力；默认跳过大批量 XML 合并，需要时加 `**--merge-xml**`

---

## 3. expand_scan_ports.py

将 `open_ports`（`;` 分隔，兼容旧版 `,`）展开为 **每个开放端口一行**，供 `scan_llm.py` 使用。

### 输入 / 输出


| 输入列                | 输出列                              |
| ------------------ | -------------------------------- |
| `ip`, `open_ports` | `ip`, `port`（及原有单位/起止 IP/ping 等） |


无 `open_ports` 的行会跳过。

### 常用命令

```bash
python3 expand_scan_ports.py \
  --input  data/990000762670_result_scan_result.csv \
  --output data/990000762670_expanded.csv
```

### 参数


| 参数         | 默认                        | 说明         |
| ---------- | ------------------------- | ---------- |
| `--input`  | `IPs_1_result_scan.csv`   | 端口扫描结果 CSV |
| `--output` | `IPs_1_result_scan_2.csv` | 展开后的 CSV   |


---

## 4. scan_llm.py

对 **(ip, port)** 目标执行异步 HTTP 探测（Phase 0–3），识别是否为 LLM 服务、部署工具、模型信息等。

依赖 `[scan_config.py](scan_config.py)` 与可选的 `llm_scan_rules.yaml`。

### 输入

- CSV 必须含 `**ip`**、`**port`**（由 `expand_scan_ports.py` 生成）
- 仅对有意义的 HTTP/HTTPS 端口会得到完整识别；非 Web 端口通常在 Phase 0 被排除

### 输出列

`ip`, `port`, `protocol`, `is_llm`（确认/疑似/否）, `deploy_tool`, `deploy_version`, `model_info`, `evidence`, `link`, `scan_time`

### 常用命令

```bash
# 全量（目标多时耗时长，建议先 --limit 试跑）
python3 scan_llm.py \
  --input      data/990000762670_expanded.csv \
  --output     data/990000762670_llm.csv \
  --checkpoint data/990000762670_llm_checkpoint.jsonl

# 断点续跑
python3 scan_llm.py \
  --input      data/990000762670_expanded.csv \
  --output     data/990000762670_llm.csv \
  --checkpoint data/990000762670_llm_checkpoint.jsonl \
  --resume

# 小样本测试
python3 scan_llm.py --input data/990000762670_expanded.csv --output /tmp/llm_test.csv --limit 500
```

### 参数


| 参数              | 默认                          | 说明                  |
| --------------- | --------------------------- | ------------------- |
| `--input`       | `IPs_1_result_scan_2.csv`   | 含 ip、port 的 CSV     |
| `--output`      | `IPs_1_result_llm.csv`      | 结果 CSV              |
| `--checkpoint`  | `llm_scan_checkpoint.jsonl` | 已完成 ip:port 记录      |
| `--resume`      | 关                           | 跳过 checkpoint 中已有目标 |
| `--batch-size`  | `2000`                      | 流水线每批处理目标数          |
| `--concurrency` | 配置默认                        | 覆盖各阶段并发             |
| `--limit`       | 无                           | 只处理前 N 个目标          |
| `--config`      | 内置/YAML                     | 自定义规则文件路径           |


### 注意

- 展开后行数可能很大（例如 19k IP × 多端口 → 数十万行），请评估磁盘与时间
- 不需要 root

---

## 5. ip_port_scan_sv.py（可选）

在已有 `open_ports` 的基础上，按 **每个 IP 的开放端口** 执行 nmap `**-sV`** 服务版本探测，输出 `service` 列。

### 常用命令

```bash
sudo python3 ip_port_scan_sv.py \
  --input  data/990000762670_result_scan_result.csv \
  --output data/990000762670_scan_sv.csv
```

### 参数


| 参数            | 默认                        | 说明                   |
| ------------- | ------------------------- | -------------------- |
| `--input`     | `IPs_1_result_scan.csv`   | 含 `open_ports` 的 CSV |
| `--output`    | `IPs_1_result_scan_1.csv` | 展开并带 service 的 CSV   |
| `--xml-dir`   | `scan_sv_xml`             | 每 IP 一个 nmap XML     |
| `--cache`     | `port_sv_cache.json`      | 服务探测缓存               |
| `--skip-scan` | 关                         | 仅从已有 XML 填充          |
| `--limit`     | 无                         | 限制 IP 数量             |


---

## 6. ip_full_port_scan.py（可选）

从已有 `open_ports` 的 IP 中 **抽样**（默认 10 个），对这些 IP 做 **全端口**（`-p-`）扫描，结果写入 `**all_open_ports`**。

### 常用命令

```bash
sudo python3 ip_full_port_scan.py \
  --input  data/990000762670_result_scan_result.csv \
  --sample 10
```

### 参数


| 参数            | 默认                          | 说明        |
| ------------- | --------------------------- | --------- |
| `--input`     | `IPs_1_result_scan.csv`     | 输入 CSV    |
| `--output`    | 与 `--input` 相同              | 写回同一文件    |
| `--sample`    | `10`                        | 抽样 IP 数量  |
| `--xml`       | `scan_full.xml`             | nmap XML  |
| `--cache`     | `full_port_scan_cache.json` | 全端口缓存     |
| `--skip-scan` | 关                           | 仅合并已有 XML |


---

## 7. scan_config.py

扫描规则加载与 HTTP 响应匹配引擎，**不单独运行**。由 `scan_llm.py` 导入；规则文件默认同目录下的 `llm_scan_rules.yaml`，缺失时使用内置规则。

---

## 实战示例：data/990000762670.xls

```bash
cd /home/lx

# 1) IP地址段展开 IP
python3 ip_ping_check.py \
  --data-dir data/990000762670.xls \
  --col-start START_IP --col-end END_IP \
  --skip-ping \
  --dedup-ip

# 2) 端口扫描（中断后用 --resume 续扫，例如补 IPv6）
sudo python3 ip_port_scan.py \
  --input data/990000762670_result.csv \
  --batch-size 100 \ #分批次扫描，每批次数量
  --parallel-workers 2 \ #线程数
  --resume #断点需扫标识

# 3) 展开端口，供 LLM 扫描
python3 expand_scan_ports.py \
  --input  data/990000762670_result_scan_result.csv \
  --output data/990000762670_expanded.csv

# 4) LLM 服务识别
python3 scan_llm.py \
  --input      data/990000762670_expanded.csv \
  --output     data/990000762670_llm.csv \
  --checkpoint data/990000762670_llm_checkpoint.jsonl \ #指定断点需扫checkpoint文件
  --resume
```

---

## 断点续跑与故障恢复


| 阶段     | 断点文件                     | 续跑方式                       |
| ------ | ------------------------ | -------------------------- |
| 端口扫描   | `port_scan_cache.json`   | `ip_port_scan.py --resume` |
| LLM 扫描 | `*_llm_checkpoint.jsonl` | `scan_llm.py --resume`     |


**典型场景：** IPv4 全部扫完（cache 中已有全部 IPv4），程序卡在 `merging 402 batch XML files` 时崩溃。

- `port_scan_cache.json` 与 `*_scan_result.csv` 在每批结束后已更新，**IPv4 数据完整**
- 重启后执行：`sudo python3 ip_port_scan.py --input ... --resume`，将 **只扫描 cache 中缺失的 IP**（例如剩余 IPv6）
- 合并失败的 `scan_v4.xml` 可忽略；需要时可删除后由批次 XML 重新合并，或依赖 cache/CSV

---

## 常见生成文件


| 文件                                                     | 来源                |
| ------------------------------------------------------ | ----------------- |
| `ping_cache.json`                                      | ip_ping_check     |
| `*_result.csv`                                         | ip_ping_check 输出  |
| `ips_scan.txt` / `ips_scan_v4.txt` / `ips_scan_v6.txt` | ip_port_scan      |
| `scan_v4.xml` / `scan_v6.xml`                          | ip_port_scan 合并结果 |
| `scan_v4_batch_*.xml`                                  | 分批扫描中间文件          |
| `port_scan_cache.json`                                 | ip_port_scan 断点   |
| `*_scan_result.csv`                                    | ip_port_scan 输出   |
| `*_expanded.csv`                                       | expand_scan_ports |
| `*_llm.csv` / `*_llm_checkpoint.jsonl`                 | scan_llm          |
| `scan_sv_xml/`                                         | ip_port_scan_sv   |
| `scan_full.xml`                                        | ip_full_port_scan |


---

## 清理中间文件（可选）

端口扫描完成后若不再需要批次 XML：

```bash
rm -f /home/lx/scan_v4_batch_*.xml /home/lx/scan_v6_batch_*.xml
rm -f /home/lx/ips_scan_v4_batch_*.txt /home/lx/ips_scan_v6_batch_*.txt
```

