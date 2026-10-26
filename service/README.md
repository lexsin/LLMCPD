# V7 扫描 service（MySQL 交接契约 2.1）

新版以 `probe_task_run` 领取运行，完整执行正式 V7 流水线。Java 创建任务、预登记全部文件、解析输入和周期调度；Python 维护实际运行状态、租约、来源组、系统结果修订和扫描产物。原 TEST、专项副本及临时实验目录未修改。

当前是待隔离联调的实现，不是生产切换公告。没有执行真实数据库迁移或生产扫描。旧 `probe_task.PENDING` 轮询、自动 ALTER TABLE、全局 asset_llm 发布已退出支持入口；旧仓储文件和 vendor 根目录保留为历史，不供新版调用。旧说明见 `docs/legacy/README-v1.md`，旧 design.md/config.example.yaml 同属 v1，不可用来启动新版。

## 入口与配置

运行环境：Linux、Python 3.12+、MySQL 8/InnoDB、nmap、正式 V7 所需字体及图像依赖。本轮完整离线验证在 3.43 的 Linux/Python 3.13.11 上执行；此前还做过 Windows/Python 3.12 离线验证。SYN 扫描沿用 V7 root 权限检查。安装依赖不会由服务自动执行。

```bash
python -m pip install -r requirements.txt
# 另行部署经审核的 2.1 表结构；服务只读检查字段/唯一键/可空性，不执行 DDL。
# 使用 config.v21.example.yaml 编写独立 config.yaml，不沿用 v1 配置。
export LLM_SCANNER_MYSQL_PASSWORD='由部署系统注入'
python -m llm_detect.main --config config.yaml --check
```

`--check` 只校验配置和固定发布包，输出完整 scanner_version，不连接 MySQL、不扫描、不启动 SSH 作业；它不代替 nmap、字体、SSH 及 MySQL 实机联调。实际消费队列的命令仍为 `python -m llm_detect.main --config config.yaml`，`--once` 会连接配置的队列并最多处理一轮，**不是 dry-run**。新版无需 HTTP 下发；不沿用 v1 的 `--http` 入口。

## 实现结构

- `llm_detect/v21/`：配置、发布校验、输入准备、运行仓储、outbox、阶段子进程、远端作业、产物和报告。
- `vendor/v7/v7-20261026-service21-r3/`：当前正式 V7 运行依赖的固定发布包，`release.json` 记录 SHA-256；service_hooks/service_remote 为兼容接入与守护辅助代码。上一版 r1/r2 目录保留。
- `tests_v21/`：默认阻断网络的离线测试、模拟完整任务和显式开启的隔离 MySQL 测试。
- `docs/IMPLEMENTATION_V21.md`：交接格式、运行/恢复、安全边界及验收说明；`deploy/` 仅提供未启用的部署示例。

发布包保留原 CLI 参数和默认扫描行为；仅当 service 显式传入上下文时启用提交、控制、证据绑定和文件写入隔离。升级必须使用新的 releaseId，不能修改已被运行引用的发布包。

## 验证

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests_v21 -q
```

默认测试不连接生产队列或目标 IP。事务测试使用内存 SQLite 验证约束、回滚和重放，不冒充 MySQL 并发测试。真实 MySQL 测试默认跳过，仅在明确开启 V7_ISOLATED_MYSQL=1、提供 V7_TEST_MYSQL_USER/PASSWORD（可选 HOST/PORT）时，在回环地址服务器新建随机 test_v7_* 数据库并仅清理这个测试库。Linux 进程组测试只启动临时休眠 Python 子进程，不调用 nmap。

2026-10-26 在 3.43 对 r3 重跑：**59 passed, 1 skipped**。r2 的 18 个缺陷回归用例保留；r3 新增无浏览器预检回归，匹配 V7 已有的 HTTP 响应图卡流程，中文字体仍为必要依赖。固定发布清单校验通过；跳过项为隔离 MySQL 写入测试。覆盖范围、发布版本及待验收项见 [验证记录](docs/VALIDATION_V21.md)。

## 上线前仍需完成

- 隔离 MySQL 8 实测和 Java 2.1 下发联调；本次环境未提供可用隔离 MySQL。
- Linux 本地进程组与守护程序的临时进程测试已通过；真实 SSH 远端停止/恢复、断链、服务重启接管和部署共享存储 flock/fsync 仍需隔离实机验收。
- 自动任务文件删除保持关闭：Java 在途上传/解析/导出的停止屏障尚未确认，服务不会擅自推进 WAIT_STOP 或删除用户文件。enable_cleanup=true 会明确拒绝启动，避免假装清理协议已完成。
- 控制终态竞争和 Java 对 SOURCE/RUN 报告版本的解释，仍按此前暂缓事项协调；本轮未修改两份桌面设计文档。
