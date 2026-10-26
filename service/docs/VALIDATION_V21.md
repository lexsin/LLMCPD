# service 2.1 验证记录

更新日期：2026-10-26（北京时间）。本记录描述已执行的检查及未执行的验收，不能作为生产切换完成的依据。

## 固定发布

- 正式基线：`/home/lixiao/llm-detect/TEST/strategy_v7_active_gpu_20260916`。
- 实现目录：`/home/lixiao/llm-detect/service`。
- 当前发布目录：`vendor/v7/v7-20261026-service21-r3`。
- scanner_version：`v7-20261026-service21-r3+sha256:67a484cdc1a12f15a528f5afd3f967d6e0e9718dab683958f3c787be39e54c57`。
- 清单包含 18 个扫描/辅助文件，并绑定当前 service 适配代码、入口、默认参数和 requirements.txt 的 SHA-256（23 项适配文件）。
- 上一版 r1/r2 发布目录及其清单保持不变。恢复旧运行仍需匹配其冻结版本与对应旧适配部署，不能用 r3 替代旧版本。

仅修改 service 范围内的代码、测试和文档；原 TEST 扫描源码未修改。AST 回归逐项比较正式代码的算法函数及类；明确列出的编排/回调接入函数允许兼容改动，其余算法函数体必须一致。此比较不替代真实目标环境的算法验收。

## 已执行检查

环境：3.43 Linux，Python 3.13.11（Anaconda）。采用现有环境执行离线检查，未安装或启动数据库/扫描服务。

```bash
cd /home/lixiao/llm-detect/service
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests_v21 -q -p no:cacheprovider
PYTHONDONTWRITEBYTECODE=1 python3 -m llm_detect.main --config config.v21.example.yaml --check
```

最终全量测试输出：`59 passed, 1 skipped in 5.52s`。r1 为 40 项通过、1 项跳过；r2 新增 18 个回归用例，结果为 58 项通过、1 项跳过；r3 新增预检回归。

`--check` 返回退出码 0：`contract_version=2.1`、`release_files=18`、`database_connected=false`、`scanner_started=false`，scanner_version 与上文一致。

默认测试阻断网络连接，仅允许 asyncio 本地 socketpair 自管道。已覆盖：

| 范围 | 已验证内容 | 验证方式与限制 |
| --- | --- | --- |
| 发布与算法 | 校验清单、缺失/篡改拒绝、规则冻结、正式算法函数体保持、模拟响应前后结论 | 静态比较与离线模拟，不访问目标 |
| 输入与来源 | 完整清单就绪、哈希、原始 resource 关联、来源组原子发布、重叠范围去重和容量限制 | 内存 SQLite 真实事务与临时输入文件 |
| 结果与恢复 | 事件先落盘、重放幂等、提交回滚、修订历史、旧租约拒绝写入、来源与历史运行隔离 | SQLite 事务；不证明 MySQL 锁与并发行为 |
| 控制 | 暂停/继续、STOP 覆盖、删除撤销写入、优先恢复活动运行 | 仓储和编排离线测试 |
| 本地进程 | 所属进程组停止确认、父进程关闭 FD 后子进程继续持有执行锁 | Linux 真实临时休眠进程；不执行扫描 |
| 远端控制辅助 | 旧 epoch/绑定拒绝、连接未知状态不当作已停止、守护续租过期和显式停止终止进程组 | RPC 模拟及 Linux 真实假 worker；没有真实 SSH 断链演练 |
| 文件与报告 | READY 文件不被恢复覆盖、结果版本校验、空结果 XLSX、多来源报告隔离、重复运行保留首轮结果与文件 | 真实临时 CSV/XLSX；完整任务的扫描阶段采用模拟 |

r1 阶段已修正恢复异常分支的未初始化变量，并为不完整发布清单增加明确的 RELEASE_FORMAT 错误；本轮最终全量测试同时包含这些既有检查。

## r2 审查修复回归

四项缺陷先在隔离临时目录复现，再修改 service 适配层；固定扫描算法文件未作变更。新增 `tests_v21/test_review_regressions.py`，18 个参数化测试全部通过：

| 修复 | 新增验证 |
| --- | --- |
| 主动复核恢复键格式 | 已完成和 UNKNOWN_INTERRUPTED 两种记录交给原生 main/resume，run_target 调用数均为 0；再次恢复不重复发事件 |
| 远端结果完整性 | 接受完整、部分失败、零候选结果；拒绝缺行、错误/重复/越界/额外端点、损坏或缺失 checkpoint、汇总不一致及 SHA-256 不一致；失败不覆盖既有本地结果 |
| SOURCE/RUN 截图一致性 | 两种报告实际生成 XLSX 并检查嵌入图片数量：过期依据的图片均排除，当前依据图片均保留；捕获/子进程调用采用替身，不访问目标 |
| STOP 汇总一致性 | 运行中停止、暂停后空闲停止两种路径均在确认后得到 source_total=source_finished=2，各来源终态及 finished_at 同步 |

r2 阶段未修改原 TEST、旧 r1 发布文件、真实数据库或生产队列，也未启用自动删除。

## r3 部署预检修复

10.10.6.80 的 CentOS 7 设备没有 Chrome。V7 实际的 capture-csv/fill 使用 detect_chrome(required=False)，已支持 HTTP 响应图卡，但适配预检使用了默认 required=True，造成环境被提前拒绝。r3 仅将预检对齐为浏览器可选，不改识别算法；新增测试确认无浏览器时预检通过、缺少中文字体时仍拒绝。

10.10.6.80 已复用既有 Miniconda 创建独立 Python 3.12.15 环境 `/home/lixiao/llm-detect/envs/scanner-py312`，依赖安装使用兼容 CentOS 7 的二进制包。业务库只读结构检查通过：MySQL 8.4.6，扫描核心表、字段、必要唯一键和可空字段满足契约。该检查不是写入/并发联调；没有迁移表结构或领取任务。

上线仍需对齐 Java 配置及现存运行：Java 默认扫描版本为 v7-handoff-1，现存三条运行版本均为 v7-demo，其中一条状态为 RUNNING；这些值不能用 r3 静默替代。消费者在确认旧记录处理方式与版本配置前保持未启动。设备部署记录位于 `/home/lixiao/llm-detect/deploy80/`。

## 跳过及待验收

1. **隔离 MySQL 写入/并发联调未完成。** `test_mysql.py` 因未显式提供隔离实例及测试账户而跳过；10.10.6.80 仅执行既有业务库的只读结构检查。隔离写入测试仅接受回环地址，新建随机 `test_v7_*`，只清理自身新建库。3.43 当前 Python 环境没有 mysql.connector；10.10.6.80 的独立环境已安装该依赖。
2. **Java 2.1 交接未完成实机联调。** 需覆盖文件就绪/快照格式、运行领取、控制序号、历史运行、字段/唯一索引及报告版本解释。
3. **真实本地扫描与 SSH 远端故障演练未执行。** 尚需覆盖长耗时扫描阶段、SSH 断链、guardian 异常、service 重启/接管及同版本恢复。现有 Linux 假进程测试不能代替这些演练。
4. **部署环境验收未完成。** 包括 nmap/root、字体/截图、部署共享存储的 flock/fsync、容量和长事务性能。`--check` 只验证配置与发布文件，不证明运行依赖完整。
5. **自动文件清理保持关闭。** Java 在途上传/解析/导出的停止屏障尚未确认；enable_cleanup=true 拒绝启动。没有擅自推进 WAIT_STOP 或删除用户文件。
6. 控制终态竞争、SOURCE/RUN 报告版本口径仍属此前暂缓协调事项；本次未改两份桌面业务设计文档。

没有领取生产任务，没有执行真实扫描，没有数据库迁移，没有安装/启动 systemd 服务，也没有实施上线切换。
