# 扫描 service 2.1 实现交接

## 1. 发布与启动边界

正式扫描基线为 3.43 的 `/home/lixiao/llm-detect/TEST/strategy_v7_active_gpu_20260916`；不混入 strategy_temp_* 或新疆专项后处理。service 通过固定发布包执行，旧 vendor 根目录不参与新入口。兼容改动只涉及提交钩子、控制检查、证据依据绑定、写入隔离及远端守护，不调整指纹规则、GPU/NPU 判据或主动推理策略。

当前默认发布为 v7-20261026-service21-r3。部署预检与 V7 的 capture-csv/fill 保持一致：Chrome 可选，支持无浏览器 HTTP 响应图卡；中文字体、nmap 和 SYN 扫描权限仍须校验。r1/r2 发布目录未覆盖。

scanner_version 使用 `releaseId+sha256:<规范化发布清单校验值>`，由 `--check` 输出。清单同时校验 V7 文件及 service 适配代码/defaults，避免只冻结 vendor 却在恢复时静默替换提交逻辑。Java 可留空，首次准备阶段冻结；显式指定时必须使用完整值。版本、规则缺失/校验失败不回退到当前默认版本。更新适配代码也必须创建新发布；旧运行需要对应的旧发布和适配部署，无法匹配时明确拒绝而非换版本继续。恢复期间变更数据根目录、全端口执行方式或远端 INI 文件会被拒绝，须恢复原配置；不会把旧远端作业遗留后另起一个替代作业。

启动只读检查 14 张扫描核心表的字段、唯一键和四个下发字段的可空性。DDL 由部署方审核执行；Python 不创建任务/运行、不更新 next_run_at、不写人工复核或 compute_*、asset_llm。

## 2. 输入与参数格式

Java 在创建任务的同一事务预登记完整且非空文件清单；上传失败保留 fileId。运行 files[] 必须恰好覆盖任务的全部文件，全部 READY；不允许仅筛选已成功文件。每项包含 file_id（建议十进制字符串）、source_order（1..N）、original_name、parsed_hash、valid_row_count、invalid_row_count。快照和规范化文件哈希必须一致。

规范化输入是无 BOM 的 UTF-8 JSON，hash 对完整发布字节计算 SHA-256，格式为：

```json
{
  "schema_version": 1,
  "rows": [
    {
      "resource_id": "101",
      "start_ip": "192.0.2.1",
      "end_ip": "192.0.2.1",
      "unit_name": "使用单位",
      "source_unit": "江苏电信",
      "province_name": "江苏省",
      "operator_name": "电信",
      "resource_type": "SINGLE_IP",
      "enterprise_name": "江苏电信"
    }
  ]
}
```

rows[] 仅包含有效源行。resource_id 对应实际 probe_pending_resource.id，基础字段逐一核对，不按行号或单位反推。IP 段按输入范围展开，内部去重，但每个主机的全部源行关联单独保存。部署容量上限 max_expanded_hosts 默认 1,000,000；超过上限明确失败，不偷偷只扫描端点，尤其不会展开无界 IPv6 范围。

param_snapshot_json 必须提供完整 v1 字段，参考 `llm_detect/v21/defaults.json`，未知字段或缺失字段拒绝。run.concurrency 与 port_scan.parallel_workers 必须一致（1..20）；verify_workers、HTTP/GPU、全端口和主动复核并发各自独立。首版受控全端口使用 candidates 模式；发布包原 CLI 的 all 模式仍保留。

## 3. 执行与提交

领取对象是 probe_task_run，按任务→运行顺序加锁，领取/接管递增 lease_epoch。默认 5 秒轮询、10 秒续租、60 秒租约、2 秒控制检查。`/run/lock/llm-detect-v7-machine.lock` 阻止第二个受控 service，活动 runId 同时保存在 data_root/active-run.json；重启优先等待/恢复该运行，不在其状态不明时领取另一个任务。共享运行目录还持有执行锁，两个锁 FD 均向扫描子进程传递。租约失败后旧扫描无法提交，子进程监视各自租约代次的续租文件，失去续租自动结束所属进程组。恢复在旧写入者退出、执行锁可用后才继续。不要删除锁文件“强行解锁”；共享文件系统必须实测支持 flock/fsync 语义。

准备完成、规则/程序版本已冻结后，事务登记全部来源组，并原子发布 source_total、首次 started_at、RUNNING。后续仍按文件串行扫描；单个来源组实际处理时再写自身 started_at。恢复复用来源组，不改变 runId、原 started_at 或已完成阶段。

阶段依次为 EXPAND、PORT_SCAN、IDENTIFY、GPU_RECHECK、EVIDENCE、FULL_PORT、FULL_IDENTIFY、FULL_GPU_RECHECK、MERGE、ACTIVE_RECHECK、EVIDENCE_FINAL、FINALIZE。运行汇总在所有来源组结束后执行。端口策略及参数沿用正式 V7；无开放端口仍生成空表及报告。

结果回调先原子写入并 fsync 完整 outbox JSON，再推进原生断点。数据库在同一有效租约事务中写 probe_scan_event、主机/端点/系统结果、修订历史和计数；事件重放不重复计数。恢复先重放，再由持久化载荷重建原生 checkpoint/cache，不把旧 checkpoint 单独视为数据库提交凭据。

LLM 首次结果、同 IP GPU/NPU 关联、低概率复查及主动复核分别提交修订。相同规范化结果不新增修订；raw_result_json 保留完整 V7 行。系统修订不写人工复核表。事件持久化 observed_at，首次结果优先采用 V7 scan_time（受控子进程 TZ=UTC），修订采用事件观察时间；重放不把历史检测时间改成数据库恢复时间。数据库 committed_at 单独记录实际提交时间。

主动推理在真正准备调用时记录 inflight；已完成结果先持久化，再确认原断点。恢复时只有未确认完成的调用记 UNKNOWN_INTERRUPTED，保留原 GPU 结论，不自动重发可能已执行的推理。后续若需重试此类结果，应走明确的新执行，而不是悄悄恢复重试。

r2 恢复主动复核断点时直接使用正式扫描器的 row_key（`IP|端口|协议`）；其他阶段继续使用各自原生格式，避免已完成或 UNKNOWN_INTERRUPTED 记录被误当成待执行。回归测试实际调用主动复核 CLI 的 main/resume 分支，确认不会再进入 run_target。

## 4. 远端与产物

远端 INI 沿用正式 V7 的 ssh/remote 配置，必须配置专用 identity_file 和 known_hosts_file，保持严格主机校验。新版仅复用旧 SSH 传输，不调用旧 runner 的自动清目录逻辑。远端独立 guardian 绑定 task/run/source/stage、输入及发布哈希和 epoch；陈旧 epoch、不同绑定拒绝操作。守护器续约失效后结束对应工作进程组；客户端失联不代表停止成功，不确认控制、不启动替代任务。作业目录保留，清理需另行审批/协议。

本地/远端停止均按可验证的进程组身份收尾，不使用 pkill -f 等模糊匹配。PAUSE/STOP 确认只针对读取到的请求序号；被更高 STOP 覆盖的 PAUSE 不误确认。排队和已确认暂停的 STOP 无需扫描槽位。service 自身 SIGTERM 收尾后把运行留在可恢复状态，不伪造用户 STOP 请求。

r2 在运行中控制确认和空闲 STOP 两条事务路径同步重算来源组/主机/端点汇总；STOP 同时写入来源组 finished_at，避免终态已经确认但 source_finished 仍为旧值。

远端 finished 后，r2 下载 CSV、summary 和最终 checkpoint，逐文件核对远端 SHA-256。summary 必须包含 selected_candidates/completed/failed_or_timed_out/new_open_ports 四个非负整数；候选计数、最新 checkpoint 状态、输入主机范围、合法端口及新增端点集合必须一致，CSV 不得缺行、重复或出现额外端点。运行中允许读取尚在追加的断点；最终验收严格拒绝损坏断点。零候选时允许没有 checkpoint。校验失败不发布新的本地扫描输入或覆盖既有结果文件。

文件先登记 WRITING，完成关闭、校验和不可变路径发布后置 READY。生成中断标 FAILED；重试新增 generation_no，不覆盖 READY。截图额外绑定源组、endpoint_id、系统 revision 和完整原始行依据签名，旧图不能重新绑定为当前证据。

来源组保留 V7 原格式 XLSX；RUN CSV 包含 task_id/run_id/source_group_id。RUN XLSX 增加“来源清单”，每个来源组单独保留 V7 的分类工作表与图片，避免相同 IP:端口跨文件串图。RUN 报告从数据库已提交原始行导出，离线嵌入已验证截图，不重新访问目标或重新扫描。来源组报告绑定生成当时版本；Java 的 SOURCE/RUN 版本解释仍需按此前待确认事项统一。

r2 的 SOURCE 与 RUN 报告共用 report_evidence.prepare_manifest：仅保留与 committed.csv 当前行完整依据哈希相同、图片存在且位于本来源目录内的记录。即使最后截图阶段失败并遗留旧 manifest，也不会将旧图嵌入新结论；缺图保持空白。该修复不改变 Java 对报告版本的既有业务解释。

## 5. 验证与未完成上线项

默认 pytest 禁止网络连接（仅允许 asyncio 的本地 socketpair 自管道）。内存 SQLite 验证真实事务回滚/约束/重放，不验证 MySQL 锁。离线回归使用相同模拟响应比较原正式扫描与适配扫描，不更改正式结果文件。端到端测试模拟两文件所有阶段、生成真实 XLSX、再执行第二轮，验证首轮结果和文件不变。

隔离 MySQL 测试需显式设置 V7_ISOLATED_MYSQL=1 和测试账户，仅允许回环地址，新建随机 test_v7_*，finally 仅删除这个新建测试库；不会选择或覆盖既有业务库。无配置则明确跳过。Linux 进程组测试仅启动临时休眠进程，远端真实故障演练仍需在隔离主机进行。

本次不启用自动删除。Java 在途写入屏障尚无已确认协议，无法安全把 WAIT_STOP 推进到文件删除；enable_cleanup=true 将拒绝启动。删除请求对应的扫描 STOP 和写入撤销已接入，但文件清理/Java 数据删除闭环须补齐屏障后单独验收。

2026-10-26 已在 3.43 Linux/Python 3.13.11 完成 r3 全套离线验证：59 项通过，1 项隔离 MySQL 测试跳过。包含 r2 的 18 个缺陷回归用例及 r3 的无浏览器预检用例。本地进程组停止、执行锁继承、远端守护程序的续租过期和显式停止使用真实临时进程验证通过；守护程序测试使用休眠假 worker，不调用扫描器、SSH 或目标。详见 `VALIDATION_V21.md`。

上线前必须完成：隔离 MySQL 8 + Java 下发联调、实际扫描阶段及真实 SSH 远端控制、断链/接管演练、部署共享存储锁/fsync、容量与长事务性能测试；复核此前暂缓的控制终态和报告版本口径。本实现及离线通过不代表这些环境验收已经完成。
