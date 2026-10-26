"""Column contract copied from the agreed 2.1 field document. No DDL is executed."""

CONTRACT = {
  "probe_task": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_name": {
      "type": "VARCHAR(256)",
      "required": True,
      "note": "任务名称"
    },
    "task_desc": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "任务描述"
    },
    "task_type": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "任务类型：ONCE 为一次性任务（可人工重复执行），PERIODIC 为周期任务；仅表示触发方式，不表示周期计划当前是否启用",
      "default": "ONCE"
    },
    "lifecycle_status": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "ACTIVE / DELETE_REQUESTED",
      "default": "ACTIVE"
    },
    "param_json": {
      "type": "LONGTEXT",
      "required": True,
      "note": "未来执行使用的扫描参数",
      "default": "{}"
    },
    "concurrency": {
      "type": "SMALLINT UNSIGNED",
      "required": True,
      "note": "页面配置的基础端口扫描 worker 数，映射 Python --parallel-workers；不是文件/来源组数量",
      "default": "3"
    },
    "schedule_enabled": {
      "type": "TINYINT UNSIGNED",
      "required": True,
      "note": "周期计划开关：0=未启用/已停用，1=已启用；仅 PERIODIC 可设为 1，ONCE 固定为 0。停用计划不改变 task_type，也不自动停止已创建运行；由 Java 维护",
      "default": "0"
    },
    "cron_expression": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "每月指定日期及时间的 cron 表达式；PERIODIC 启用前必填，ONCE 为空；按 Java 调度组件约定语法校验，时区 Asia/Shanghai"
    },
    "next_run_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "下一次计划执行时间，保存 UTC，随计划推进更新。由 Java 在启用/修改计划时计算，并由 Java 调度器在到期处理事务中推进；Python 不更新。停用计划或 ONCE 时为空"
    },
    "last_run_no": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "已分配的最大执行序号",
      "default": "0"
    },
    "latest_run_id": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "最近创建的执行记录，不代表最近成功记录"
    },
    "delete_requested_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "请求删除时间"
    }
  },
  "probe_task_file": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "original_name": {
      "type": "VARCHAR(255)",
      "required": True,
      "note": "原始文件名，仅用于显示"
    },
    "file_format": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "首版仅支持 XLSX",
      "default": "XLSX"
    },
    "storage_id": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "存储根目录配置标识",
      "default": "LOCAL"
    },
    "relative_path": {
      "type": "VARCHAR(1024)",
      "required": True,
      "note": "原文件相对路径；预登记时可填写服务器预分配位置，不代表实体文件已上传完成"
    },
    "parse_status": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "PENDING=等待上传/等待解析，PARSING=原文件完整发布后解析中，READY=原文件/规范化文件/源行/hash 全部发布完成，FAILED=解析失败；任何非 READY 项均阻止启动",
      "default": "PENDING"
    },
    "row_total": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "解析的数据行数",
      "default": "0"
    },
    "valid_row_count": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "合法目标行数",
      "default": "0"
    },
    "invalid_row_count": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "无效目标行数",
      "default": "0"
    },
    "parsed_relative_path": {
      "type": "VARCHAR(1024)",
      "required": False,
      "note": "规范化源记录文件位置"
    },
    "parsed_hash": {
      "type": "CHAR(64)",
      "required": False,
      "note": "规范化输入文件实际 UTF-8 字节的 SHA-256；READY 前必须写入，并在每次运行 input_snapshot_json.files 中冻结，Python 校验快照/本字段/实际文件三者一致"
    },
    "parse_error_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "文件或行级错误说明"
    },
    "uploaded_by": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "上传人"
    },
    "parsed_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "解析结束时间"
    }
  },
  "probe_pending_resource": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "file_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "固定输入文件 ID"
    },
    "start_ip": {
      "type": "VARCHAR(45)",
      "required": False,
      "note": "规范化起始 IP；合法记录必填"
    },
    "end_ip": {
      "type": "VARCHAR(45)",
      "required": False,
      "note": "规范化终止 IP；合法记录必填"
    },
    "ip_version": {
      "type": "TINYINT UNSIGNED",
      "required": False,
      "note": "4 / 6"
    },
    "range_size": {
      "type": "DECIMAL(39,0)",
      "required": False,
      "note": "地址范围规模，用于展开前检查"
    },
    "unit_name": {
      "type": "VARCHAR(255)",
      "required": False,
      "note": "模板中的“使用单位信息”"
    },
    "source_unit": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "模板中的“来源单位”"
    },
    "province_name": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "从来源单位等明确企业信息直接解析并规范化的省份名称；有效源行必填，不查询省份 code"
    },
    "operator_name": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "从明确企业信息直接解析并规范化的运营商名称；有效源行必填，与省份名称共同确定企业，不查询运营商 code"
    },
    "validation_status": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "VALID / INVALID"
    },
    "validation_error": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "无效原因"
    }
  },
  "probe_task_run": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_no": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "任务内执行序号"
    },
    "trigger_type": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "MANUAL：一次性任务人工启动/再次执行；SCHEDULED：周期任务到期触发"
    },
    "input_snapshot_json": {
      "type": "LONGTEXT",
      "required": True,
      "note": "固定文件 ID 清单、规范化输入 parsed_hash、输入范围及来源摘要；不包含输入版本号或原文件 file_hash"
    },
    "param_snapshot_json": {
      "type": "LONGTEXT",
      "required": True,
      "note": "本次实际扫描参数"
    },
    "rule_snapshot_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "Java 下发时可与 rule_hash 同时留空；Python 首次 PREPARING 按部署配置的已发布默认规则补齐完整快照；实际扫描前必须冻结，之后不可替换"
    },
    "rule_hash": {
      "type": "CHAR(64)",
      "required": False,
      "note": "与 rule_snapshot_json 同时提供或同时为空；Python 校验/补齐规则内容 UTF-8 字节的 SHA-256，实际扫描前必备，冻结后恢复复用"
    },
    "scanner_version": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "Java 可指定或留空；Python 校验指定版本，未指定时在首次准备阶段记录实际固定部署版本/提交标识，实际扫描前必备；恢复/接管不得静默换版本"
    },
    "concurrency": {
      "type": "SMALLINT UNSIGNED",
      "required": True,
      "note": "本次固定的基础端口扫描 worker 数，等于 param_snapshot_json.port_scan.parallel_workers",
      "default": "3"
    },
    "status": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "本次实际执行状态",
      "default": "QUEUED"
    },
    "worker_id": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "当前执行器标识"
    },
    "lease_epoch": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "每次领取/接管递增的租约代次",
      "default": "0"
    },
    "heartbeat_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "最近心跳"
    },
    "lease_expires_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "租约到期时间"
    },
    "requested_action": {
      "type": "VARCHAR(16)",
      "required": False,
      "note": "Java 下发给 Python 的运行控制动作：PAUSE=暂停，RESUME=暂停后恢复，STOP=停止；无控制请求时为空。允许保留最后一次动作，不表示实际执行状态；Python 仅在 request_seq > ack_seq 时处理。新扫描通过新增 status=QUEUED 的运行启动，不使用 START 动作；Java 不用此字段直接修改实际 status"
    },
    "request_seq": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本 run_id 内单调递增的控制请求序号，由 Java 在锁定任务和运行的控制事务中分配；每个新请求加 1，并与 requested_action、requested_at 同事务写入，恢复不重置。同一动作尚待确认时重试复用原序号；其他待确认动作不允许覆盖，STOP 可覆盖待确认 PAUSE/RESUME 并递增序号。Python 通过 request_seq > ack_seq 判断有待处理请求，完成后将 ack_seq 更新为实际处理的序号，不能直接确认读取后才出现的新请求",
      "default": "0"
    },
    "ack_seq": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "已确认控制序号，Python 写",
      "default": "0"
    },
    "requested_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "控制请求时间"
    },
    "source_total": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "来源组总数；发布首次启动的事务中必须等于 input_snapshot_json.files 完整清单数量，包含尚未开始执行的文件",
      "default": "0"
    },
    "source_finished": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "已结束来源组数",
      "default": "0"
    },
    "host_total": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "各来源组主机数之和",
      "default": "0"
    },
    "host_finished": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "已处理结束的主机数",
      "default": "0"
    },
    "unique_ip_count": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "跨来源组去重后的 IP 数",
      "default": "0"
    },
    "endpoint_total": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "各来源组端点总数",
      "default": "0"
    },
    "endpoint_finished": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "已处理结束的端点数",
      "default": "0"
    },
    "progress_percent": {
      "type": "DECIMAL(5,2)",
      "required": True,
      "note": "本次运行整体工作完成百分比，由 Python 汇总各来源组、阶段后写入，Java 直接读取；不能用当前来源组或当前阶段的百分比代替",
      "default": "0"
    },
    "result_version": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "系统结果提交版本，用于绑定导出文件",
      "default": "0"
    },
    "workspace_relative_path": {
      "type": "VARCHAR(1024)",
      "required": False,
      "note": "保留的可空兼容字段；NULL 时 Python 按 tasks/{task_id}/runs/{id} 推导运行目录，Java 可显式填写相同值；非空值必须与推导值一致，本次不删除该字段"
    },
    "final_artifact_id": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "默认最终 XLSX 的产物 ID"
    },
    "summary_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "分类统计、错误数量、阶段摘要"
    },
    "error_code": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "运行级错误码"
    },
    "error_message": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "运行级错误摘要"
    },
    "started_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "首次实际扫描启动发布时间，不是领取时间；Python 完成全部来源组登记后，与 source_total、status=RUNNING 在同一事务首次写入；首次启动前的 PREPARING 期间为空，恢复不重写"
    },
    "finished_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "进入终态的时间"
    }
  },
  "probe_run_source": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "file_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "固定的固定输入文件"
    },
    "source_order": {
      "type": "INT UNSIGNED",
      "required": True,
      "note": "文件在本次执行中的顺序"
    },
    "source_name": {
      "type": "VARCHAR(255)",
      "required": True,
      "note": "来源组显示名称，通常为文件名"
    },
    "input_snapshot_json": {
      "type": "LONGTEXT",
      "required": True,
      "note": "该组源记录与归属快照"
    },
    "input_hash": {
      "type": "CHAR(64)",
      "required": True,
      "note": "该组规范化输入校验值"
    },
    "status": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "PENDING / RUNNING / PAUSED / SUCCESS / PARTIAL / FAILED / STOPPED；预登记全部来源组时为 PENDING，尚未执行不代表来源组缺失",
      "default": "PENDING"
    },
    "current_stage": {
      "type": "VARCHAR(32)",
      "required": False,
      "note": "本来源组当前阶段代码，由 Python 更新；主要供任务详情展示，应结合来源组名称及企业归属理解，不代表整个任务或运行的所有企业都处于此阶段"
    },
    "policy_code": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "V7 来源扫描策略代码"
    },
    "policy_summary_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "阈值、单 IP 数、小范围扩展数等"
    },
    "host_total": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本组去重主机数",
      "default": "0"
    },
    "host_finished": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本组已结束主机数",
      "default": "0"
    },
    "endpoint_total": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本组端点总数",
      "default": "0"
    },
    "endpoint_finished": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本组已结束端点数",
      "default": "0"
    },
    "progress_percent": {
      "type": "DECIMAL(5,2)",
      "required": True,
      "note": "本组完成百分比",
      "default": "0"
    },
    "workspace_relative_path": {
      "type": "VARCHAR(1024)",
      "required": True,
      "note": "本组独立目录"
    },
    "error_code": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "本组错误码"
    },
    "error_message": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "本组错误摘要"
    },
    "started_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "本来源组实际开始处理时间；仅预登记时为空，不随运行首次启动统一填写"
    },
    "finished_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "结束时间"
    }
  },
  "probe_run_stage": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属来源组"
    },
    "stage_code": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "阶段代码"
    },
    "stage_order": {
      "type": "SMALLINT UNSIGNED",
      "required": True,
      "note": "阶段顺序"
    },
    "status": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "PENDING / RUNNING / PAUSED / SUCCESS / PARTIAL / FAILED / SKIPPED",
      "default": "PENDING"
    },
    "attempt_no": {
      "type": "INT UNSIGNED",
      "required": True,
      "note": "阶段启动/恢复次数",
      "default": "0"
    },
    "work_unit": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "IP / ENDPOINT / FILE / ITEM"
    },
    "work_total": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "待统计时为空"
    },
    "work_finished": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "已结束工作项",
      "default": "0"
    },
    "work_success": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "成功数",
      "default": "0"
    },
    "work_failed": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "失败数",
      "default": "0"
    },
    "work_skipped": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "跳过数",
      "default": "0"
    },
    "last_committed_seq": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "最新已入库的阶段提交序号",
      "default": "0"
    },
    "checkpoint_relative_path": {
      "type": "VARCHAR(1024)",
      "required": False,
      "note": "检查点位置"
    },
    "summary_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "阶段统计、子阶段信息"
    },
    "error_code": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "错误码"
    },
    "error_message": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "错误摘要"
    },
    "started_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "首次开始时间"
    },
    "finished_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "完成或失败时间"
    }
  },
  "probe_host": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属来源组"
    },
    "host_ip": {
      "type": "VARCHAR(45)",
      "required": True,
      "note": "规范化 IP"
    },
    "ip_version": {
      "type": "TINYINT UNSIGNED",
      "required": True,
      "note": "4 / 6"
    },
    "source_form": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "SINGLE / RANGE / BOTH"
    },
    "scan_mode": {
      "type": "VARCHAR(32)",
      "required": False,
      "note": "PN / HOST_DISCOVERY"
    },
    "host_phase": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "当前主机处理阶段",
      "default": "PENDING_SCAN"
    },
    "scan_status": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "实际扫描状态或 V7 原始状态"
    },
    "open_ports_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "开放端口快照"
    },
    "full_port_status": {
      "type": "VARCHAR(32)",
      "required": False,
      "note": "全端口复查状态；未选中时为空"
    },
    "probe_info": {
      "type": "VARCHAR(1000)",
      "required": False,
      "note": "无开放端口、不可达等说明"
    },
    "error_code": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "程序执行错误"
    },
    "error_message": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "错误摘要"
    },
    "scan_start_time": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "基础端口扫描开始时间"
    },
    "scan_end_time": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "基础端口扫描结束时间"
    },
    "finished_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "所有关联识别/复核结束时间"
    }
  },
  "probe_host_resource": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属来源组"
    },
    "host_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "主机记录 ID"
    },
    "resource_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "原始目标行 ID"
    },
    "source_form": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "此关联来自 SINGLE / RANGE"
    }
  },
  "probe_endpoint": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属来源组"
    },
    "host_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属主机"
    },
    "host_ip": {
      "type": "VARCHAR(45)",
      "required": True,
      "note": "规范化 IP"
    },
    "port": {
      "type": "SMALLINT UNSIGNED",
      "required": True,
      "note": "TCP 端口"
    },
    "discovered_stage": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "PORT_SCAN / FULL_PORT"
    },
    "protocol": {
      "type": "VARCHAR(16)",
      "required": False,
      "note": "HTTP / HTTPS / NON_HTTP；尚未识别为空"
    },
    "probe_shape": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "FRAMEWORK / WEB / UNKNOWN",
      "default": "UNKNOWN"
    },
    "endpoint_status": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "PENDING / RUNNING / DONE / FAILED / SKIPPED",
      "default": "PENDING"
    },
    "current_stage": {
      "type": "VARCHAR(32)",
      "required": False,
      "note": "当前识别/复核阶段"
    },
    "scan_status": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "V7 的具体探测状态"
    },
    "error_code": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "执行错误码"
    },
    "error_message": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "执行错误摘要"
    },
    "probe_start_time": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "首次识别时间"
    },
    "probe_end_time": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "基础识别结束时间"
    },
    "finished_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "全部端点处理结束时间"
    }
  },
  "probe_asset_port": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属来源组"
    },
    "endpoint_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "端点 ID"
    },
    "host_ip": {
      "type": "VARCHAR(45)",
      "required": True,
      "note": "IP"
    },
    "port": {
      "type": "SMALLINT UNSIGNED",
      "required": True,
      "note": "端口"
    },
    "protocol": {
      "type": "VARCHAR(16)",
      "required": False,
      "note": "已识别协议"
    },
    "is_llm": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "CONFIRMED / SUSPECTED / NO"
    },
    "service_type": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "V7 服务类型"
    },
    "model_domain": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "模型领域原始值"
    },
    "deploy_tool": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "部署工具"
    },
    "deploy_version": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "工具版本"
    },
    "model_info": {
      "type": "LONGTEXT",
      "required": False,
      "note": "模型信息"
    },
    "gpu_likelihood": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "HIGH / MEDIUM / LOW / UNKNOWN",
      "default": "UNKNOWN"
    },
    "gpu_evidence": {
      "type": "LONGTEXT",
      "required": False,
      "note": "GPU 判断证据"
    },
    "gpu_probe_detail_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "GPU 探测明细"
    },
    "npu_likelihood": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "HIGH / MEDIUM / LOW / UNKNOWN",
      "default": "UNKNOWN"
    },
    "npu_evidence": {
      "type": "LONGTEXT",
      "required": False,
      "note": "NPU 判断证据"
    },
    "accelerator_type": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "V7 加速器类型"
    },
    "scan_status": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "原始扫描结论状态"
    },
    "scan_confidence": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "V7 原始置信度"
    },
    "protocol_probe_detail_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "协议探测明细"
    },
    "http_probe_detail_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "HTTP 探测明细"
    },
    "certificate_names_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "证书域名列表"
    },
    "tested_hostnames_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "测试域名列表"
    },
    "selected_hostname": {
      "type": "VARCHAR(255)",
      "required": False,
      "note": "最终使用域名"
    },
    "evidence": {
      "type": "LONGTEXT",
      "required": False,
      "note": "原始证据摘要"
    },
    "links_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "访问链接列表"
    },
    "analysis": {
      "type": "LONGTEXT",
      "required": False,
      "note": "V7 的“分析”字段"
    },
    "gpu_second_stage_status": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "GPU 二阶段复核状态"
    },
    "active_probe_status": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "主动复核状态，包括 UNKNOWN_INTERRUPTED"
    },
    "gpu_likelihood_before": {
      "type": "VARCHAR(16)",
      "required": False,
      "note": "主动复核前 GPU 结论"
    },
    "gpu_likelihood_after": {
      "type": "VARCHAR(16)",
      "required": False,
      "note": "主动复核后 GPU 结论"
    },
    "verdict_rule_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "有实际记录时保存命中规则；不得反推伪造"
    },
    "fingerprint_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "指纹摘要"
    },
    "raw_result_json": {
      "type": "LONGTEXT",
      "required": True,
      "note": "本阶段完整 V7 原始行，保留扩展字段"
    },
    "result_stage_code": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "最新结果来源阶段"
    },
    "result_stage_seq": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "最新阶段提交序号"
    },
    "revision_no": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本端点系统结果修订号",
      "default": "1"
    },
    "result_hash": {
      "type": "CHAR(64)",
      "required": True,
      "note": "规范化结果校验值"
    },
    "detect_time": {
      "type": "DATETIME(6)",
      "required": True,
      "note": "当前结果对应检测时间"
    }
  },
  "probe_asset_port_history": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属来源组"
    },
    "asset_port_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "当前结果 ID"
    },
    "revision_no": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "端点修订号"
    },
    "stage_code": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "修订来源阶段"
    },
    "stage_seq": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "阶段提交序号"
    },
    "event_id": {
      "type": "CHAR(36)",
      "required": True,
      "note": "产生修订的提交事件"
    },
    "change_reason": {
      "type": "VARCHAR(128)",
      "required": True,
      "note": "INITIAL / GPU_CORRELATION / NPU_CORRELATION / GPU_RECHECK / ACTIVE_RECHECK 等"
    },
    "result_snapshot_json": {
      "type": "LONGTEXT",
      "required": True,
      "note": "完整规范化结果及原始 V7 行"
    },
    "result_hash": {
      "type": "CHAR(64)",
      "required": True,
      "note": "快照校验值"
    },
    "detect_time": {
      "type": "DATETIME(6)",
      "required": True,
      "note": "对应检测时间"
    }
  },
  "probe_scan_event": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "event_id": {
      "type": "CHAR(36)",
      "required": True,
      "note": "全局唯一事件 ID"
    },
    "schema_version": {
      "type": "SMALLINT UNSIGNED",
      "required": True,
      "note": "提交记录格式版本",
      "default": "1"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "来源组事件必填；运行级产物事件可空"
    },
    "stage_code": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "阶段代码"
    },
    "stage_seq": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "阶段内提交序号"
    },
    "event_type": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "阶段、主机、端点、结果、修订或产物事件"
    },
    "lease_epoch": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本次提交所用租约代次"
    },
    "payload_hash": {
      "type": "CHAR(64)",
      "required": True,
      "note": "业务内容校验值"
    },
    "payload_relative_path": {
      "type": "VARCHAR(1024)",
      "required": False,
      "note": "对应不可变本地提交记录"
    },
    "record_count": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本次提交的记录数",
      "default": "0"
    },
    "committed_at": {
      "type": "DATETIME(6)",
      "required": True,
      "note": "数据库提交时间"
    }
  },
  "probe_artifact": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属任务"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属执行"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "来源组产物关联；汇总产物为空"
    },
    "scope_type": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "RUN / SOURCE"
    },
    "scope_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "对应 run_id 或 source_group_id"
    },
    "artifact_type": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "产物类型"
    },
    "logical_name": {
      "type": "VARCHAR(128)",
      "required": True,
      "note": "稳定逻辑名称，如 final_xlsx、port_cache"
    },
    "generation_no": {
      "type": "INT UNSIGNED",
      "required": True,
      "note": "文件生成版本",
      "default": "1"
    },
    "display_name": {
      "type": "VARCHAR(255)",
      "required": True,
      "note": "下载显示名称"
    },
    "storage_id": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "存储配置标识",
      "default": "LOCAL"
    },
    "relative_path": {
      "type": "VARCHAR(1024)",
      "required": True,
      "note": "相对存储根目录的路径"
    },
    "mime_type": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "文件媒体类型"
    },
    "file_size": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "文件大小"
    },
    "file_hash": {
      "type": "CHAR(64)",
      "required": False,
      "note": "完成文件的校验值"
    },
    "status": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "WRITING / READY / FAILED",
      "default": "WRITING"
    },
    "stage_code": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "生成阶段"
    },
    "endpoint_id": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "端点证据关联"
    },
    "result_revision_no": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "截图对应的系统结果修订"
    },
    "result_version": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "报告对应的运行结果版本"
    },
    "source_url": {
      "type": "LONGTEXT",
      "required": False,
      "note": "证据采集地址"
    },
    "captured_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "证据采集时间"
    },
    "metadata_json": {
      "type": "LONGTEXT",
      "required": False,
      "note": "截图方式、统计、关联信息等"
    },
    "error_message": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "生成失败摘要"
    },
    "ready_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "文件发布完成时间"
    }
  },
  "probe_task_cleanup_job": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "要删除的任务 ID"
    },
    "request_id": {
      "type": "CHAR(36)",
      "required": True,
      "note": "删除请求去重 ID"
    },
    "status": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "清理作业状态",
      "default": "WAIT_STOP"
    },
    "storage_id": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "任务目录所在存储配置",
      "default": "LOCAL"
    },
    "task_relative_path": {
      "type": "VARCHAR(1024)",
      "required": True,
      "note": "由 task_id 派生的任务根目录"
    },
    "worker_id": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "文件清理执行器"
    },
    "lease_epoch": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "清理租约代次",
      "default": "0"
    },
    "heartbeat_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "清理心跳"
    },
    "lease_expires_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "清理租约到期时间"
    },
    "attempt_no": {
      "type": "INT UNSIGNED",
      "required": True,
      "note": "清理尝试次数",
      "default": "0"
    },
    "retry_after": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "可再次尝试的时间"
    },
    "files_purged_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "文件清理完成时间"
    },
    "data_purged_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "业务数据清理完成时间"
    },
    "requested_by": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "发起人"
    },
    "last_error_code": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "最近错误码"
    },
    "last_error_message": {
      "type": "VARCHAR(2000)",
      "required": False,
      "note": "最近错误摘要"
    },
    "finished_at": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "完成时间"
    }
  },
  "probe_asset_review": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者，即实际复核人；Java 从登录态填写，不接受客户端指定其他用户"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间；Java 写 UTC"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者；追加型复核历史不做 UPDATE，保持 NULL"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间；追加型复核历史不做 UPDATE，保持 NULL"
    },
    "task_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "被复核结果所属任务，须与 asset_port_id 实际归属一致"
    },
    "run_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "被复核结果所属执行；第 n 次通过关联 probe_task_run.run_no 展示，不复制序号"
    },
    "source_group_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "被复核结果所属来源组；同 IP 不同文件的结果仍分别记录"
    },
    "asset_port_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "关联 probe_asset_port.id，是单条复核身份，不以 IP 或端口字符串替代"
    },
    "request_id": {
      "type": "CHAR(36)",
      "required": True,
      "note": "同一任务内一次复核提交的 UUID；超时/断网重试复用原值，主动再次复核使用新值；幂等查询范围为 task_id + request_id"
    },
    "request_hash": {
      "type": "CHAR(64)",
      "required": True,
      "note": "Java 对登录用户、任务/执行、排序去重的完整 assetIds 及各条期望系统版本/哈希、期望人工版本、动作、规范化说明计算的 SHA-256；不包含请求时间；防止同 UUID 被换内容重用"
    },
    "review_no": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本 asset_port_id 内单调递增的人工复核序号，从 1 开始；不是扫描执行序号，也不是系统 revision_no"
    },
    "system_revision_no": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "提交时复核依据的 probe_asset_port.revision_no，由服务端核验并冻结"
    },
    "system_result_hash": {
      "type": "CHAR(64)",
      "required": True,
      "note": "同一系统结果版本的 result_hash，和 system_revision_no 一起校验依据是否变化"
    },
    "system_gpu_likelihood": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "当时系统 GPU 结论快照，HIGH / MEDIUM / LOW / UNKNOWN；本版可提交对象仅限系统 MEDIUM"
    },
    "review_action": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "MAINTAIN / CONFIRM_HIGH / CONFIRM_MID；分别维持当时系统判定、确认为高、调整为中"
    },
    "reviewed_gpu_likelihood": {
      "type": "VARCHAR(16)",
      "required": True,
      "note": "Java 派生的人工结论：MAINTAIN 复制当时系统值，CONFIRM_HIGH=HIGH，CONFIRM_MID=MEDIUM；不直接相信客户端传值"
    },
    "review_remark": {
      "type": "VARCHAR(2000)",
      "required": True,
      "note": "复核说明，去首尾空白后非空、最多 2000 字符；即使维持判定也须填写"
    },
    "reviewed_at": {
      "type": "DATETIME(6)",
      "required": True,
      "note": "实际提交复核的 UTC 时间，Java 生成；同一批次各行使用同一时间"
    }
  },
  "compute_report_batch": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "province_code": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "组织字典的省份标准码"
    },
    "province_name": {
      "type": "VARCHAR(64)",
      "required": True,
      "note": "规范化省份名称，与扫描源记录采用相同名称解析规则，作为名称比对键的一部分"
    },
    "operator_code": {
      "type": "VARCHAR(32)",
      "required": True,
      "note": "组织字典的运营商标准码"
    },
    "operator_name": {
      "type": "VARCHAR(64)",
      "required": True,
      "note": "规范化运营商名称，与扫描源记录采用相同名称解析规则，作为名称比对键的一部分"
    },
    "enterprise_name": {
      "type": "VARCHAR(255)",
      "required": True,
      "note": "规范化省份＋运营商；原始企业文本保留在上传原文件"
    },
    "report_month": {
      "type": "DATE",
      "required": True,
      "note": "上报月份，保存该月首日，如 2026-10-01，API 返回 2026-10"
    },
    "revision_no": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "同企业同月完整覆盖成功后加一，内容相同重传不增加",
      "default": "1"
    },
    "row_count": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "当前有效清单的 IP 段记录数，不是 IP 展开数"
    },
    "content_hash": {
      "type": "CHAR(64)",
      "required": True,
      "note": "本企业规范化全量明细的 SHA-256；判断同企业同月重复上报是否内容相同：相同返回 UNCHANGED，不替换明细、不递增 revision_no。与原文件是否允许编辑无关，不是整个 XLSX 的文件 hash；由 Java 计算和维护"
    },
    "original_name": {
      "type": "VARCHAR(255)",
      "required": True,
      "note": "当前提交原文件名"
    },
    "relative_path": {
      "type": "VARCHAR(1024)",
      "required": True,
      "note": "原文件相对路径，位于独立 compute-imports 目录，不位于 tasks 目录"
    },
    "imported_at": {
      "type": "DATETIME(6)",
      "required": True,
      "note": "最近实际发布全量清单的时间，保存 UTC；页面上报日期由此转换显示"
    },
    "imported_by": {
      "type": "BIGINT UNSIGNED",
      "required": False,
      "note": "发布人"
    }
  },
  "compute_ip": {
    "id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "本表自增主键，PRIMARY KEY"
    },
    "creator": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "创建者"
    },
    "create_date": {
      "type": "DATETIME",
      "required": False,
      "note": "创建时间"
    },
    "updater": {
      "type": "BIGINT(20)",
      "required": False,
      "note": "更新者"
    },
    "update_date": {
      "type": "DATETIME",
      "required": False,
      "note": "更新时间"
    },
    "batch_id": {
      "type": "BIGINT UNSIGNED",
      "required": True,
      "note": "所属 compute_report_batch.id，月份及企业归属以批次为准"
    },
    "enterprise_name": {
      "type": "VARCHAR(255)",
      "required": True,
      "note": "模板“企业名称”去首尾空格并规范化后的企业名称；导入逐行保存，须与所属批次 enterprise_name 一致，不等同于使用人/单位"
    },
    "system_name": {
      "type": "VARCHAR(255)",
      "required": False,
      "note": "模板“系统”，保留原值，不当作扫描状态；业务枚举未定义"
    },
    "house_id": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "模板“机房ID”，业务字符串，不是 compute_house.id；不要求机房台账存在"
    },
    "segment_id": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "模板“IP地址段编号”，保留原值，不作为全局唯一键"
    },
    "start_ip": {
      "type": "VARCHAR(45)",
      "required": True,
      "note": "模板“起始IP地址”，规范化 IPv4/IPv6"
    },
    "end_ip": {
      "type": "VARCHAR(45)",
      "required": True,
      "note": "模板“终止IP地址”，同族且不小于起始地址；原值空时按单 IP 规范化"
    },
    "ip_version": {
      "type": "TINYINT UNSIGNED",
      "required": True,
      "note": "4 / 6"
    },
    "start_ip_bin": {
      "type": "BINARY(16)",
      "required": True,
      "note": "范围比较用大端 16 字节；IPv4 高 12 字节补 0，低 4 字节为 IPv4"
    },
    "end_ip_bin": {
      "type": "BINARY(16)",
      "required": True,
      "note": "与起始地址同一编码；必须结合 ip_version 比较"
    },
    "range_size": {
      "type": "DECIMAL(39,0)",
      "required": True,
      "note": "包含两端的地址数；不得为比对展开全量 IPv6 地址"
    },
    "ip_use_type": {
      "type": "VARCHAR(64)",
      "required": False,
      "note": "模板“IP地址使用方式”，保留文本，未确认编码前不强制转旧 0/1/2"
    },
    "use_unit": {
      "type": "VARCHAR(255)",
      "required": False,
      "note": "模板“使用人或者单位”，不等同于上报企业"
    },
    "source_unit": {
      "type": "VARCHAR(255)",
      "required": False,
      "note": "模板“来源单位”"
    },
    "allocation_unit": {
      "type": "VARCHAR(255)",
      "required": False,
      "note": "模板“分配单位”"
    },
    "allocation_time_raw": {
      "type": "VARCHAR(128)",
      "required": False,
      "note": "模板“分配使用时间”的原始展示值"
    },
    "allocation_time": {
      "type": "DATETIME(6)",
      "required": False,
      "note": "能合法解析时保存 UTC；无时区原值按 Asia/Shanghai 解释，不能代替上报时间"
    }
  }
}
