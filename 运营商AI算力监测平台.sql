-- ============================================================================
-- 运营商AI算力监测平台 · 业务与配置表 DDL
-- 库：MySQL 8.0+，utf8mb4 / utf8mb4_general_ci
-- 约定：账号与权限由平台脚手架 sys_* 承担，本脚本不含用户/角色/菜单等系统管理类表
-- JSON 形态列仅存 TEXT，不使用 MySQL JSON 类型；列注释遵循 sa-design-database 分段规则
-- 表清单：
--   config_llm_platform         大模型开源平台配置（端口、URL路径、检测URL）
--   config_llm_provider         大模型厂商配置（类型、名称、Web/API域名JSON）
--   config_llm_http_feature       大模型 HTTP 特征配置（类型、字段、取值）
--   compute_house          算力报备 · 机房主数据（含网络信息安全责任人）
--   compute_house_frame    算力报备 · 机架信息（从属于机房）
--   compute_ip             算力报备 · IP 地址段（从属于机房；含检测状态摘要）
--   compute_llm            算力报备 · 大模型情况台账
--   compute_detect_ip          报备检测 · IP 级（说明与复核）
--   compute_detect_port        报备检测 · 端口级比对记录
--   probe_task                     IP 探测 · 任务
--   probe_pending_resource         IP 探测 · 待探测资源（受理录入）
--   probe_host                     IP 探测 · 主机（Nmap 过程）
--   probe_endpoint                 IP 探测 · 端点 IP:端口（分型探测过程）
--   probe_asset_port                 IP 探测 · 任务维度端口资产
--   probe_asset_ip                   IP 探测 · 资产 IP 级复核
--   asset_llm                       大模型资产
--   report_info                     报告信息
-- 执行顺序：compute_house → compute_house_frame / compute_ip；
--           compute_detect_ip → compute_detect_port；
--           probe_task → probe_pending_resource / probe_host → probe_endpoint；
--           probe_asset_port / probe_asset_ip；asset_llm；
--           report_info
-- ============================================================================

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `config_llm_platform` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `platform_name` varchar(128) NOT NULL COMMENT '平台名称',
  `platform_ports` text COMMENT '平台端口列表 | Json [{"port":443,"desc":"HTTPS推理"},{"port":8080,"desc":"管理后台"}]',
  `platform_urls` text COMMENT '平台URL路径列表 | Json [{"path":"/v1/chat/completions","desc":"对话补全API"},{"path":"/health","desc":"存活探测"}]',
  `check_url` varchar(1024) NOT NULL COMMENT '检测URL | 备注 用于主动探测或存证；可为相对路径，由引擎与目标IP端口拼装基址',
  `sort_order` int NOT NULL DEFAULT '0' COMMENT '展示排序 | 备注 数值越小越靠前',
  `enabled` tinyint NOT NULL DEFAULT '1' COMMENT '是否启用 | 取值 0=否;1=是',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  KEY `idx_platform_name` (`platform_name`),
  KEY `idx_enabled` (`enabled`,`sort_order`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='大模型开源平台配置表';

CREATE TABLE IF NOT EXISTS `config_llm_provider` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `provider_type` tinyint NOT NULL COMMENT '服务商类型 | 取值 1=国内大模型服务商;2=国外大模型服务商;3=聚合网关类;4=平台方',
  `provider_name` varchar(256) NOT NULL COMMENT '服务商名称',
  `web_domain` text COMMENT 'Web站点域名列表 | Json [{"host":"www.example.com","desc":"官网首页"},{"host":"docs.example.com","desc":"文档站"}]',
  `api_domain` text COMMENT 'API服务域名列表 | Json [{"host":"api.example.com","basePath":"/v1","desc":"开放API网关"}]',
  `sort_order` int NOT NULL DEFAULT '0' COMMENT '展示排序 | 备注 数值越小越靠前',
  `enabled` tinyint NOT NULL DEFAULT '1' COMMENT '是否启用 | 取值 0=否;1=是',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_provider_name_type` (`provider_name`,`provider_type`),
  KEY `idx_provider_type` (`provider_type`),
  KEY `idx_enabled` (`enabled`,`sort_order`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='大模型厂商配置表';

CREATE TABLE IF NOT EXISTS `config_llm_http_feature` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `feature_type` varchar(64) NOT NULL COMMENT '特征类型 | 备注 与流量识别或探测引擎约定的分类，如RequestHeader、UrlPath、BodyMarker等',
  `feature_field` varchar(256) NOT NULL COMMENT '特征字段 | 备注 如HTTP头名、URL关键字、响应体片段名等',
  `feature_value` varchar(4000) NOT NULL COMMENT '特征值 | 备注 字面量、前缀、正则等，解释规则由引擎与本文档迭代约定',
  `sort_order` int NOT NULL DEFAULT '0' COMMENT '同类型内排序 | 备注 越小越优先尝试',
  `enabled` tinyint NOT NULL DEFAULT '1' COMMENT '是否启用 | 取值 0=否;1=是',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_type_field` (`feature_type`,`feature_field`(191)),
  KEY `idx_feature_type` (`feature_type`,`enabled`,`sort_order`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='大模型HTTP特征配置表';

-- ----------------------------------------------------------------------------
-- 算力报备主数据
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `compute_house` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `report_batch` varchar(32) NOT NULL COMMENT '报备批次',
  `province` varchar(32) NOT NULL DEFAULT '' COMMENT '组织范围-省',
  `operator` varchar(16) NOT NULL DEFAULT '' COMMENT '组织范围-运营商',
  `report_time` datetime DEFAULT NULL COMMENT '导入时间',
  `house_id` bigint unsigned NOT NULL COMMENT '报送机房ID | 备注 IRCS经营者产生，同批次内惟一',
  `house_name` varchar(128) NOT NULL COMMENT '机房名称 | 备注 涉人工智能算力业务须在实际名称后加「-算力」',
  `house_type` int NOT NULL COMMENT '机房性质 | 备注 编码见报送规范10.4节',
  `house_province` bigint unsigned NOT NULL COMMENT '机房所在省或直辖市代码 | 备注 GB/T 2260-2007 六位行政区划数字代码',
  `house_city` bigint unsigned NOT NULL COMMENT '机房所在市或区（县）代码 | 备注 GB/T 2260-2007 六位行政区划数字代码',
  `house_county` bigint unsigned DEFAULT NULL COMMENT '机房所在县代码 | 备注 GB/T 2260-2007 六位行政区划数字代码；选填',
  `house_add` varchar(128) NOT NULL COMMENT '机房通信地址',
  `house_zip` varchar(6) DEFAULT NULL COMMENT '邮编 | 备注 对应机房通信地址',
  `officer_name` varchar(64) NOT NULL COMMENT '网络信息安全责任人姓名',
  `officer_id_type` tinyint DEFAULT NULL COMMENT '责任人证件类型 | 备注 编码见报送规范表30',
  `officer_id_no` varchar(32) DEFAULT NULL COMMENT '责任人证件号码',
  `officer_tel` varchar(32) DEFAULT NULL COMMENT '责任人固定电话',
  `officer_mobile` varchar(32) DEFAULT NULL COMMENT '责任人移动电话',
  `officer_email` varchar(128) DEFAULT NULL COMMENT '责任人电子邮箱',
  `enabled` tinyint NOT NULL DEFAULT '1' COMMENT '是否启用 | 取值 0=停用;1=启用 | 备注 停用机房不参与新建检测任务',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_report_batch_house_id` (`report_batch`,`house_id`),
  KEY `idx_report_batch` (`report_batch`),
  KEY `idx_org_scope` (`province`,`operator`),
  KEY `idx_region` (`house_province`,`house_city`,`house_county`),
  KEY `idx_enabled` (`enabled`,`house_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='算力报备机房主数据表';

CREATE TABLE IF NOT EXISTS `compute_house_frame` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `report_batch` varchar(32) NOT NULL COMMENT '报备批次',
  `province` varchar(32) NOT NULL DEFAULT '' COMMENT '组织范围-省',
  `operator` varchar(16) NOT NULL DEFAULT '' COMMENT '组织范围-运营商',
  `report_time` datetime DEFAULT NULL COMMENT '导入时间',
  `compute_house_id` bigint unsigned NOT NULL COMMENT '所属机房主键',
  `frame_id` bigint unsigned NOT NULL COMMENT '机架信息ID | 备注 企业侧ISMS定义，机房内惟一',
  `use_type` tinyint NOT NULL COMMENT '使用类型 | 取值 1=自用;2=出租',
  `distribution` tinyint NOT NULL COMMENT '分配状态 | 取值 1=未分配;2=已分配',
  `occupancy` tinyint NOT NULL COMMENT '占用状态 | 取值 1=未占用;2=已占用',
  `frame_name` varchar(128) NOT NULL COMMENT '机架或机位名称',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_house_frame` (`compute_house_id`,`frame_id`),
  KEY `idx_report_batch` (`report_batch`),
  KEY `idx_frame_name` (`frame_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='算力报备机架信息表';

CREATE TABLE IF NOT EXISTS `compute_ip` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `report_batch` varchar(32) NOT NULL COMMENT '报备批次',
  `province` varchar(32) NOT NULL DEFAULT '' COMMENT '组织范围-省',
  `operator` varchar(16) NOT NULL DEFAULT '' COMMENT '组织范围-运营商',
  `report_time` datetime DEFAULT NULL COMMENT '导入时间',
  `compute_house_id` bigint unsigned NOT NULL COMMENT '所属机房主键',
  `segment_id` bigint unsigned NOT NULL COMMENT 'IP地址段序号 | 备注 企业侧ISMS定义，机房内惟一',
  `start_ip` varchar(64) NOT NULL COMMENT '起始IP地址',
  `end_ip` varchar(64) NOT NULL COMMENT '终止IP地址 | 备注 与起始相同时表示单地址',
  `ip_use_type` tinyint NOT NULL COMMENT 'IP地址使用方式 | 取值 0=静态;1=动态;2=保留',
  `source_unit` varchar(128) NOT NULL COMMENT '来源单位 | 备注 自有填本单位，用户携带填用户单位',
  `allocation_unit` varchar(128) NOT NULL COMMENT '上级分配单位 | 备注 集团/省/市公司或ICANN、APNIC等',
  `allocation_time` date NOT NULL COMMENT '分配时间 | 备注 报送格式 yyyy-MM-dd',
  `use_unit` varchar(128) NOT NULL COMMENT '使用单位 | 备注 算力IP须在名称后加「-算力」',
  `detect_status` varchar(16) NOT NULL DEFAULT 'NOT_STARTED' COMMENT '检测状态 | 取值 NOT_STARTED=未检测;RUNNING=检测中;SUCCESS=已完成;FAILED=失败',
  `app_type_code` tinyint DEFAULT NULL COMMENT '应用类型 | 取值 0=API调用;1=平台化服务;2=定制化/私有化部署;3=模型即服务',
  `asset_verdict` tinyint DEFAULT NULL COMMENT '资产判定 | 取值 0=非LLM/不足证;1=已确认LLM;2=疑似LLM',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_house_segment` (`compute_house_id`,`segment_id`),
  KEY `idx_report_batch` (`report_batch`),
  KEY `idx_org_scope` (`province`,`operator`),
  KEY `idx_detect_status` (`detect_status`),
  KEY `idx_start_ip` (`start_ip`),
  KEY `idx_use_unit` (`use_unit`(64))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='算力报备IP地址段表';

CREATE TABLE IF NOT EXISTS `compute_llm` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `report_batch` varchar(32) NOT NULL COMMENT '报备批次',
  `province` varchar(32) NOT NULL DEFAULT '' COMMENT '组织范围-省',
  `operator` varchar(16) NOT NULL DEFAULT '' COMMENT '组织范围-运营商',
  `report_time` datetime DEFAULT NULL COMMENT '导入时间',
  `model_seq_id` bigint unsigned NOT NULL COMMENT '大模型序号 | 备注 企业侧定义，同批次内惟一',
  `model_name` varchar(128) NOT NULL COMMENT '大模型名称',
  `model_version` varchar(64) NOT NULL COMMENT '大模型版本号',
  `developer_type` tinyint NOT NULL COMMENT '模型研发方类型 | 取值 0=自研;1=第三方国产;2=第三方海外',
  `service_mode` tinyint NOT NULL COMMENT '服务方式 | 取值 0=API调用;1=平台化服务;2=定制化/私有化部署;3=模型即服务',
  `launch_date` date NOT NULL COMMENT '服务上线日期 | 备注 报送格式 yyyy-MM-dd',
  `service_status` tinyint NOT NULL COMMENT '服务状态 | 取值 0=在线服务中;1=已下线;2=内测/公测中',
  `infra_type` tinyint NOT NULL COMMENT '计算基础设施类型 | 取值 0=自建算力集群;1=租赁算力（国内）;2=租赁算力（海外）;3=混合模式',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_report_batch_model_seq` (`report_batch`,`model_seq_id`),
  KEY `idx_report_batch` (`report_batch`),
  KEY `idx_org_scope` (`province`,`operator`),
  KEY `idx_model_name` (`model_name`),
  KEY `idx_service_status` (`service_status`,`launch_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='算力报备大模型情况表';

-- ----------------------------------------------------------------------------
-- 报备检测
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `compute_detect_ip` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `report_batch` varchar(32) NOT NULL COMMENT '报备批次',
  `host_ip` varchar(64) NOT NULL COMMENT '主机IP',
  `province` varchar(32) NOT NULL DEFAULT '' COMMENT '组织范围-省',
  `operator` varchar(16) NOT NULL DEFAULT '' COMMENT '组织范围-运营商',
  `house_name` varchar(128) DEFAULT NULL COMMENT '所属机房名称',
  `report_desc` text COMMENT '报备侧说明',
  `review_conclusion` varchar(32) NOT NULL COMMENT '人工复核结论 | 取值 MAINTAIN=维持系统结论;CONFIRM_MATCH=人工确认一致;CONFIRM_MISMATCH=人工确认不一致',
  `review_remark` varchar(2000) NOT NULL COMMENT '复核说明',
  `reviewer` bigint unsigned DEFAULT NULL COMMENT '复核人',
  `review_date` datetime NOT NULL COMMENT '复核时间',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_batch_host_ip` (`report_batch`,`host_ip`),
  KEY `idx_host_ip` (`host_ip`),
  KEY `idx_org_scope` (`province`,`operator`),
  KEY `idx_review_date` (`review_date` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='报备IP检测表';

CREATE TABLE IF NOT EXISTS `compute_detect_port` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `detect_id` bigint unsigned DEFAULT NULL COMMENT 'IP级主键',
  `host_ip` varchar(64) NOT NULL COMMENT '主机IP',
  `port` int unsigned NOT NULL COMMENT '端口',
  `compare_status` tinyint NOT NULL DEFAULT '1' COMMENT '比对状态 | 取值 0=一致;1=待复核;2=不一致',
  `check_time` datetime NOT NULL COMMENT '核验时间',
  `detect_desc` text COMMENT '检测侧说明',
  `rule_snap` text COMMENT '比对规则快照 | Json {"ruleSetId":"report-cmp-2026.05","branch":"path"}',
  `fingerprint_snap` text COMMENT '检测指纹摘要 | Json {"httpStatus":200,"titleHit":true}',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  KEY `idx_detect_id` (`detect_id`),
  KEY `idx_host_port` (`host_ip`,`port`),
  KEY `idx_compare_status` (`compare_status`,`check_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='报备IP检测端口表';

-- ----------------------------------------------------------------------------
-- IP 探测
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `probe_task` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `task_name` varchar(256) NOT NULL COMMENT '任务名称',
  `task_desc` varchar(2000) DEFAULT NULL COMMENT '任务描述',
  `biz_date` date NOT NULL COMMENT '业务/核查日',
  `status` varchar(32) NOT NULL DEFAULT 'PENDING' COMMENT '任务状态 | 取值 PENDING=待受理;RUNNING=执行中;STOPPED=已停止;SUCCESS=成功;PARTIAL=部分成功;FAILED=失败',
  `param_json` text NOT NULL COMMENT '任务参数 | Json {"ipSegments":[],"expandCap":1024,"nmapProfile":"DEFAULT_LLM_TOP200"}',
  `host_total` int unsigned NOT NULL DEFAULT '0' COMMENT '主机总数',
  `host_finished` int unsigned NOT NULL DEFAULT '0' COMMENT '已完成主机数',
  `endpoint_total` int unsigned NOT NULL DEFAULT '0' COMMENT '端点总数',
  `endpoint_finished` int unsigned NOT NULL DEFAULT '0' COMMENT '已完成端点数',
  `start_time` datetime DEFAULT NULL COMMENT '开始执行时间',
  `end_time` datetime DEFAULT NULL COMMENT '结束时间',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  KEY `idx_status` (`status`),
  KEY `idx_biz_date` (`biz_date`),
  KEY `idx_create_date` (`create_date` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP探测任务表';

CREATE TABLE IF NOT EXISTS `probe_pending_resource` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `task_id` bigint unsigned NOT NULL COMMENT '所属任务',
  `resource_type` varchar(32) NOT NULL COMMENT '资源类型 | 取值 IP_SEGMENT=IP段;SINGLE_IP=单IP;IP_PORT=IP+端口',
  `resource_value` varchar(2048) NOT NULL COMMENT '资源值',
  `insert_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '插入时间',
  PRIMARY KEY (`id`),
  KEY `idx_task_id` (`task_id`),
  KEY `idx_insert_time` (`insert_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP探测待探测资源表';

CREATE TABLE IF NOT EXISTS `probe_host` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `task_id` bigint unsigned NOT NULL COMMENT '所属任务',
  `host_ip` varchar(64) NOT NULL COMMENT '主机IP',
  `host_phase` varchar(32) DEFAULT NULL COMMENT '主机阶段 | 取值 PENDING_SCAN=待扫描;SCANNING=扫描中;PROBING=分型探测中;VERDICT_DONE=判定完成',
  `open_ports_json` text COMMENT '开放端口快照 | Json [{"port":443,"proto":"tcp","service":"https"}]',
  `probe_info` varchar(1000) DEFAULT NULL COMMENT '探测信息 | 备注 如无端口开放、不可探测、主机不可达等',
  `scan_start_time` datetime DEFAULT NULL COMMENT '扫描开始时间',
  `scan_end_time` datetime DEFAULT NULL COMMENT '扫描结束时间',
  `insert_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '插入时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_task_host_ip` (`task_id`,`host_ip`),
  KEY `idx_task_id` (`task_id`),
  KEY `idx_host_phase` (`host_phase`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP探测主机表';

CREATE TABLE IF NOT EXISTS `probe_endpoint` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `task_id` bigint unsigned NOT NULL COMMENT '所属任务',
  `host_ip` varchar(64) NOT NULL COMMENT '主机IP',
  `port` int unsigned NOT NULL COMMENT 'TCP端口',
  `probe_shape` varchar(16) NOT NULL DEFAULT 'UNKNOWN' COMMENT '探测形态 | 取值 FRAMEWORK=开源框架/API;WEB=Web应用;UNKNOWN=未分型',
  `endpoint_status` varchar(32) NOT NULL DEFAULT 'PENDING' COMMENT '端点状态 | 取值 PENDING=待探测;RUNNING=探测中;SUCCESS=成功;FAILED=失败',
  `probe_start_time` datetime DEFAULT NULL COMMENT '分型探测开始时间',
  `probe_end_time` datetime DEFAULT NULL COMMENT '分型探测结束时间',
  `insert_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '插入时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_task_host_port` (`task_id`,`host_ip`,`port`),
  KEY `idx_task_id` (`task_id`),
  KEY `idx_host_ip_port` (`host_ip`,`port`),
  KEY `idx_endpoint_status` (`endpoint_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP探测端点表';

CREATE TABLE IF NOT EXISTS `probe_asset_port` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `task_id` bigint unsigned NOT NULL COMMENT '所属任务',
  `host_ip` varchar(64) NOT NULL COMMENT '主机IP',
  `port` int unsigned NOT NULL COMMENT 'TCP端口',
  `probe_shape` varchar(16) DEFAULT NULL COMMENT '探测形态 | 取值 FRAMEWORK;WEB;UNKNOWN',
  `app_type_code` tinyint DEFAULT NULL COMMENT '应用类型 | 取值 0=API调用;1=平台化服务;2=定制化/私有化部署;3=模型即服务',
  `asset_verdict` tinyint NOT NULL COMMENT '资产判定 | 取值 0=非LLM/不足证;1=已确认LLM;2=疑似LLM',
  `verdict_rule_json` text COMMENT '判定规则快照 | Json {"ruleSetId":"llm-probe-2026.05","matchedBranches":[]}',
  `fingerprint_json` text COMMENT '指纹摘要 | Json {"httpStatus":200,"titleSnippet":"…"}',
  `detect_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '检测/判定时间',
  `insert_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '插入时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_task_host_port` (`task_id`,`host_ip`,`port`),
  KEY `idx_task_id` (`task_id`),
  KEY `idx_host_port` (`host_ip`,`port`),
  KEY `idx_asset_verdict` (`asset_verdict`,`detect_time` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP探测资产端口表';

CREATE TABLE IF NOT EXISTS `probe_asset_ip` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `task_id` bigint unsigned NOT NULL COMMENT '所属任务',
  `host_ip` varchar(64) NOT NULL COMMENT '主机IP',
  `review_conclusion` varchar(32) NOT NULL COMMENT '人工复核结论 | 取值 MAINTAIN=维持系统判定;CONFIRM_LLM=确认为LLM服务;CONFIRM_NON=确认为非LLM/不足证',
  `review_remark` varchar(2000) NOT NULL COMMENT '复核说明',
  `reviewer` bigint unsigned DEFAULT NULL COMMENT '复核人',
  `review_date` datetime NOT NULL COMMENT '复核时间',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_task_host_ip` (`task_id`,`host_ip`),
  KEY `idx_task_id` (`task_id`),
  KEY `idx_review_date` (`review_date` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP探测资产IP表';

-- ----------------------------------------------------------------------------
-- 资产管理
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `asset_llm` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `host_ip` varchar(64) NOT NULL COMMENT '主机IP',
  `port` int unsigned NOT NULL COMMENT 'TCP端口',
  `province` varchar(32) NOT NULL DEFAULT '' COMMENT '组织范围-省',
  `operator` varchar(16) NOT NULL DEFAULT '' COMMENT '组织范围-运营商',
  `house_name` varchar(128) DEFAULT NULL COMMENT '所属机房名称',
  `reported` tinyint NOT NULL DEFAULT '0' COMMENT '是否报备 | 取值 0=否;1=是',
  `detect_source` varchar(16) NOT NULL DEFAULT 'IP_PROBE' COMMENT '检测来源 | 取值 REPORT_DETECT=报备检测;IP_PROBE=IP探测;BOTH=双来源',
  `probe_shape` varchar(16) DEFAULT NULL COMMENT '探测形态 | 取值 FRAMEWORK;WEB;UNKNOWN',
  `app_type_code` tinyint DEFAULT NULL COMMENT '服务方式 | 取值 0=API调用;1=平台化服务;2=定制化/私有化部署;3=模型即服务',
  `asset_verdict` tinyint NOT NULL COMMENT '是否大模型 | 取值 0=非LLM/不足证;1=已确认LLM;2=疑似LLM',
  `alive_status` tinyint NOT NULL DEFAULT '1' COMMENT '存活状态 | 取值 0=失效;1=存活',
  `verdict_rule_json` text COMMENT '判定规则快照 | Json',
  `fingerprint_json` text COMMENT '指纹摘要 | Json',
  `detect_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '最近检测时间',
  `insert_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '插入时间',
  `update_time` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_host_port` (`host_ip`,`port`),
  KEY `idx_org_scope` (`province`,`operator`),
  KEY `idx_reported` (`reported`),
  KEY `idx_detect_source` (`detect_source`),
  KEY `idx_detect_time` (`detect_time` DESC),
  KEY `idx_asset_verdict` (`asset_verdict`),
  KEY `idx_alive_status` (`alive_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='大模型资产全局表';

-- ----------------------------------------------------------------------------
-- 报告管理
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `report_info` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
  `report_name` varchar(256) NOT NULL COMMENT '报告名称',
  `report_type` varchar(16) NOT NULL COMMENT '报告类型 | 取值 ENTERPRISE=企业;PROVINCE=省份;NATION=全国',
  `status` varchar(16) NOT NULL DEFAULT 'GENERATING' COMMENT '状态 | 取值 GENERATING=生成中;SUCCESS=已完成;FAILED=失败',
  `file_path` varchar(1024) DEFAULT NULL COMMENT '文件存储路径',
  `file_size` bigint unsigned DEFAULT NULL COMMENT '文件大小字节',
  `finish_time` datetime DEFAULT NULL COMMENT '生成完成时间',
  `creator` bigint unsigned DEFAULT NULL COMMENT '创建人',
  `create_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updater` bigint unsigned DEFAULT NULL COMMENT '更新人',
  `update_date` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  KEY `idx_status` (`status`),
  KEY `idx_report_type` (`report_type`),
  KEY `idx_create_date` (`create_date` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='报告信息表';
