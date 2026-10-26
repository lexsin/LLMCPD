"""Required uniqueness from the 2.1 document; used only for read-only validation."""
UNIQUE_INDEXES = {
  "probe_task_run": {
    "uk_run_no": [
      "task_id",
      "run_no"
    ]
  },
  "probe_run_source": {
    "uk_run_file": [
      "run_id",
      "file_id"
    ]
  },
  "probe_run_stage": {
    "uk_source_stage": [
      "run_id",
      "source_group_id",
      "stage_code"
    ]
  },
  "probe_host": {
    "uk_source_host": [
      "run_id",
      "source_group_id",
      "host_ip"
    ]
  },
  "probe_host_resource": {
    "uk_host_resource": [
      "host_id",
      "resource_id"
    ]
  },
  "probe_endpoint": {
    "uk_source_endpoint": [
      "run_id",
      "source_group_id",
      "host_ip",
      "port"
    ]
  },
  "probe_asset_port": {
    "uk_asset_endpoint": [
      "endpoint_id"
    ],
    "uk_asset_scope": [
      "run_id",
      "source_group_id",
      "host_ip",
      "port"
    ]
  },
  "probe_asset_port_history": {
    "uk_asset_revision": [
      "asset_port_id",
      "revision_no"
    ]
  },
  "probe_scan_event": {
    "uk_event": [
      "event_id"
    ]
  },
  "probe_artifact": {
    "uk_artifact_version": [
      "scope_type",
      "scope_id",
      "artifact_type",
      "logical_name",
      "generation_no"
    ]
  },
  "probe_task_cleanup_job": {
    "uk_cleanup_request": [
      "request_id"
    ],
    "uk_cleanup_task": [
      "task_id"
    ]
  },
  "probe_asset_review": {
    "uk_review_asset_no": [
      "asset_port_id",
      "review_no"
    ],
    "uk_review_request_asset": [
      "request_id",
      "asset_port_id"
    ]
  },
  "compute_report_batch": {
    "uk_compute_enterprise_month": [
      "province_code",
      "operator_code",
      "report_month"
    ],
    "uk_compute_enterprise_name_month": [
      "province_name",
      "operator_name",
      "report_month"
    ]
  }
}
