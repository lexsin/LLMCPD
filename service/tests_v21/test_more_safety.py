import json
from types import SimpleNamespace

import pytest

from llm_detect.v21.common import ContractError, LeaseLost, atomic_json
from llm_detect.v21.config import Config
from llm_detect.v21.remote import RemoteJob
from llm_detect.v21.repository import update
from .test_contract import prepared


def test_no_ready_artifacts_are_reclassified_on_recovery(tmp_path):
    db,repo,lease,sources=prepared(tmp_path)
    first=repo.reserve_artifact(lease,None,"FINAL_CSV","final_csv","a.csv","RUN_FINALIZE",0)
    repo.artifact_ready(lease,first,"tasks/1/result.csv",12,"hash","text/csv",0)
    second=repo.reserve_artifact(lease,None,"FINAL_XLSX","final_xlsx","a.xlsx","RUN_FINALIZE",0)
    repo.fail_abandoned_artifacts(lease)
    states={r["id"]:r["status"] for r in db.rows("probe_artifact")}
    assert states=={first:"READY",second:"FAILED"}


def test_remote_stop_does_not_treat_transport_failure_as_absence():
    job=RemoteJob.__new__(RemoteJob);job.helper="/job/bin/service_remote.py";job.job="/job"
    def disconnected(*args):raise OSError("SSH disconnected")
    job.transport=SimpleNamespace(ssh=disconnected)
    with pytest.raises(OSError):job.rpc("stop")
    job.transport=SimpleNamespace(ssh=lambda *a:SimpleNamespace(stdout="unknown"))
    with pytest.raises(ContractError,match="metadata remains"):job.rpc("stop")
    job.transport=SimpleNamespace(ssh=lambda *a:SimpleNamespace(stdout="absent"))
    assert job.rpc("stop")=={"state":"stopped"}


def test_started_run_requires_complete_sources_on_recovery(tmp_path):
    db,repo,lease,sources=prepared(tmp_path,2)
    run,files,rows=repo.input_records(lease)
    from llm_detect.v21.inputs import validate_inputs
    inputs=validate_inputs(run,files,rows,{"LOCAL":tmp_path})
    with db.cursor() as cur:cur.execute("DELETE FROM probe_run_source WHERE id=%s",(sources[1]["id"],))
    with pytest.raises(ContractError,match="incomplete"):repo.publish_sources(lease,inputs)


def test_writes_revoked_when_task_deleted(tmp_path):
    db,repo,lease,sources=prepared(tmp_path)
    with db.cursor() as cur:
        update(cur,"probe_task",lease.task_id,{"lifecycle_status":"DELETE_REQUESTED"})
        update(cur,"probe_task_run",lease.run_id,{"requested_action":"STOP","request_seq":1})
    with pytest.raises(LeaseLost):repo.start_stage(lease,sources[0]["id"],"EXPAND")
    assert repo.command(lease)==("STOP",1)
    repo.begin_control(lease,"STOP")
    assert repo.finish_control(lease,"STOP",1)


def test_wrong_config_or_missing_environment_is_rejected(tmp_path,monkeypatch):
    config=tmp_path/"config.yaml";config.write_text("database: {}",encoding="utf-8")
    with pytest.raises(ContractError):Config.load(config)
    config.write_text("contract_version: '2.1'\ndatabase:\n  password: env:V7_TEST_MISSING_SECRET\n",encoding="utf-8")
    monkeypatch.delenv("V7_TEST_MISSING_SECRET",raising=False)
    with pytest.raises(ContractError):Config.load(config)


def test_proof_hash_ignores_only_empty_csv_padding():
    from llm_detect.v21.common import proof_hash
    assert proof_hash({"ip":"192.0.2.1","port":"80"})==proof_hash({"ip":"192.0.2.1","port":"80","active_probe_api":""})
    assert proof_hash({"ip":"192.0.2.1","gpu_evidence":"old"})!=proof_hash({"ip":"192.0.2.1","gpu_evidence":"new"})
