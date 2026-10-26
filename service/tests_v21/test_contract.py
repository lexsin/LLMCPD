import copy
import json
from datetime import timedelta

import pytest

from llm_detect.v21.common import ContractError, LeaseLost, atomic_json, dumps
from llm_detect.v21.events import Outbox, read_event
from llm_detect.v21.inputs import expand_hosts, validate_inputs, validate_params
from llm_detect.v21.repository import Lease, Repository, insert, update
from .support import SQLiteFixture, seed


def prepared(tmp_path, count=1):
    db=SQLiteFixture()
    repo, task, rid=seed(db,tmp_path,count)
    lease=repo.claim("offline-worker")
    run, files, rows=repo.input_records(lease)
    inputs=validate_inputs(run,files,rows,{"LOCAL":tmp_path})
    repo.freeze(lease,{"schema_version":1,"format":"YAML","content":"fixture"},"hash","fixture-version")
    repo.bind_executor(lease,{"executor":"local"})
    sources=repo.publish_sources(lease,inputs)
    return db,repo,lease,sources


def commit_rows(tmp_path, repo, lease, source, stage, kind, rows, **meta):
    repo.start_stage(lease,source["id"],stage)
    path=Outbox(tmp_path,lease.task_id,lease.run_id,source["id"],stage).emit(kind,rows,**meta)
    event=read_event(path)
    return path,event,repo.commit(lease,event,path.name)


def test_complete_manifest_and_atomic_publication(tmp_path):
    db=SQLiteFixture(); repo,task,rid=seed(db,tmp_path,2)
    lease=repo.claim("a"); run,files,rows=repo.input_records(lease)
    files[1]["parse_status"]="PENDING"
    with pytest.raises(ContractError,match="READY"):
        validate_inputs(run,files,rows,{"LOCAL":tmp_path})
    run["input_snapshot_json"]=dumps({"schema_version":1,"allow_invalid_rows":False,"files":json.loads(run["input_snapshot_json"])["files"][:1]})
    with pytest.raises(ContractError,match="all pre-registered"):
        validate_inputs(run,files,rows,{"LOCAL":tmp_path})
    assert repo.get_run(rid)["started_at"] is None
    db,repo,lease,sources=prepared(tmp_path,2)
    assert len(sources)==2 and all(s["status"]=="PENDING" and s["started_at"] is None for s in sources)
    assert repo.get_run(lease.run_id)["source_total"]==2
    assert repo.get_run(lease.run_id)["started_at"] is not None


def test_source_publication_rollback(tmp_path,monkeypatch):
    db=SQLiteFixture();repo,_,_=seed(db,tmp_path,2);lease=repo.claim("a")
    run,files,rows=repo.input_records(lease);inputs=validate_inputs(run,files,rows,{"LOCAL":tmp_path})
    repo.freeze(lease,{"content":"fixture"},"hash","fixture")
    import llm_detect.v21.repository as module
    original=module.insert
    def fail_second(cur,table,values):
        if table=="probe_run_source" and values["source_order"]==2:
            raise RuntimeError("injected failure")
        return original(cur,table,values)
    monkeypatch.setattr(module,"insert",fail_second)
    with pytest.raises(RuntimeError):repo.publish_sources(lease,inputs)
    assert db.rows("probe_run_source")==[]
    assert repo.get_run(lease.run_id)["started_at"] is None


def test_event_replay_rollback_and_revision(tmp_path,monkeypatch):
    db,repo,lease,sources=prepared(tmp_path);source=sources[0]
    hosts=expand_hosts(json.loads(source["input_snapshot_json"])["rows"],100)
    commit_rows(tmp_path,repo,lease,source,"EXPAND","HOST",hosts)
    assert len(db.rows("probe_host"))==2 and len(db.rows("probe_host_resource"))==3
    commit_rows(tmp_path,repo,lease,source,"PORT_SCAN","PORTS",[{"ip":"192.0.2.2","ports":[80],"scan_mode":"PN"}])
    raw={"ip":"192.0.2.2","port":"80","protocol":"http","is_llm":"确认","gpu_likelihood":"中","npu_likelihood":"未知"}
    repo.start_stage(lease,source["id"],"IDENTIFY")
    path=Outbox(tmp_path,lease.task_id,lease.run_id,source["id"],"IDENTIFY").emit("RESULT",[raw],reason="INITIAL")
    event=read_event(path)
    original=repo._counts
    monkeypatch.setattr(repo,"_counts",lambda *a: (_ for _ in ()).throw(RuntimeError("after result insert")))
    with pytest.raises(RuntimeError):repo.commit(lease,event,path.name)
    assert db.rows("probe_asset_port")==[] and db.rows("probe_asset_port_history")==[]
    monkeypatch.setattr(repo,"_counts",original)
    assert repo.commit(lease,event,path.name)
    version=repo.get_run(lease.run_id)["result_version"]
    assert not repo.commit(lease,event,path.name)
    assert repo.get_run(lease.run_id)["result_version"]==version
    assert len(db.rows("probe_asset_port_history"))==1
    raw["gpu_likelihood"]="高"
    commit_rows(tmp_path,repo,lease,source,"GPU_RECHECK","RESULT",[raw],reason="GPU_RECHECK")
    assert db.rows("probe_asset_port")[0]["revision_no"]==2
    assert len(db.rows("probe_asset_port_history"))==2
    assert db.rows("probe_asset_port")[0]["gpu_likelihood"]=="HIGH"
    assert db.rows("probe_asset_review")==[]


def test_stale_epoch_cannot_write_or_renew(tmp_path):
    db,repo,lease,sources=prepared(tmp_path)
    with db.cursor() as cur:
        update(cur,"probe_task_run",lease.run_id,{"lease_expires_at":db.now(cur)-timedelta(seconds=1)})
    newer=repo.claim("new-worker")
    assert newer.epoch==lease.epoch+1
    with pytest.raises(LeaseLost):repo.heartbeat(lease)
    with pytest.raises(LeaseLost):repo.start_stage(lease,sources[0]["id"],"EXPAND")
    repo.heartbeat(newer)


def test_pause_resume_same_run_and_superseded_control(tmp_path):
    db,repo,lease,sources=prepared(tmp_path)
    with db.cursor() as cur:update(cur,"probe_task_run",lease.run_id,{"requested_action":"PAUSE","request_seq":1})
    assert repo.command(lease)==("PAUSE",1)
    repo.begin_control(lease,"PAUSE")
    with db.cursor() as cur:update(cur,"probe_task_run",lease.run_id,{"requested_action":"STOP","request_seq":2})
    assert not repo.finish_control(lease,"PAUSE",1)
    assert repo.finish_control(lease,"STOP",2)
    assert repo.get_run(lease.run_id)["ack_seq"]==2
    assert repo.get_run(lease.run_id)["status"]=="STOPPED"


def test_resume_preserves_sources_started_at_and_frozen_rules(tmp_path):
    db,repo,lease,sources=prepared(tmp_path)
    started=repo.get_run(lease.run_id)["started_at"]
    with db.cursor() as cur:update(cur,"probe_task_run",lease.run_id,{"requested_action":"PAUSE","request_seq":1})
    repo.finish_control(lease,"PAUSE",1)
    with db.cursor() as cur:update(cur,"probe_task_run",lease.run_id,{"requested_action":"RESUME","request_seq":2})
    newer=repo.claim("new"); run,files,rows=repo.input_records(newer)
    inputs=validate_inputs(run,files,rows,{"LOCAL":tmp_path})
    restored=repo.publish_sources(newer,inputs)
    assert [s["id"] for s in restored]==[s["id"] for s in sources]
    assert repo.get_run(lease.run_id)["started_at"]==started
    assert repo.get_run(lease.run_id)["ack_seq"]==2
    with pytest.raises(ContractError):repo.freeze(newer,{"content":"other"},"newhash","fixture-version")


def test_queued_stop_never_publishes_started_at(tmp_path):
    db=SQLiteFixture();repo,_,rid=seed(db,tmp_path)
    with db.cursor() as cur:update(cur,"probe_task_run",rid,{"requested_action":"STOP","request_seq":1})
    repo.stop_idle_requests("control-worker")
    assert repo.get_run(rid)["status"]=="STOPPED" and repo.get_run(rid)["started_at"] is None
    assert repo.claim("scanner") is None


def test_cross_source_same_endpoint_is_not_merged(tmp_path):
    db,repo,lease,sources=prepared(tmp_path,2)
    for source in sources:
        commit_rows(tmp_path,repo,lease,source,"EXPAND","HOST",expand_hosts(json.loads(source["input_snapshot_json"])["rows"],100))
        commit_rows(tmp_path,repo,lease,source,"IDENTIFY","RESULT",[{"ip":"192.0.2.2","port":"80","is_llm":"否","gpu_likelihood":"低"}])
    assert len(db.rows("probe_endpoint"))==2
    assert len(db.rows("probe_asset_port"))==2
    exported,_=repo.result_rows(lease)
    assert len({r["source_group_id"] for r in exported})==2


def test_event_corruption_and_sequence_gap(tmp_path):
    db,repo,lease,sources=prepared(tmp_path);sid=sources[0]["id"]
    repo.start_stage(lease,sid,"EXPAND")
    box=Outbox(tmp_path,lease.task_id,lease.run_id,sid,"EXPAND")
    first=box.emit("HOST",[]);second=box.emit("HOST",[])
    with pytest.raises(ContractError,match="sequence"):repo.commit(lease,read_event(second),second.name)
    bad=json.loads(first.read_text());bad["rows"]=[{"tampered":True}];atomic_json(first,bad)
    with pytest.raises(ContractError,match="invalid durable"):read_event(first)


def test_artifact_not_ready_on_version_change(tmp_path):
    db,repo,lease,sources=prepared(tmp_path)
    aid=repo.reserve_artifact(lease,None,"FINAL_XLSX","final_xlsx","test.xlsx","RUN_FINALIZE",0)
    assert db.rows("probe_artifact")[0]["status"]=="WRITING"
    with db.cursor() as cur:update(cur,"probe_task_run",lease.run_id,{"result_version":1})
    with pytest.raises(ContractError):repo.artifact_ready(lease,aid,"tasks/1/a.xlsx",12,"hash","mime",0)
    assert db.rows("probe_artifact")[0]["status"]=="WRITING"


def test_preferred_recovery_does_not_claim_another_queued_run(tmp_path):
    db,repo,lease,sources=prepared(tmp_path)
    other=tmp_path/"another";other.mkdir()
    _,_,second=seed(db,other)
    assert repo.claim("replacement",preferred_id=lease.run_id) is None
    assert repo.get_run(second)["status"]=="QUEUED"
