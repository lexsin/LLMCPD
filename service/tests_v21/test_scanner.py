import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

from llm_detect.v21.common import ContractError, atomic_json, proof_hash
from llm_detect.v21.config import DEFAULT_RELEASE, SERVICE_ROOT
from llm_detect.v21.events import Outbox, read_event
from llm_detect.v21.inputs import expand_hosts, validate_params
from llm_detect.v21.stage_worker import restore_checkpoints, write_csv

RELEASE = SERVICE_ROOT / "vendor/v7" / DEFAULT_RELEASE
UPSTREAM = SERVICE_ROOT.parent / "TEST/strategy_v7_active_gpu_20260916"


def module_at(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def scanner(monkeypatch):
    monkeypatch.syspath_prepend(str(RELEASE))
    monkeypatch.delenv("LLM_SERVICE_CONTEXT",raising=False)
    return module_at(RELEASE / "scan_llm.py","offline_v7_scanner")


def test_original_and_adapted_pipeline_same_offline_results(tmp_path,monkeypatch,scanner):
    original=module_at(UPSTREAM / "scan_llm.py","offline_original_v7")
    outputs=[]
    for index, module in enumerate((original,scanner)):
        async def phase0(targets,*args,m=module,**kwargs):
            return [m.TargetState(ip=ip,port=port,protocol="http",service_type="普通Web",gpu_likelihood="低") for ip,port in targets]
        async def unchanged(states,*args,**kwargs):return states
        for name in ("phase1_fingerprint","phase2_deploy","phase3_model","phase_gpu_discovery","phase_gpu_openapi"):
            monkeypatch.setattr(module,name,unchanged)
        monkeypatch.setattr(module,"phase0_protocol",phase0)
        monkeypatch.setattr(module,"_now",lambda:"2026-10-25 00:00:00")
        path=tmp_path / f"result-{index}.csv"
        asyncio.run(module.run_pipeline([("192.0.2.1","80"),("192.0.2.1","8080")],path,tmp_path / f"checkpoint-{index}.jsonl",set(),module.get_default_config(),batch_size=1))
        outputs.append(module.read_csv_rows_preserve(path)[1])
    assert outputs[0]==outputs[1]
    assert not (tmp_path / "outbox").exists()


def test_result_durable_before_native_checkpoint(tmp_path,monkeypatch,scanner):
    cfg={"run_root":str(tmp_path),"source_root":str(tmp_path),"task_id":1,"run_id":2,"source_id":3,"stage":"IDENTIFY","control_file":str(tmp_path/"control.json")}
    path=tmp_path / "context.json";atomic_json(path,cfg)
    monkeypatch.setenv("LLM_SERVICE_CONTEXT",str(path))
    import service_hooks
    monkeypatch.setattr(service_hooks,"_writer",None)
    async def phase0(targets,*args,**kwargs):return [scanner.TargetState(ip=ip,port=port) for ip,port in targets]
    monkeypatch.setattr(scanner,"phase0_protocol",phase0)
    def crash_after_result(*args):
        events=list((tmp_path / "outbox/3_IDENTIFY").glob("*.json"))
        assert events and read_event(events[0])["rows"][0]["ip"]=="192.0.2.1"
        raise RuntimeError("crash before checkpoint")
    monkeypatch.setattr(scanner,"append_checkpoint",crash_after_result)
    with pytest.raises(RuntimeError):
        asyncio.run(scanner.run_pipeline([("192.0.2.1","80")],tmp_path/"identify.csv",tmp_path/"identify.jsonl",set(),scanner.get_default_config()))
    restore_checkpoints(cfg)
    assert scanner.load_checkpoint(tmp_path/"identify.jsonl")=={"192.0.2.1:80"}


def test_active_inflight_is_not_automatically_reinferred(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(RELEASE))
    cfg={"run_root":str(tmp_path),"source_root":str(tmp_path),"task_id":1,"run_id":2,"source_id":3,"stage":"ACTIVE_RECHECK","control_file":str(tmp_path/"control.json")}
    atomic_json(tmp_path/"active_inflight/target.json",{"ip":"192.0.2.1","port":"80","gpu_likelihood":"中"})
    restore_checkpoints(cfg)
    completed=json.loads((tmp_path/"active.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert completed["row"]["active_probe_status"]=="UNKNOWN_INTERRUPTED"
    assert completed["row"]["gpu_likelihood"]=="中"
    assert len(list((tmp_path/"outbox/3_ACTIVE_RECHECK").glob("*.json")))==1
    restore_checkpoints(cfg)
    assert len(list((tmp_path/"outbox/3_ACTIVE_RECHECK").glob("*.json")))==1


def test_port_policy_boundary_and_explicit_single_preserved(monkeypatch):
    monkeypatch.syspath_prepend(str(RELEASE))
    policy=module_at(RELEASE/"scan_ports_by_source_type.py","offline_source_policy")
    rows=[{"ip":str(__import__("ipaddress").ip_address(0xC6120000+i))} for i in range(50000)]
    source=[{"起始IP":rows[0]["ip"],"终止IP":rows[0]["ip"]}]
    pn,discovery,code=policy.classify_rows(rows[:49999],source)
    assert len(pn)==49999 and not discovery
    pn,discovery,code=policy.classify_rows(rows,source)
    assert len(pn)==1 and len(discovery)==49999


def test_capacity_and_ipv6_do_not_expand_unbounded_ranges():
    with pytest.raises(ContractError,match="capacity"):
        expand_hosts([{"resource_id":1,"start_ip":"::","end_ip":"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}],1000)
    rows=expand_hosts([{"resource_id":1,"start_ip":"::1","end_ip":"::2"},{"resource_id":2,"start_ip":"::2","end_ip":"::2"}],10)
    assert rows[1]["source_form"]=="BOTH" and len(rows[1]["resources"])==2


def test_parameters_do_not_overwrite_other_concurrency():
    value=json.loads((SERVICE_ROOT/"llm_detect/v21/defaults.json").read_text())
    value["port_scan"]["parallel_workers"]=5
    assert validate_params(value,5)["gpu_recheck"]["concurrency"]==20
    assert value["full_port"]["workers"]==6 and value["port_scan"]["verify_workers"]==12
    with pytest.raises(ContractError):validate_params(value,3)
    value["port_scan"]["extra_unsupported"]=1
    with pytest.raises(ContractError):validate_params(value,5)


def test_optional_hooks_are_noop_without_context(monkeypatch):
    monkeypatch.syspath_prepend(str(RELEASE));monkeypatch.delenv("LLM_SERVICE_CONTEXT",raising=False)
    import service_hooks
    service_hooks.emit("RESULT",[{"ip":"192.0.2.1"}])
    service_hooks.check_control()
    assert service_hooks.bind_proof({}, {})=={}


def test_full_port_partial_and_callback_before_checkpoint(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(RELEASE))
    module=module_at(RELEASE/"full_port_recheck.py","offline_full_port")
    writes=[]
    monkeypatch.setattr(module,"service_emit",lambda kind,rows,**kw:writes.append((kind,rows)))
    original=module.append_checkpoint
    def checked(path,item):
        assert writes and writes[-1][0]=="FULL_PORT_HOST"
        original(path,item)
    monkeypatch.setattr(module,"append_checkpoint",checked)
    monkeypatch.setattr(module,"scan_one",lambda item,args:{"ip":item["ip"],"status":"timeout","ports":[],"elapsed_seconds":1,"error":"fixture"})
    write_csv(tmp_path/"ports.csv",[{"ip":"192.0.2.1","port":"80"}])
    write_csv(tmp_path/"llm.csv",[{"ip":"192.0.2.1","port":"80","gpu_likelihood":"中"}])
    monkeypatch.setattr(sys,"argv",["full_port_recheck.py","--ports-input",str(tmp_path/"ports.csv"),"--llm-input",str(tmp_path/"llm.csv"),"--output",str(tmp_path/"new.csv"),"--checkpoint",str(tmp_path/"full.jsonl")])
    assert module.main()==2
    assert json.loads((tmp_path/"new.summary.json").read_text())["failed_or_timed_out"]==1
