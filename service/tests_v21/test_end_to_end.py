"""End-to-end DB/outbox/artifact flow with synthetic scanner stages, no socket calls."""
import json
from pathlib import Path

from llm_detect.v21.common import atomic_json, dumps
from llm_detect.v21.config import Config, DEFAULT_RELEASE, SERVICE_ROOT
from llm_detect.v21.events import Outbox
from llm_detect.v21.repository import insert, update
from llm_detect.v21.runtime import Runtime
from llm_detect.v21.stage_worker import execute, read_csv, write_csv
from .support import SQLiteFixture, seed


def test_full_task_repeated_runs_and_history(tmp_path,monkeypatch):
    import llm_detect.v21.runtime as runtime_module
    class OfflineFence:
        fd=None
        def __init__(self,*a):pass
        def acquire(self,*a):pass
        def close(self):pass
    monkeypatch.setattr(runtime_module,"ExecutionLock",OfflineFence)
    db=SQLiteFixture();repo,task,rid=seed(db,tmp_path,2)
    cfg=Config(data_root=tmp_path,storage_roots={"LOCAL":tmp_path},release_root=SERVICE_ROOT/"vendor/v7")
    runtime=Runtime(cfg,repo)
    release=runtime.releases.get()
    monkeypatch.setattr(runtime.releases,"get",lambda *a:release)
    monkeypatch.setattr(runtime,"publish_evidence",lambda *a:0)
    monkeypatch.syspath_prepend(str(release.path))
    import finalize_llm_results
    monkeypatch.setattr(finalize_llm_results,"fill_screenshots",lambda *a,**kw:0)
    def simulated(lease,root,argv,cwd,context=None):
        if "llm_detect.v21.preflight" in argv:
            assert repo.get_run(lease.run_id)["started_at"] is None
            return 0
        if context is None:
            from llm_detect.v21.reports import build
            build(json.loads(Path(argv[-1]).read_text(encoding="utf-8")))
            return 0
        c=json.loads(Path(context).read_text(encoding="utf-8")); stage=c["stage"];folder=Path(c["source_root"])
        box=Outbox(root,lease.task_id,lease.run_id,c["source_id"],stage)
        if stage=="EXPAND":
            return execute(c)
        if stage=="PORT_SCAN":
            box.emit("PORTS",[{"ip":"192.0.2.1","ports":[],"scan_mode":"PN"},{"ip":"192.0.2.2","ports":[80],"scan_mode":"PN"}])
            write_csv(folder/"endpoints.csv",[{"ip":"192.0.2.2","port":"80"}])
        elif stage in {"IDENTIFY","FULL_IDENTIFY"}:
            row={"ip":"192.0.2.2","port":"80" if stage=="IDENTIFY" else "443","protocol":"http","is_llm":"确认",
                 "gpu_likelihood":"低" if stage=="IDENTIFY" else "高","npu_likelihood":"未知"}
            box.emit("RESULT",[row],reason="INITIAL")
            write_csv(folder/("identify.csv" if stage=="IDENTIFY" else "full_identify.csv"),[row])
        elif stage in {"GPU_RECHECK","FULL_GPU_RECHECK"}:
            prefix="identify" if stage=="GPU_RECHECK" else "full_identify"
            rows=read_csv(folder/f"{prefix}.csv")
            if stage=="GPU_RECHECK":
                rows[0]["gpu_likelihood"]="中";box.emit("RESULT",rows,reason="GPU_RECHECK")
            write_csv(folder/("low.csv" if stage=="GPU_RECHECK" else "full_low.csv"),rows)
        elif stage=="FULL_PORT":
            box.emit("FULL_PORT_HOST",[{"ip":"192.0.2.2","status":"complete","ports":[443]}])
            write_csv(folder/"full_new.csv",[{"ip":"192.0.2.2","port":"443"}])
        elif stage=="MERGE":
            write_csv(folder/"merged.csv",read_csv(folder/"low.csv")+read_csv(folder/"full_low.csv"))
        elif stage=="ACTIVE_RECHECK":
            rows=read_csv(folder/"merged.csv");rows[0]["gpu_likelihood"]="高";rows[0]["active_probe_status"]="promoted_high"
            box.emit("RESULT",[rows[0]],reason="ACTIVE_RECHECK")
            write_csv(folder/"active.csv",rows)
        elif stage in {"EVIDENCE","EVIDENCE_FINAL"}:
            atomic_json(folder/"manifest.json",{})
        elif stage=="FINALIZE":
            finalize_llm_results.write_result(finalize_llm_results.read_scan(folder/"committed.csv"),folder/"final.xlsx")
        return 0
    monkeypatch.setattr(runtime,"child_stage",simulated)
    lease=repo.claim("e2e-1");runtime.run_one(lease)
    run=repo.get_run(rid)
    assert run["status"]=="SUCCESS" and run["source_finished"]==2
    assert run["host_total"]==4 and run["unique_ip_count"]==2 and run["endpoint_total"]==4
    assert len(db.rows("probe_host_resource"))==6
    first_assets=[dict(r) for r in db.rows("probe_asset_port")]
    assert len(first_assets)==4 and all(r["gpu_likelihood"]=="HIGH" for r in first_assets)
    assert len(db.rows("probe_run_stage"))==24
    assert run["final_artifact_id"] is not None
    ready=[a for a in db.rows("probe_artifact") if a["status"]=="READY"]
    assert all((cfg.data_root/a["relative_path"]).is_file() for a in ready)
    with db.cursor() as cur:
        second=insert(cur,"probe_task_run",{"task_id":task,"run_no":2,"trigger_type":"MANUAL",
            "input_snapshot_json":run["input_snapshot_json"],"param_snapshot_json":run["param_snapshot_json"],"create_date":db.now(cur)})
    newer=repo.claim("e2e-2");runtime.run_one(newer)
    assert repo.get_run(second)["status"]=="SUCCESS"
    assert [a for a in db.rows("probe_asset_port") if a["run_id"]==rid]==first_assets
    assert repo.get_run(rid)["result_version"]==run["result_version"]
    assert len(db.rows("probe_run_source"))==4
    assert repo.get_run(second)["final_artifact_id"]!=run["final_artifact_id"]
