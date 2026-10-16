#!/usr/bin/env python3
import csv, importlib.util, json, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("remote_full_port_runner",here/"remote_full_port_runner.py")
module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module; spec.loader.exec_module(module)
assert "/" not in module.safe_component("run 1/中国移动")
assert module.safe_component("a/b") != module.safe_component("a_b")
with tempfile.TemporaryDirectory() as raw:
    root=Path(raw); key=root/"key"; hosts=root/"known_hosts"; key.write_text("key"); hosts.write_text("host key")
    config_path=root/"remote.ini"
    config_path.write_text("[ssh]\nhost=h\nuser=u\nidentity_file=%s\nknown_hosts_file=%s\npoll_interval=1\n\n[remote]\nremote_base_dir=/tmp/jobs\n"%(key,hosts),encoding="utf-8")
    config=module.Config(config_path)
    assert config.port == 22
    output=root/"output.csv"; summary=root/"summary.json"
    with output.open("w",encoding="utf-8-sig",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=["ip","port"]); writer.writeheader(); writer.writerow({"ip":"127.0.0.1","port":"12345"})
    summary.write_text(json.dumps({"selected_candidates":1,"completed":1,"failed_or_timed_out":0}),encoding="utf-8")
    assert module.validate_result_files(output,summary)["completed"] == 1

    class Completed: stdout=""
    class FakeRunner(module.Runner):
        def __init__(self):
            super().__init__(config,here/"full_port_recheck.py",root/"status.txt","phase=full-port-remote index=1")
            self.states=[("missing",None),("running",None),("finished",2)]
            self.launched=0
        def ensure_worker(self, run): return "/tmp/jobs/"+run+"/bin/full_port_recheck.py"
        def job_state(self, job): return self.states.pop(0)
        def ssh(self, script, description): return Completed()
        def upload_atomic(self, local, remote, description): pass
        def remote_exists(self, path): return False
        def launch(self, job, worker, args): self.launched += 1
        def download(self, remote, local, description):
            local=Path(local)
            if remote.endswith("new_ports.csv"):
                with local.open("w",encoding="utf-8-sig",newline="") as stream:
                    writer=csv.DictWriter(stream,fieldnames=["ip","port"]); writer.writeheader(); writer.writerow({"ip":"10.0.0.1","port":"9000"})
            elif remote.endswith("summary.json"):
                local.write_text(json.dumps({"selected_candidates":1,"completed":1,"failed_or_timed_out":1}),encoding="utf-8")
            else: local.write_text("worker log",encoding="utf-8")
    ports=root/"ports.csv"; llm=root/"llm.csv"; ports.write_text("ip,port\n10.0.0.1,8000\n"); llm.write_text("ip,port\n10.0.0.1,8000\n")
    args=SimpleNamespace(run_id="run 1",job_id="1_中国移动",ports_input=ports,llm_input=llm,output=root/"new_ports.csv",checkpoint=root/"checkpoint.jsonl",summary=root/"out_summary.json",mode="candidates",max_targets=50,max_rate=200,min_rate=100,workers=6,max_retries=0,host_timeout="40m",process_timeout=2700)
    original_sleep=module.time.sleep; module.time.sleep=lambda _: None
    try: assert FakeRunner().run(args) == 2
    finally: module.time.sleep=original_sleep
    assert (root/"new_ports.csv").is_file() and (root/"out_summary.json").is_file()
    assert "remote_state=partial" in (root/"status.txt").read_text(encoding="utf-8")
    reused=FakeRunner()
    assert reused.run(args) == 2 and reused.launched == 0
print("remote_full_port_runner_tests=passed")
