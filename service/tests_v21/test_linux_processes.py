"""Synthetic sleeping processes only; no nmap, HTTP targets or database."""
import os
import sys
import threading

import pytest

from llm_detect.v21.common import LeaseLost
from llm_detect.v21.processes import ExecutionLock, ManagedProcess, group_members

pytestmark=pytest.mark.skipif(os.name!="posix" or not __import__("pathlib").Path("/proc").is_dir(),reason="requires Linux /proc/process groups")


def test_owned_process_group_is_confirmed_stopped(tmp_path):
    manager=ManagedProcess(tmp_path/"process.json",grace=1,kill=1)
    manager.launch([sys.executable,"-c","import time; time.sleep(30)"],tmp_path,dict(os.environ),tmp_path/"log")
    identity=dict(manager.identity)
    manager.stop()
    assert not group_members(identity["pgid"],identity["token"])
    assert not (tmp_path/"process.json").exists()


def test_child_retains_run_fence_after_parent_fd_closes(tmp_path):
    fence=ExecutionLock(tmp_path);fence.acquire(threading.Event())
    manager=ManagedProcess(tmp_path/"process.json",grace=1,kill=1)
    manager.lock_fd=fence.fd
    manager.launch([sys.executable,"-c","import time; time.sleep(30)"],tmp_path,dict(os.environ),tmp_path/"log")
    fence.close()
    second=ExecutionLock(tmp_path)
    lost=threading.Event();lost.set()
    try:
        with pytest.raises(LeaseLost):second.acquire(lost)
        manager.stop()
        second.acquire(threading.Event())
    finally:
        manager.stop();second.close()
