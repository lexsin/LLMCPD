"""Opt-in MySQL 8 checks. Never use an existing application schema or remote DB."""
import json
import os
import uuid
from datetime import timedelta

import pytest

from llm_detect.v21.common import LeaseLost
from llm_detect.v21.database import MySQL
from llm_detect.v21.events import Outbox, read_event
from llm_detect.v21.inputs import expand_hosts, validate_inputs
from llm_detect.v21.repository import update
from .support import fixture_ddl, seed

pytestmark = pytest.mark.isolated_mysql


@pytest.fixture
def mysql_database():
    if os.environ.get("V7_ISOLATED_MYSQL") != "1":
        pytest.skip("requires explicit V7_ISOLATED_MYSQL=1 and disposable loopback MySQL 8")
    import mysql.connector
    host=os.environ.get("V7_TEST_MYSQL_HOST","127.0.0.1")
    if host not in {"127.0.0.1","localhost","::1"}:
        pytest.fail("isolated MySQL tests refuse non-loopback hosts")
    options={"host":host,"port":int(os.environ.get("V7_TEST_MYSQL_PORT","3306")),
             "user":os.environ["V7_TEST_MYSQL_USER"],"password":os.environ["V7_TEST_MYSQL_PASSWORD"]}
    name="test_v7_"+uuid.uuid4().hex
    admin=mysql.connector.connect(**options)
    cursor=admin.cursor()
    created=False
    try:
        cursor.execute(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
        created=True
        db=MySQL(dict(options,database=name,pool_size=4))
        with db.cursor() as cur:
            for sql in fixture_ddl(mysql=True):cur.execute(sql)
        db.validate_schema()
        yield db
    finally:
        if created:
            assert name.startswith("test_v7_") and len(name)==40
            cursor.execute(f"DROP DATABASE `{name}`")
        cursor.close();admin.close()


def test_mysql_claim_atomic_sources_replay_and_fencing(mysql_database,tmp_path):
    db=mysql_database
    repo,_,_=seed(db,tmp_path,2)
    lease=repo.claim("mysql-a")
    assert repo.claim("mysql-b") is None
    run,files,resources=repo.input_records(lease)
    inputs=validate_inputs(run,files,resources,{"LOCAL":tmp_path})
    repo.freeze(lease,{"content":"fixture"},"hash","fixture")
    sources=repo.publish_sources(lease,inputs)
    assert len(sources)==2 and repo.get_run(lease.run_id)["source_total"]==2
    source=sources[0];repo.start_stage(lease,source["id"],"EXPAND")
    event_path=Outbox(tmp_path,lease.task_id,lease.run_id,source["id"],"EXPAND").emit("HOST",expand_hosts(json.loads(source["input_snapshot_json"])["rows"],100))
    event=read_event(event_path)
    assert repo.commit(lease,event,event_path.name)
    assert not repo.commit(lease,event,event_path.name)
    with db.cursor() as cur:
        update(cur,"probe_task_run",lease.run_id,{"lease_expires_at":db.now(cur)-timedelta(seconds=1)})
    newer=repo.claim("mysql-b")
    assert newer.epoch>lease.epoch
    with pytest.raises(LeaseLost):repo.heartbeat(lease)
