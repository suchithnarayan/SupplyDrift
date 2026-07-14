"""Scan job queue: UI enqueues a run per connection; runners claim + complete it."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


def _dockerhub(store, name="My Dockerhub"):
    return store.save_connector({"name": name, "source_type": "dockerhub", "connection": {"namespaces": ["acme"]}})


def test_enqueue_claim_complete_flow(empty_store):
    s = empty_store
    c = _dockerhub(s)
    run = s.enqueue_scan(c["id"])
    assert run["status"] == "queued" and run["job_type"] == "image" and run["source_name"] == "My Dockerhub"

    # dedupe — re-enqueue while pending returns the SAME run
    assert s.enqueue_scan(c["id"])["id"] == run["id"]

    # a github runner must NOT pick up an image job
    assert s.claim_scan_run("github", "runner-gh") is None

    # the image runner claims it (atomic) — second claim gets nothing
    claimed = s.claim_scan_run("image", "runner-img")
    assert claimed["id"] == run["id"] and claimed["status"] == "running" and claimed["claimed_by"] == "runner-img"
    assert claimed["runner_id"] == "runner-img"
    assert claimed["started_at"] == claimed["claimed_at"]
    assert claimed["source_type"] == "dockerhub"
    assert s.claim_scan_run("image", "runner-img2") is None

    done = s.complete_scan_run(run["id"], "succeeded", {"components": 5, "assets": 1})
    assert done["status"] == "succeeded" and done["summary"] == {"components": 5, "assets": 1}
    assert done["runner_id"] == "runner-img"
    assert done["started_at"] == claimed["claimed_at"]
    assert done["source_type"] == "dockerhub"
    assert s.get_connector(c["id"])["last_sync_at"] == done["finished_at"]

    assert s.latest_scan_run(c["id"])["id"] == run["id"]
    # once finished, a fresh enqueue creates a NEW run
    run3 = s.enqueue_scan(c["id"])
    assert run3["id"] != run["id"] and run3["status"] == "queued"


def test_complete_bound_to_claiming_runner(empty_store):
    # A run may only be completed by the runner that claimed it (SD-03). A stray
    # QUEUE-token holder supplying a different runner_id is rejected; the run stays
    # running. Completing without a runner_id stays allowed (legacy/late completes).
    s = empty_store
    c = _dockerhub(s)
    run = s.enqueue_scan(c["id"])
    s.claim_scan_run("image", "runner-A")
    assert s.complete_scan_run(run["id"], "succeeded", {}, runner_id="runner-B") is None
    assert s.latest_scan_run(c["id"])["status"] == "running"  # unchanged
    done = s.complete_scan_run(run["id"], "succeeded", {}, runner_id="runner-A")
    assert done["status"] == "succeeded"


def test_enqueue_refresh_marks_action(empty_store):
    s = empty_store
    c = _dockerhub(s)
    run = s.enqueue_refresh(c["id"])
    assert run["status"] == "queued" and run["job_type"] == "image"
    assert run["summary"]["action"] == "refresh"
    claimed = s.claim_scan_run("image", "runner-img")
    assert claimed["id"] == run["id"]
    assert claimed["summary"]["action"] == "refresh"


def test_job_type_mapping(empty_store):
    s = empty_store
    gh = s.save_connector({"name": "Repos", "source_type": "github", "connection": {"owner": "acme"}})
    assert s.enqueue_scan(gh["id"])["job_type"] == "github"
    assert _dockerhub(s, "DH").get("id")  # sanity
    assert s.enqueue_scan(_dockerhub(s, "DH2")["id"])["job_type"] == "image"


def test_enqueue_unknown_connector(empty_store):
    with pytest.raises(ValueError):
        empty_store.enqueue_scan("does-not-exist")


def test_enqueue_warns_when_no_runner(empty_store):
    s = empty_store
    c = _dockerhub(s)
    # No runner has ever polled -> enqueue reports no runner + a warning.
    run = s.enqueue_scan(c["id"])
    assert run["runner_available"] is False
    assert "runner" in run["warning"].lower()


def test_enqueue_no_warning_when_runner_live(empty_store):
    s = empty_store
    c = _dockerhub(s)
    # An image runner polls (empty queue) -> records a heartbeat.
    assert s.claim_scan_run("image", "runner-img") is None
    assert s.has_live_runner("image") is True
    run = s.enqueue_scan(c["id"])
    assert run["runner_available"] is True and "warning" not in run


def test_latest_run_annotates_queued_with_runner_status(empty_store):
    s = empty_store
    c = _dockerhub(s)
    s.enqueue_scan(c["id"])
    # Polled while still queued with no runner -> annotated false (drives the pill).
    assert s.latest_scan_run(c["id"])["runner_available"] is False
    # Once claimed (running), the annotation is not applied (irrelevant).
    s.claim_scan_run("image", "runner-img")
    latest = s.latest_scan_run(c["id"])
    assert latest["status"] == "running" and "runner_available" not in latest


def test_live_runner_is_per_job_type(empty_store):
    s = empty_store
    # Only a github runner is polling; an image source must still warn.
    s.claim_scan_run("github", "runner-gh")
    assert s.has_live_runner("github") is True
    assert s.has_live_runner("image") is False
    run = s.enqueue_scan(_dockerhub(s)["id"])  # image job
    assert run["runner_available"] is False


def _github(store, name):
    return store.save_connector({"name": name, "source_type": "github", "connection": {"owner": "acme"}})


def test_busy_runner_with_stale_heartbeat_still_present(empty_store):
    """The reported bug: while a runner is mid-scan it stops polling, so its
    heartbeat goes stale — but the queued jobs behind it must NOT say 'no runner
    connected'. The in-progress run proves the runner is present (just busy)."""
    s = empty_store
    a, b = _github(s, "repoA"), _github(s, "repoB")
    s.enqueue_scan(a["id"])
    s.enqueue_scan(b["id"])
    claimed = s.claim_scan_run("github", "gh-runner")  # claims oldest (A) -> running
    assert claimed["source_name"] == "repoA"
    # Simulate the runner being busy mid-scan: its heartbeat ages out.
    stale = (datetime.now(timezone.utc) - timedelta(seconds=600)).replace(microsecond=0).isoformat()
    with s.connect() as conn:
        conn.execute("UPDATE runner_heartbeats SET last_seen_at = ? WHERE job_type = 'github'", (stale,))

    available, busy = s.runner_presence("github")
    assert available is True and busy is True  # present-but-busy, NOT absent
    latest_b = s.latest_scan_run(b["id"])
    assert latest_b["status"] == "queued"
    assert latest_b["runner_available"] is True and latest_b["runner_busy"] is True
    assert "warning" not in latest_b  # no false "no runner connected"


def test_queued_jobs_drain_fifo_not_dropped(empty_store):
    """Queued jobs are not dropped — a single runner drains them FIFO: it claims
    the oldest, completes it, then its next poll claims the next."""
    s = empty_store
    a, b = _github(s, "repoA"), _github(s, "repoB")
    s.enqueue_scan(a["id"])
    s.enqueue_scan(b["id"])
    first = s.claim_scan_run("github", "gh-runner")
    assert first["source_name"] == "repoA"  # FIFO: oldest queued first
    s.complete_scan_run(first["id"], "succeeded", {"x": 1})
    second = s.claim_scan_run("github", "gh-runner")
    assert second["source_name"] == "repoB"  # B waited its turn, was NOT dropped
    assert s.claim_scan_run("github", "gh-runner") is None  # queue drained


def test_stuck_running_job_past_busy_window_is_absent(empty_store):
    """A runner that died mid-scan (stale heartbeat AND its 'running' job is older
    than the busy window) is no longer counted — UI degrades to 'no runner'."""
    s = empty_store
    a = _github(s, "repoA")
    s.enqueue_scan(a["id"])
    claimed = s.claim_scan_run("github", "gh-runner")
    old = (datetime.now(timezone.utc) - timedelta(seconds=3600)).replace(microsecond=0).isoformat()
    with s.connect() as conn:
        conn.execute("UPDATE runner_heartbeats SET last_seen_at = ?", (old,))
        conn.execute("UPDATE scan_runs SET claimed_at = ? WHERE id = ?", (old, claimed["id"]))
    available, busy = s.runner_presence("github")
    assert available is False and busy is False


def test_stale_heartbeat_is_not_live(empty_store):
    s = empty_store
    # A heartbeat from 10 minutes ago is outside the liveness window.
    old = (datetime.now(timezone.utc) - timedelta(seconds=600)).replace(microsecond=0).isoformat()
    with s.connect() as conn:
        conn.execute(
            "INSERT INTO runner_heartbeats (runner_id, job_type, last_seen_at) VALUES (?, ?, ?)",
            ("old-runner", "image", old))
    assert s.has_live_runner("image") is False
    # The enqueue response then warns despite a (stale) heartbeat existing.
    assert s.enqueue_scan(_dockerhub(s)["id"])["runner_available"] is False


def test_scan_runs_paginated(empty_store):
    s = empty_store
    s.enqueue_scan(_dockerhub(s)["id"])
    page = s.list_scan_runs({"limit": ["10"]})
    assert set(page) == {"items", "total", "limit", "offset"} and page["total"] == 1
    assert page["items"][0]["source_type"] == "dockerhub"
    assert page["items"][0]["runner_id"] is None
    assert page["items"][0]["started_at"] is None
    assert s.list_scan_runs({"status": ["running"]}) == []  # filter works (nothing running)


def test_scan_queue_routes(fastapi_client):
    client, store = fastapi_client
    c = _dockerhub(store, "DH-routes")
    r = client.post(f"/api/connectors/{c['id']}/scan")
    assert r.status_code == 202 and r.json()["status"] == "queued"
    # No runner has polled this fresh store -> the enqueue response flags it.
    assert r.json()["runner_available"] is False and r.json().get("warning")
    assert client.get("/api/scan/runs").status_code == 200
    assert client.get(f"/api/connectors/{c['id']}/scan/latest").json()["status"] == "queued"

    claimed = client.post("/api/scan/runs/claim", json={"job_type": "image", "runner_id": "r1"}).json()
    assert claimed["status"] == "running" and claimed["claimed_by"] == "r1"
    assert claimed["runner_id"] == "r1" and claimed["source_type"] == "dockerhub"
    done = client.post(f"/api/scan/runs/{claimed['id']}/complete",
                       json={"status": "succeeded", "summary": {"assets": 1}}).json()
    assert done["status"] == "succeeded"
    assert done["runner_id"] == "r1" and done["source_type"] == "dockerhub"

    assert client.post("/api/connectors/nope/scan").status_code == 404
    assert client.post("/api/connectors/nope/refresh").status_code == 404
    # claim with nothing queued -> null
    assert client.post("/api/scan/runs/claim", json={"job_type": "github", "runner_id": "x"}).json() is None


def _age_claim(store, run_id, seconds):
    old = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).replace(microsecond=0).isoformat()
    with store.connect() as conn:
        conn.execute("UPDATE scan_runs SET claimed_at = ? WHERE id = ?", (old, run_id))


def test_reap_orphaned_running_run(empty_store):
    """A runner that dies mid-scan leaves a 'running' run forever; reaping fails it."""
    s = empty_store
    c = _github(s, "repoA")
    run = s.enqueue_scan(c["id"])
    s.claim_scan_run("github", "gh-runner")  # -> running
    _age_claim(s, run["id"], 4000)           # older than the 3600s default timeout
    assert s.reap_stale_scan_runs() == 1
    reaped = s.latest_scan_run(c["id"])
    assert reaped["status"] == "failed" and "orphaned" in (reaped["error"] or "").lower()
    # idempotent — nothing left to reap
    assert s.reap_stale_scan_runs() == 0


def test_boot_reap_clears_all_running(empty_store):
    """On restart (timeout 0) every 'running' run is reaped, even a recent one —
    its runner is gone after a compose down/up and will only claim 'queued' jobs."""
    s = empty_store
    c = _github(s, "repoA")
    s.enqueue_scan(c["id"])
    s.claim_scan_run("github", "gh-runner")  # running, claimed 'just now'
    _age_claim(s, s.latest_scan_run(c["id"])["id"], 5)  # a few seconds old (pre-restart)
    assert s.reap_stale_scan_runs(timeout_seconds=0) == 1
    assert s.latest_scan_run(c["id"])["status"] == "failed"


def test_reap_leaves_fresh_running_alone(empty_store):
    s = empty_store
    c = _github(s, "repoA")
    s.enqueue_scan(c["id"])
    s.claim_scan_run("github", "gh-runner")  # claimed just now -> not stale
    assert s.reap_stale_scan_runs() == 0
    assert s.latest_scan_run(c["id"])["status"] == "running"


def test_latest_scan_run_self_heals(empty_store):
    """Polling the source card (latest_scan_run) reaps an orphaned run on its own."""
    s = empty_store
    c = _github(s, "repoA")
    run = s.enqueue_scan(c["id"])
    s.claim_scan_run("github", "gh-runner")
    _age_claim(s, run["id"], 4000)
    assert s.latest_scan_run(c["id"])["status"] == "failed"  # reaped during the poll


def test_late_complete_overrides_reaped_run(empty_store):
    """Reaping is safe: a slow-but-alive runner that later completes still wins."""
    s = empty_store
    c = _github(s, "repoA")
    run = s.enqueue_scan(c["id"])
    s.claim_scan_run("github", "gh-runner")
    _age_claim(s, run["id"], 4000)
    s.reap_stale_scan_runs()
    assert s.latest_scan_run(c["id"])["status"] == "failed"
    done = s.complete_scan_run(run["id"], "succeeded", {"components": 3})
    assert done["status"] == "succeeded"


def test_cancel_queued_and_running(empty_store):
    s = empty_store
    c = _github(s, "repoA")
    run = s.enqueue_scan(c["id"])
    # cancel a queued run
    canceled = s.cancel_connector_scan(c["id"])
    assert canceled["status"] == "canceled" and canceled["id"] == run["id"]
    # cancel is a no-op once finished
    assert s.cancel_scan_run(run["id"])["status"] == "canceled"
    # cancel a running run
    run2 = s.enqueue_scan(c["id"])
    s.claim_scan_run("github", "gh-runner")
    assert s.cancel_scan_run(run2["id"])["status"] == "canceled"
    # nothing active to cancel now
    assert s.cancel_connector_scan(c["id"]) is None


def test_cancel_routes(fastapi_client):
    client, store = fastapi_client
    c = _dockerhub(store, "DH-cancel")
    run = client.post(f"/api/connectors/{c['id']}/scan").json()
    stopped = client.post(f"/api/connectors/{c['id']}/scan/cancel").json()
    assert stopped["status"] == "canceled" and stopped["id"] == run["id"]
    # direct run-id cancel endpoint also works
    run2 = client.post(f"/api/connectors/{c['id']}/scan").json()
    assert client.post(f"/api/scan/runs/{run2['id']}/cancel").json()["status"] == "canceled"
