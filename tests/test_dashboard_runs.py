"""Tests for the ActiveRuns class."""

from unittest.mock import MagicMock

from dashboard.runs import ActiveRun, ActiveRuns


def _make_loop():
    """Create a mock PayloadLoop."""
    loop = MagicMock()
    loop.pause.return_value = True
    loop.resume.return_value = True
    loop.kill.return_value = None
    return loop


def test_start_and_get():
    """Test starting a run and retrieving it."""
    runs = ActiveRuns()
    run = ActiveRun(engagement_id="test1")
    runs.start(run)
    assert runs.get("test1") is run
    assert runs.get("nonexistent") is None


def test_list():
    """Test listing all active runs."""
    runs = ActiveRuns()
    runs.start(ActiveRun(engagement_id="1"))
    runs.start(ActiveRun(engagement_id="2"))
    runs.start(ActiveRun(engagement_id="3"))
    assert len(runs.list()) == 3
    ids = {r.engagement_id for r in runs.list()}
    assert ids == {"1", "2", "3"}


def test_pause_running():
    """Test pausing a running engagement."""
    runs = ActiveRuns()
    loop = _make_loop()
    run = ActiveRun(engagement_id="1", status="running", loop=loop)
    runs.start(run)
    assert runs.pause("1") is True
    assert run.status == "paused"
    loop.pause.assert_called_once()


def test_pause_not_running():
    """Test pausing an engagement that isn't running."""
    runs = ActiveRuns()
    run = ActiveRun(engagement_id="1", status="paused")
    runs.start(run)
    assert runs.pause("1") is False


def test_pause_no_loop():
    """Test pausing an engagement with no loop."""
    runs = ActiveRuns()
    run = ActiveRun(engagement_id="1", status="running")
    runs.start(run)
    assert runs.pause("1") is False


def test_pause_nonexistent():
    """Test pausing a nonexistent engagement."""
    runs = ActiveRuns()
    assert runs.pause("nonexistent") is False


def test_resume_paused():
    """Test resuming a paused engagement."""
    runs = ActiveRuns()
    loop = _make_loop()
    run = ActiveRun(engagement_id="1", status="paused", loop=loop)
    runs.start(run)
    assert runs.resume("1") is True
    assert run.status == "running"
    loop.resume.assert_called_once()


def test_resume_not_paused():
    """Test resuming an engagement that isn't paused."""
    runs = ActiveRuns()
    loop = _make_loop()
    run = ActiveRun(engagement_id="1", status="running", loop=loop)
    runs.start(run)
    assert runs.resume("1") is False


def test_kill_running():
    """Test killing a running engagement."""
    runs = ActiveRuns()
    loop = _make_loop()
    run = ActiveRun(engagement_id="1", status="running", loop=loop)
    runs.start(run)
    assert runs.kill("1") is True
    assert run.status == "killed"
    loop.kill_and_reset.assert_called_once()


def test_kill_completed():
    """Test killing a completed engagement (should fail)."""
    runs = ActiveRuns()
    run = ActiveRun(engagement_id="1", status="completed")
    runs.start(run)
    assert runs.kill("1") is False


def test_remove():
    """Test removing a run."""
    runs = ActiveRuns()
    runs.start(ActiveRun(engagement_id="1"))
    runs.remove("1")
    assert runs.get("1") is None


def test_complete():
    """Test marking a run as completed."""
    runs = ActiveRuns()
    run = ActiveRun(engagement_id="1", status="running")
    runs.start(run)
    runs.complete("1", {"total_fired": 100, "hits": 5, "near_misses": 10, "no_diff": 85})
    assert run.status == "completed"
    assert run.total_fired == 100
    assert run.hits == 5
    assert run.near_misses == 10
    assert run.no_diff == 85


def test_add_finding():
    """Test adding a finding to a run."""
    runs = ActiveRuns()
    run = ActiveRun(engagement_id="1")
    runs.start(run)
    runs.add_finding("1", {"parameter": "foo", "severity": "confirmed"})
    assert len(run.findings) == 1
    assert run.findings[0]["parameter"] == "foo"


def test_to_dict():
    """Test ActiveRun serialization."""
    run = ActiveRun(
        engagement_id="1",
        status="running",
        total_fired=50,
        payload_count=100,
        hits=5,
        near_misses=10,
        no_diff=35,
    )
    d = run.to_dict()
    assert d["engagement_id"] == "1"
    assert d["status"] == "running"
    assert d["total_fired"] == 50
    assert d["payload_count"] == 100
    assert d["hits"] == 5
    assert d["progress"] == 50.0


def test_to_dict_zero_payloads():
    """Test serialization when payload_count is 0."""
    run = ActiveRun(engagement_id="1", total_fired=0, payload_count=0)
    d = run.to_dict()
    assert d["progress"] == 0
