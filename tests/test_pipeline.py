import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from triage import api
from triage.db import Database
from triage.ingest import parse_record
from triage.llm import FixtureTriageModel
from triage.schema import NormalizedAlert, Source
from triage.service import TriageService


def test_dedupe_and_persistence(tmp_path):
    db = Database(str(tmp_path / "test.db")); db.initialize()
    service = TriageService(db, FixtureTriageModel())
    alert = NormalizedAlert(source=Source.SURICATA, timestamp=datetime.now(timezone.utc), title="Nmap scan", source_ip="10.0.0.2", raw={"alert": {}})
    alert_id, duplicate = asyncio.run(service.process(alert))
    assert not duplicate
    same_id, duplicate = asyncio.run(service.process(alert))
    assert duplicate and same_id == alert_id
    stored = db.get_alert(alert_id)
    assert stored and stored.duplicate_count == 1 and stored.triage.severity == "high"

@pytest.mark.parametrize("offset", [timedelta(hours=-4), timedelta(hours=2)])
def test_repeat_with_a_sensor_offset_is_still_a_duplicate(tmp_path, offset):
    """Suricata's EVE writes local time with an offset (US: -0400). Stored as given,
    the text comparison against a UTC cutoff never matched a repeat in the US."""
    db = Database(str(tmp_path / "test.db")); db.initialize()
    service = TriageService(db, FixtureTriageModel())
    local = datetime.now(timezone(offset)).replace(microsecond=0)
    alert = parse_record(Source.SURICATA, {"timestamp": local.strftime("%Y-%m-%dT%H:%M:%S.%f%z"), "src_ip": "10.0.0.9",
                                           "alert": {"signature": "ET SCAN", "signature_id": 1, "severity": 2}})
    first, duplicate = asyncio.run(service.process(alert))
    again, duplicate_again = asyncio.run(service.process(alert))
    assert not duplicate and duplicate_again and again == first
    stored = db.list_alerts()[0]["timestamp"]
    assert stored.endswith("+00:00") and datetime.fromisoformat(stored) == local


def test_alerts_order_by_moment_across_offsets(tmp_path):
    db = Database(str(tmp_path / "test.db")); db.initialize()
    service = TriageService(db, FixtureTriageModel())
    # As text, "...T13:00-04:00" (17:00 UTC) sorts before "...T15:00+00:00"; in time it is later.
    for title, stamp in (("earlier", "2026-10-08T15:00:00+00:00"), ("later", "2026-10-08T13:00:00.000000-0400"),
                         ("earliest", "2026-10-08T16:00:00+02:00")):
        asyncio.run(service.process(parse_record(Source.SURICATA, {"timestamp": stamp, "src_ip": title,
                                                                   "alert": {"signature": title}})))
    assert [row["title"] for row in db.list_alerts()] == ["later", "earlier", "earliest"]
    assert db.devices()[0]["last_seen"] in {row["timestamp"] for row in db.list_alerts()}


def test_existing_offset_timestamps_are_migrated_to_utc_once(tmp_path):
    path = str(tmp_path / "old.db")
    db = Database(path); db.initialize()
    service = TriageService(db, FixtureTriageModel())
    ids = [asyncio.run(service.process(NormalizedAlert(source=Source.SURICATA, title=f"Old {n}", source_ip=f"10.0.0.{n}",
                                                       raw={"alert": {}})))[0] for n in range(4)]
    old = ["2026-10-08T13:00:00.123456-0400", "2026-10-08T13:00:00-04:00", "2026-10-08T17:00:00Z", "not a time"]
    with db.connect() as con:
        for alert_id, stamp in zip(ids, old):
            con.execute("UPDATE alerts SET timestamp=? WHERE id=?", (stamp, alert_id))
        con.execute("DELETE FROM settings WHERE key='migrated_utc_timestamps'")
    Database(path).initialize()
    Database(path).initialize()  # idempotent: a second start changes nothing
    with db.connect() as con:
        stored = [con.execute("SELECT timestamp FROM alerts WHERE id=?", (alert_id,)).fetchone()[0] for alert_id in ids]
    assert stored == ["2026-10-08T17:00:00.123456+00:00", "2026-10-08T17:00:00+00:00", "2026-10-08T17:00:00+00:00",
                      "not a time"]


def test_role_session(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    # initialize() returns the generated admin password once, on the run that
    # creates the account. There is no fixed default credential any more.
    seeded_password = db.initialize()
    assert seeded_password
    session = db.authenticate("admin", seeded_password)
    assert session and db.user_for_token(session["token"])["role"] == "admin"


def test_admin_user_validation_and_logout(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "test.db"))
    seeded_password = db.initialize()
    monkeypatch.setattr(api, "db", db)
    client = TestClient(api.app)
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": seeded_password},
    )
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    changed = client.post("/api/auth/password", headers=headers,
                          json={"current_password": seeded_password,
                                "new_password": "chosen-admin-passphrase"})
    assert changed.status_code == 200

    weak = client.post(
        "/api/users",
        headers=headers,
        json={"username": "new user", "password": "short", "role": "owner"},
    )
    assert weak.status_code == 422

    oversized = client.post(
        "/api/users",
        headers=headers,
        json={"username": "unicode", "password": "🔒" * 20, "role": "owner"},
    )
    assert oversized.status_code == 422

    created = client.post(
        "/api/users",
        headers=headers,
        json={"username": "new-owner", "password": "long-demo-passphrase", "role": "owner"},
    )
    assert created.status_code == 201

    owner_login = client.post(
        "/api/auth/login",
        json={"username": "new-owner", "password": "long-demo-passphrase"},
    )
    owner_headers = {"Authorization": f"Bearer {owner_login.json()['token']}"}
    forbidden = client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "escalated", "password": "another-passphrase", "role": "admin"},
    )
    assert forbidden.status_code == 403

    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/users", headers=headers).status_code == 401


def test_trends_count_alerts_on_this_computers_calendar_day(tmp_path):
    """Stored timestamps are UTC; the chart's days are the owner's. 02:30 UTC is the
    evening before in the US, and must be counted there, not on the UTC date."""
    db = Database(str(tmp_path / "test.db")); db.initialize()
    service = TriageService(db, FixtureTriageModel())
    moments = [datetime(2026, 10, 8, 2, 30, tzinfo=timezone.utc), datetime(2026, 10, 8, 15, 0, tzinfo=timezone.utc)]
    for index, moment in enumerate(moments):
        alert = NormalizedAlert(source=Source.SURICATA, timestamp=moment, title=f"Scan {index}", source_ip=f"10.0.0.{index + 2}",
                                raw={"alert": {}})
        asyncio.run(service.process(alert))
    counted: dict[str, int] = {}
    for row in db.trends():
        counted[row["day"]] = counted.get(row["day"], 0) + row["count"]
    expected: dict[str, int] = {}
    for moment in moments:
        day = moment.astimezone().strftime("%Y-%m-%d")
        expected[day] = expected.get(day, 0) + 1
    assert counted == expected
