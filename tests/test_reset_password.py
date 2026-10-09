"""Lost-password reset from the computer itself (python -m triage.reset_password)."""
import pytest

from triage import reset_password
from triage.db import Database


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "lighthouse.db"
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(path))
    database = Database(str(path))
    database.initialize()
    database.create_user("owner1", "owner-password-123", "owner")
    return database


def user(db, name):
    return next(u for u in db.users() if u["username"] == name)


def test_reset_gives_a_working_password_that_must_be_replaced(db, capsys):
    token = db.authenticate("owner1", "owner-password-123")["token"]
    assert reset_password.main(["owner1"]) == 0
    printed = capsys.readouterr().out
    password = printed.split("New password for owner1: ")[1].split()[0]
    assert len(password) >= 12
    assert db.authenticate("owner1", "owner-password-123") is None, "the old password stops working"
    assert db.authenticate("owner1", password) is not None
    assert user(db, "owner1")["must_change_password"] is True
    assert db.user_for_token(token) is None, "signed out everywhere"


def test_default_account_is_admin_and_the_stale_one_time_file_goes(db, tmp_path, capsys):
    stale = tmp_path / "first-run-password.txt"
    stale.write_text("old one-time password", encoding="utf-8")
    assert reset_password.main([]) == 0
    assert "New password for admin: " in capsys.readouterr().out
    assert user(db, "admin")["must_change_password"] is True
    assert not stale.exists()


def test_unknown_account_changes_nothing(db, capsys):
    assert reset_password.main(["nobody"]) == 1
    assert "no LightHouse account named 'nobody'" in capsys.readouterr().err
    assert db.authenticate("owner1", "owner-password-123") is not None


def test_never_creates_a_database_or_runs_outside_the_install(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "missing.db"
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(missing))
    assert reset_password.main([]) == 1 and not missing.exists()
    monkeypatch.delenv("LIGHTHOUSE_DB_PATH")
    monkeypatch.setattr(reset_password, "installed_runtime", lambda: False)
    assert reset_password.main([]) == 2
    assert "LightHouse's own Python" in capsys.readouterr().err
