import json
import os
import sqlite3
import threading

import pytest

from pios_updater.engine import UpdateError


def install(system, version="0.2.0"):
    system.u.check()
    system.u.install(version)
    return system.u.status()


def cur(system):
    return system.u.installed()["version"]


def test_successful_update_end_to_end(system):
    system.publish("0.2.0")
    st = install(system)
    assert cur(system) == "0.2.0"
    assert st["job"]["state"] == "success"
    assert [s["status"] for s in st["job"]["steps"]] == ["done"] * 8
    assert st["previous"]["version"] == "0.1.0"
    assert st["history"][0]["result"] == "success"
    assert (system.paths.root / "releases" / "0.1.0").is_dir(), "old release kept for rollback"
    assert system.env.restarts[-1] == "0.2.0"
    # user data untouched
    assert (system.paths.data / "files/1/foto.jpg").read_bytes() == b"JPEGDATA"
    assert sqlite3.connect(system.paths.db).execute("select body from notes").fetchone()[0] == "wichtig"
    # backup exists and is a valid database
    b = next(system.paths.backups.iterdir())
    assert sqlite3.connect(b / "pios.db").execute("select count(*) from notes").fetchone()[0] == 1
    assert json.loads((b / "meta.json").read_text())["from"] == "0.1.0"


def test_current_symlink_is_relative_and_atomic_target(system):
    system.publish("0.2.0"); install(system)
    assert os.readlink(system.paths.current) == "releases/0.2.0"
    assert not (system.paths.root / "current.new").exists()


def test_wrong_checksum_rejects_package(system):
    system.publish("0.2.0", tamper="package")
    system.u.check()
    system.u.install("0.2.0")
    st = system.u.status()
    assert st["job"]["state"] == "failed" and "Prüfsumme" in st["job"]["error"]
    assert cur(system) == "0.1.0"
    assert not (system.paths.downloads / "0.2.0" / "PiOS-NOVA-update-0.2.0.tar.zst").exists(), "bad package discarded"


def test_not_available_version_cannot_be_installed(system):
    system.publish("0.2.0"); system.u.check()
    with pytest.raises(UpdateError) as e:
        system.u.install("9.9.9")
    assert e.value.code == "not_available"


def test_incompatible_cannot_be_installed(system):
    system.publish("0.5.0", min_version="0.4.0"); system.u.check()
    with pytest.raises(UpdateError) as e:
        system.u.install("0.5.0")
    assert e.value.code == "incompatible"


def test_not_enough_disk_space(system):
    system.publish("0.2.0"); system.u.check()
    system.env.free = 1024
    with pytest.raises(UpdateError) as e:
        system.u.install("0.2.0")
    assert e.value.code == "no_space" and cur(system) == "0.1.0"


def test_concurrent_update_requests_rejected(system):
    system.publish("0.2.0"); system.u.check()
    system.u.async_jobs = True
    gate = threading.Event()
    orig = system.env.restart_backend
    system.env.restart_backend = lambda: (gate.wait(5), orig())[1]
    system.u.install("0.2.0")
    with pytest.raises(UpdateError) as e:
        system.u.install("0.2.0")
    assert e.value.code == "busy"
    with pytest.raises(UpdateError):
        system.u.rollback()
    gate.set(); system.u._thread.join(10)
    assert cur(system) == "0.2.0"


def test_interrupted_download_resumes(system):
    system.publish("0.2.0"); system.u.check()
    system.gh.drop_after = 200
    system.u.install("0.2.0")
    assert cur(system) == "0.2.0" and system.u.status()["job"]["state"] == "success"


def test_download_failure_leaves_system_untouched(system):
    system.publish("0.2.0"); system.u.check()
    system.gh.fail_status = 500
    system.u.install("0.2.0")
    st = system.u.status()
    assert st["job"]["state"] == "failed" and cur(system) == "0.1.0" and st["job"]["error"]


def test_corrupt_archive_extraction_error(system):
    system.publish("0.2.0"); system.u.check()
    a = system.u.store.cache()["available"]
    # replace package content with garbage that still matches a (forged-in-cache) manifest? -> hash check catches it
    name = f"PiOS-NOVA-update-0.2.0.tar.zst"
    system.gh.files[name] = b"not zstd" * 100
    system.u.install("0.2.0")
    assert system.u.status()["job"]["state"] == "failed" and cur(system) == "0.1.0"


def test_package_with_syntax_error_is_not_activated(system):
    system.publish("0.2.0", broken_py=True)
    install(system)
    st = system.u.status()
    assert st["job"]["state"] == "failed" and "Syntax" in st["job"]["error"]
    assert cur(system) == "0.1.0" and not (system.paths.releases / ".0.2.0.partial").exists()


def test_failed_service_start_triggers_rollback(system):
    system.publish("0.2.0")
    system.env.crash_versions.add("0.2.0")
    st = install(system)
    assert st["job"]["state"] == "rolled_back" and cur(system) == "0.1.0"
    assert system.env.running and system.env.restarts[-1] == "0.1.0"
    assert st["failed_versions"]["0.2.0"]["reason"]
    assert st["history"][0]["result"] == "rolled_back"
    assert (system.paths.data / "files/1/foto.jpg").exists()


def test_failed_healthcheck_triggers_rollback(system):
    system.publish("0.2.0")
    system.env.bad_versions.add("0.2.0")          # service runs but health API says no
    st = install(system)
    assert st["job"]["state"] == "rolled_back" and "version_active" in st["job"]["error"]
    assert cur(system) == "0.1.0"


def test_restart_command_failure_is_handled(system):
    system.publish("0.2.0")
    system.env.fail_restart = True
    system.env.crash_versions.add("0.2.0")
    st = install(system)
    assert cur(system) == "0.1.0" and st["job"]["state"] in ("rolled_back", "failed")


def test_no_reinstall_loop_after_failure(system):
    system.publish("0.2.0"); system.env.crash_versions.add("0.2.0")
    install(system)
    n = len(system.env.restarts)
    system.u.recover()                      # e.g. updater restart: must not retry the failed version
    system.u.check()
    assert len(system.env.restarts) == n and cur(system) == "0.1.0"
    assert "0.2.0" in system.u.status()["failed_versions"]


def test_database_migration_and_rollback_restores_backup(system):
    system.publish("0.2.0", schema=2)
    system.env.migrate_to["0.2.0"] = 2
    system.env.bad_versions.add("0.2.0")           # migrates, then fails its health check
    # the new version wrote data after migrating
    orig = system.env._boot
    def boot():
        orig()
        if system.env._cur()["version"] == "0.2.0":
            c = sqlite3.connect(system.paths.db); c.execute("INSERT INTO notes(body) VALUES('neu')"); c.commit(); c.close()
    system.env._boot = boot
    st = install(system)
    assert st["job"]["state"] == "rolled_back" and cur(system) == "0.1.0"
    c = sqlite3.connect(system.paths.db)
    assert c.execute("PRAGMA user_version").fetchone()[0] == 1, "old schema restored from backup"
    assert [r[0] for r in c.execute("select body from notes")] == ["wichtig"]
    assert system.env.running


def test_rollback_keeps_database_when_schema_unchanged(system):
    system.publish("0.2.0")                         # schema stays 1
    system.env.crash_versions.add("0.2.0")
    c = sqlite3.connect(system.paths.db); c.execute("INSERT INTO notes(body) VALUES('zwischendurch')"); c.commit(); c.close()
    install(system)
    assert sqlite3.connect(system.paths.db).execute("select count(*) from notes").fetchone()[0] == 2


def test_update_with_migration_succeeds(system):
    system.publish("0.2.0", schema=2); system.env.migrate_to["0.2.0"] = 2
    install(system)
    assert cur(system) == "0.2.0" and sqlite3.connect(system.paths.db).execute("PRAGMA user_version").fetchone()[0] == 2


def test_manual_rollback_refused_when_db_incompatible_then_allowed_with_restore(system):
    system.publish("0.2.0", schema=2); system.env.migrate_to["0.2.0"] = 2
    install(system)
    with pytest.raises(UpdateError) as e:
        system.u.rollback()
    assert e.value.code == "db_incompatible" and cur(system) == "0.2.0"
    system.u.rollback(restore_backup=True)
    assert cur(system) == "0.1.0" and sqlite3.connect(system.paths.db).execute("PRAGMA user_version").fetchone()[0] == 1
    assert (system.paths.data / "files/1/foto.jpg").exists()


def test_manual_rollback_when_compatible(system):
    system.publish("0.2.0"); install(system)
    st = system.u.rollback()
    assert cur(system) == "0.1.0" and st["job"]["state"] == "success"
    assert any(b.name.endswith("before-rollback") for b in system.paths.backups.iterdir())


def test_power_loss_before_switch_changes_nothing(system):
    system.publish("0.2.0"); system.u.check()
    # simulate: job journal says "install" but the symlink was never switched
    job = system.u._new_job("update", "0.1.0", "0.2.0"); system.u._step(job, "install", "running")
    (system.paths.releases / ".0.2.0.partial").mkdir()
    st = system.u.recover()
    assert st["state"] == "failed" and cur(system) == "0.1.0" and not (system.paths.releases / ".0.2.0.partial").exists()
    assert system.u.status()["job"]["state"] == "failed"


def test_power_loss_after_switch_healthy_commits(system):
    system.publish("0.2.0"); install(system)
    # rewind journal to "switched, not yet committed"
    job = system.u.store.job(); job.update(state="running", step="restart", pending={"backup": next(system.paths.backups.iterdir()).name, "from": "0.1.0", "from_dir": "0.1.0", "to_dir": "0.2.0"})
    system.u.store.save_job(job)
    system.u.recover()
    assert system.u.store.job()["state"] == "success" and cur(system) == "0.2.0"


def test_power_loss_after_switch_unhealthy_rolls_back(system):
    system.publish("0.2.0"); install(system)
    system.env.crash_versions.add("0.2.0"); system.env._boot()
    job = system.u.store.job(); job.update(state="running", step="restart", pending={"backup": next(system.paths.backups.iterdir()).name, "from": "0.1.0", "from_dir": "0.1.0", "to_dir": "0.2.0"})
    system.u.store.save_job(job)
    system.u.recover()
    assert system.u.store.job()["state"] == "rolled_back" and cur(system) == "0.1.0" and system.env.running


def test_old_releases_pruned_but_current_and_previous_kept(system):
    for v in ("0.2.0", "0.3.0", "0.4.0", "0.5.0"):
        system.publish(v); install(system, v)
    names = sorted(d.name for d in system.paths.releases.iterdir())
    assert "0.5.0" in names and "0.4.0" in names and len(names) <= 3


def test_state_files_survive_corruption_gracefully(system):
    system.u.store.status_path.write_text("{broken")
    assert system.u.status()["available"] is None
