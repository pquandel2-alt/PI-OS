import time

import pytest

from pios_updater.source import GitHubSource


def test_no_update_available(system):
    st = system.u.check()
    assert st["available"] is None and st["last_error"] is None and st["installed"]["version"] == "0.1.0"


def test_new_version_available_with_metadata(system):
    system.publish("0.2.0", notes="- Schneller\n- Neu")
    st = system.u.check()
    a = st["available"]
    assert a["version"] == "0.2.0" and a["compatible"] and a["size"] > 0 and "Schneller" in a["notes"] and a["channel"] == "stable"
    assert st["last_check"] and st["last_success"]


def test_stable_channel_ignores_beta_and_beta_channel_sees_it(system):
    system.publish("0.2.0")
    system.publish("0.3.0-beta.1", channel="beta")
    assert system.u.check()["available"]["version"] == "0.2.0"
    system.u.set_config(channel="beta")
    assert system.u.check()["available"]["version"] == "0.3.0-beta.1"


def test_prerelease_flag_on_github_cannot_smuggle_beta_into_stable(system):
    # manifest says "beta" but the tag/GitHub flag claim stable: signed manifest wins
    system.publish("0.2.0", channel="beta", prerelease=False)
    assert system.u.check()["available"] is None


def test_never_offers_downgrade_or_same_version(system):
    system.publish("0.1.0")
    assert system.u.check()["available"] is None
    system.u.set_config(channel="beta")
    system.publish("0.0.9", channel="stable")
    assert system.u.check()["available"] is None


def test_picks_highest_version(system):
    system.publish("0.2.0"); system.publish("0.2.5"); system.publish("0.2.1")
    assert system.u.check()["available"]["version"] == "0.2.5"


def test_github_unreachable_keeps_last_state_and_does_not_raise(system):
    system.publish("0.2.0")
    system.u.check()
    system.gh.srv.shutdown(); system.gh.srv.server_close()
    st = system.u.check(force=True)
    assert st["last_error"] and "GitHub" in st["last_error"]
    assert st["available"]["version"] == "0.2.0", "last known result is still shown"


def test_rate_limit_backoff(system):
    system.gh.fail_status = 403
    st = system.u.check()
    assert "Anfragelimit" in st["last_error"] and st["retry_at"] > time.time()
    hits = system.gh.hits
    system.u.check()                       # inside the back-off window: no request
    assert system.gh.hits == hits


def test_etag_avoids_refetching_manifests(system):
    system.publish("0.2.0")
    system.u.check()
    hits = system.gh.hits
    system.u.check()
    assert system.gh.hits == hits + 1, "only the (conditional) release list is requested"


@pytest.mark.parametrize("tamper", ["manifest"])
def test_tampered_manifest_is_rejected(system, tamper):
    system.publish("0.2.0", tamper=tamper)
    st = system.u.check()
    assert st["available"] is None
    assert "v0.2.0" in system.u.store.cache()["rejected"]


def test_unsigned_or_wrongly_signed_release_is_rejected(system):
    system.publish("0.2.0", sign=False)
    assert system.u.check()["available"] is None
    from pios_updater import crypto
    other_seed, _ = crypto.generate_keypair()
    system.gh.publish(other_seed, "0.2.1", tmp=system.tmp)
    assert system.u.check()["available"] is None


def test_incompatible_versions_flagged(system):
    system.publish("0.5.0", min_version="0.4.0")
    a = system.u.check()["available"]
    assert not a["compatible"] and "0.4.0" in a["problems"][0]
    system.publish("0.6.0", codename="forky", min_version="0.1.0")
    a = system.u.check()["available"]
    assert not a["compatible"] and "forky" in a["problems"][0]


def test_untrusted_download_hosts_blocked():
    s = GitHubSource()
    from pios_updater.source import SourceError
    for bad in ("http://github.com/x", "https://evil.example/x", "file:///etc/passwd", "https://github.com.evil.example/x"):
        with pytest.raises(SourceError):
            s.fetch_small(bad)
