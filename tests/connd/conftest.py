try:
    import dbus, dbusmock, gi                                             # noqa: F401,E401
    from tests.connd.dbusenv import bt_bus, bt_mock, bt_server, nm_mock, system_bus      # noqa: F401  (shared session fixtures)
except ImportError:                                                        # plain pip environments: the D-Bus based tests run in the dedicated CI job / image
    collect_ignore = ["test_nm.py", "test_bluez.py", "test_connd.py", "test_connd_hardening.py", "dbusenv.py"]
