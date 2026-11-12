import os
import tempfile
import unittest
from pathlib import Path

import custodian


class CustodianTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ[custodian.STATE_ENV] = self.temp.name

    def tearDown(self):
        os.environ.pop(custodian.STATE_ENV, None)
        self.temp.cleanup()

    def test_modes_validate_their_route_shape(self):
        custodian.validate_service("journal", "onion-only", "127.0.0.1:8080", None)
        custodian.validate_service("landing", "clearnet-redirect", None, "journalabcdefghijklmnop.onion")
        with self.assertRaises(ValueError):
            custodian.validate_service("bad", "clearnet-redirect", "127.0.0.1:8080", None)

    def test_audit_catches_shared_backend(self):
        records = [
            {"name": "journal", "mode": "onion-only", "backend": "127.0.0.1:8080"},
            {"name": "api", "mode": "onion+clearnet", "backend": "127.0.0.1:8080"},
        ]
        warnings = custodian.audit_records(records)
        self.assertTrue(any("shared backend" in warning for warning in warnings))

    def test_live_listener_audit_flags_wildcard_bind(self):
        records = [{"name": "journal", "mode": "onion-only", "backend": "127.0.0.1:8080"}]
        output = "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n"
        warnings = custodian.listener_exposure_warnings(records, output)
        self.assertIn("not loopback-only", warnings[0])

    def test_minimal_config_omits_secret_bytes(self):
        state = {"version": 1, "services": [{"name": "journal", "mode": "onion-only", "backend": "127.0.0.1:8080", "key": "/secret/path", "clients": [{"name": "laptop", "stale": False}]}]}
        output = custodian.minimal_config(state)
        self.assertIn('key_ref = "vault://journal"', output)
        self.assertIn('authorize_clients = ["laptop"]', output)
        self.assertNotIn("/secret/path", output)

    def test_torrc_includes_active_client_authorization_names(self):
        key = Path(self.temp.name) / "identities" / "journal" / "hidden-service" / "hs_ed25519_secret_key"
        state = {"version": 1, "services": [{"name": "journal", "mode": "onion-only", "backend": "127.0.0.1:8080", "key": str(key), "clients": [{"name": "laptop", "stale": False}]}]}
        fragment = custodian.torrc_fragment(state)
        self.assertIn("HiddenServiceAuthorizeClient stealth laptop", fragment)

    def test_state_file_is_private(self):
        custodian.save_state({"version": 1, "services": []})
        self.assertEqual(0o600, Path(custodian.state_file()).stat().st_mode & 0o777)

    def test_authorization_files_are_private_and_listed_redacted(self):
        descriptor = Path(self.temp.name) / "client.auth"
        descriptor.write_text("descriptor-bytes", encoding="utf-8")
        custodian.save_state({"version": 1, "services": [{"name": "api", "mode": "onion-only", "backend": "127.0.0.1:8080"}]})
        args = type("Args", (), {"service": "api", "client": "laptop", "file": str(descriptor), "replace": False})
        custodian.cmd_auth_add(args)
        state = custodian.load_state()
        stored = Path(state["services"][0]["clients"][0]["file"])
        self.assertEqual(0o600, stored.stat().st_mode & 0o777)
        self.assertEqual("laptop", state["services"][0]["clients"][0]["name"])

if __name__ == "__main__":
    unittest.main()
