import unittest
from unittest.mock import patch

import proflupinmind_api as api


class ProflupinmindAPISecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()
        self.orig_allow_raw = api.ALLOW_RAW_COMMAND
        self.orig_require_key = api.REQUIRE_API_KEY
        self.orig_api_key = api.API_KEY

    def tearDown(self):
        api.ALLOW_RAW_COMMAND = self.orig_allow_raw
        api.REQUIRE_API_KEY = self.orig_require_key
        api.API_KEY = self.orig_api_key

    def test_raw_command_endpoint_disabled_by_default(self):
        api.ALLOW_RAW_COMMAND = False
        response = self.client.post("/api/command", json={"command": "id"})

        self.assertEqual(response.status_code, 403)
        body = response.get_json()
        self.assertEqual(body["error"], "disabled endpoint")

    def test_shell_metacharacters_blocked(self):
        response = self.client.post(
            "/api/tools/nmap",
            json={"target": "example.com;id", "scan_type": "-sV"},
        )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(body["error"], "unsafe input blocked")

    def test_api_key_required_when_enabled(self):
        api.REQUIRE_API_KEY = True
        api.API_KEY = "supersecret"

        response = self.client.post("/api/tools/nmap", json={"target": "example.com"})
        self.assertEqual(response.status_code, 401)

    def test_api_key_allows_safe_request(self):
        api.REQUIRE_API_KEY = True
        api.API_KEY = "supersecret"

        with patch.object(api, "_run", return_value={"success": True, "output": "ok"}) as run_mock:
            response = self.client.post(
                "/api/tools/nmap",
                headers={"X-API-Key": "supersecret"},
                json={"target": "example.com", "scan_type": "-sV"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])
        self.assertTrue(run_mock.called)


if __name__ == "__main__":
    unittest.main()
