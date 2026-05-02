import asyncio
import shlex
import unittest

import mcp_server


class MCPServerCoreTests(unittest.TestCase):
    def test_build_command_quotes_target_without_options(self):
        target = "example.com; touch /tmp/should-not-run"
        command = mcp_server._build_command("nmap", target, "")

        self.assertIn(shlex.quote(target), command)
        self.assertNotIn(f"nmap -sV -sC -A -T4 {target}", command)

    def test_build_command_quotes_target_with_target_flag(self):
        target = "https://example.com/a path/?q=1&x=2"
        command = mcp_server._build_command("nuclei", target, "-severity low")

        self.assertEqual(command, f"nuclei -severity low -u {shlex.quote(target)}")

    def test_workspace_blocks_path_escape(self):
        result = asyncio.run(mcp_server.workspace_write("../escape.txt", "x"))

        self.assertFalse(result["success"])
        self.assertIn("escapes", result["error"])

    def test_error_statistics_uses_telemetry_keys(self):
        mcp_server._telemetry.record(exit_code=0, duration=2.0)
        stats = asyncio.run(mcp_server.error_handling_statistics())

        self.assertGreaterEqual(stats["total_commands"], 1)
        self.assertGreaterEqual(stats["successes"], 1)
        self.assertGreaterEqual(stats["avg_duration"], 0)

    def test_runtime_dashboard_has_hexstrike_style_sections(self):
        dashboard = asyncio.run(mcp_server.get_performance_dashboard())

        self.assertTrue(dashboard["success"])
        data = dashboard["dashboard"]
        self.assertIn("performance_summary", data)
        self.assertIn("resource_usage", data)
        self.assertIn("cache_stats", data)
        self.assertIn("system_health", data)

    def test_runtime_health_report_is_scored(self):
        health = asyncio.run(mcp_server.get_runtime_health())

        self.assertTrue(health["success"])
        report = health["health_report"]
        self.assertIn("overall_status", report)
        self.assertIn("health_score", report)
        self.assertGreaterEqual(report["health_score"], 0)
        self.assertLessEqual(report["health_score"], 100)


if __name__ == "__main__":
    unittest.main()
