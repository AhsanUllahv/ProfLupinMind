import asyncio
import shlex
import unittest

import mcp_server
from core.output_parser import parse as parse_output


class MCPServerCoreTests(unittest.TestCase):
    def test_build_command_quotes_target_without_options(self):
        target = "example.com; touch /tmp/should-not-run"
        command = mcp_server._build_command("nmap", target, "")

        self.assertIn(shlex.quote(target), command)
        self.assertNotIn(f"nmap -sV -sC -A -T4 {target}", command)

    def test_build_command_quotes_target_with_target_flag(self):
        target = "https://example.com/a path/?q=1&x=2"
        command = mcp_server._build_command("nuclei", target, "-severity low")

        self.assertEqual(command, f"nuclei -severity low -u {shlex.quote(target)} -json -silent")

    def test_web_examples_do_not_double_prefix_scheme(self):
        command = mcp_server._build_command("gobuster", "https://example.com", "")

        self.assertIn("-u https://example.com", command)
        self.assertNotIn("http://https://", command)

    def test_domain_tools_strip_url_to_hostname(self):
        command = mcp_server._build_command("subfinder", "https://app.example.com/path", "")

        self.assertEqual(command, "subfinder -d app.example.com -silent")

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

    def test_directory_parser_handles_feroxbuster_full_url_rows(self):
        output = "200      GET        10l        20w      123c https://example.com/admin"
        parsed = parse_output("feroxbuster", output, "https://example.com")

        self.assertEqual(parsed.summary()["urls"], 1)
        self.assertEqual(parsed.summary()["findings"], 1)

    def test_directory_parser_handles_ffuf_text_rows(self):
        output = "admin [Status: 200, Size: 1234, Words: 10, Lines: 3]"
        parsed = parse_output("ffuf", output, "https://example.com")

        self.assertIn("https://example.com/admin", parsed.urls)


if __name__ == "__main__":
    unittest.main()
