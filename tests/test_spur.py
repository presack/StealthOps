"""Regression tests for the Spur enrichment adapter."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from enrichment.providers import spur
from formatter import format_enrichment_report


class SpurTests(unittest.TestCase):
    @patch("enrichment.providers.spur.requests.get")
    def test_extracts_operator_from_tunnel_list(self, get: Mock) -> None:
        get.return_value.status_code = 200
        get.return_value.json.return_value = {
            "ip": "185.213.155.132",
            "risks": ["TUNNEL"],
            "tunnels": [
                {
                    "anonymous": True,
                    "operator": "MULLVAD_VPN",
                    "type": "VPN",
                }
            ],
        }

        result = spur.run("185.213.155.132", "test-key")

        self.assertEqual(result["tunnel_operator"], "MULLVAD_VPN")
        self.assertEqual(result["tunnel_operators"], ["MULLVAD_VPN"])
        self.assertEqual(result["tunnel_type"], "VPN")
        self.assertEqual(result["tunnel_types"], ["VPN"])
        self.assertEqual(result["tunnels"][0]["anonymous"], True)
        report = format_enrichment_report({"providers": {"spur": result}})
        self.assertIn("- tunnel_operator: MULLVAD_VPN", report)

    @patch("enrichment.providers.spur.requests.get")
    def test_supports_legacy_tunnel_object(self, get: Mock) -> None:
        get.return_value.status_code = 200
        get.return_value.json.return_value = {
            "ip": "192.0.2.1",
            "tunnels": {"operator": "EXAMPLE_VPN", "type": "VPN"},
        }

        result = spur.run("192.0.2.1", "test-key")

        self.assertEqual(result["tunnel_operator"], "EXAMPLE_VPN")
        self.assertEqual(result["tunnel_type"], "VPN")
        self.assertEqual(len(result["tunnels"]), 1)


if __name__ == "__main__":
    unittest.main()
